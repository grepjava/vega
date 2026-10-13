import CVega
import Synchronization
import Vega
import VegaIO

/// Two connected in-memory byte streams: Tokio's `io::duplex`, the async
/// counterpart of NIO's `EmbeddedChannel` for code written against
/// `AsyncReader` and `AsyncWriter`.
///
/// ```swift
/// let pair = duplex(capacity: 64)
/// rt.spawn(with: pair.second) { s in _ = try? await copy(from: s, to: s) }   // echo
/// try await pair.first.write(request)
/// ```
///
/// What one end writes the other reads, in order. Each direction buffers up
/// to `capacity` bytes: a writer facing a full buffer waits for the reader,
/// which makes small capacities good for testing backpressure and short
/// reads. Dropping an end (or `shutdownWrite()`) ends the stream for the
/// peer's reads once it has read what was buffered; writes to a dropped end
/// throw `.brokenPipe`. Waiting reads and writes end with `.cancelled` when
/// their task is cancelled. `split()` gives an end's read and write sides
/// to two tasks.
public func duplex(capacity: Int = 64 * 1024) -> DuplexStream.Pair {
    precondition(capacity > 0, "a duplex stream needs room for a byte")
    let ab = Pipe(capacity: capacity), ba = Pipe(capacity: capacity)
    return DuplexStream.Pair(first: DuplexStream(incoming: ba, outgoing: ab),
                             second: DuplexStream(incoming: ab, outgoing: ba))
}

/// One end of a `duplex()` pair.
public struct DuplexStream: ~Copyable, Sendable, AsyncReader, AsyncWriter {
    /// The two ends `duplex()` returns.
    @frozen
    public struct Pair: ~Copyable, Sendable {
        public var first: DuplexStream
        public var second: DuplexStream
    }

    /// The two sides `split()` returns.
    @frozen
    public struct Split: ~Copyable, Sendable {
        public var reader: DuplexReader
        public var writer: DuplexWriter
    }

    private let incoming: Pipe
    private let outgoing: Pipe

    fileprivate init(incoming: Pipe, outgoing: Pipe) {
        self.incoming = incoming
        self.outgoing = outgoing
    }

    deinit {
        incoming.release(.reader)
        outgoing.release(.writer)
    }

    /// Read into `buffer`'s spare capacity, waiting while nothing is
    /// buffered. Returns the bytes read: 0 at end of stream or with a full
    /// buffer.
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        try await incoming.read(into: &buffer)
    }

    /// Write all of `bytes`, waiting for the peer to read whenever the
    /// direction's buffer is full.
    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        try await outgoing.write(bytes)
    }

    /// End the stream for the peer's reads; this end can still read.
    public func shutdownWrite() {
        outgoing.closeWrite()
    }

    /// Bytes waiting to be read from this end.
    public var available: Int { incoming.buffered }

    /// Bytes written to this end that the peer hasn't read yet.
    public var unreadByPeer: Int { outgoing.buffered }

    /// The read and write sides, to use from separate tasks. The peer reads
    /// end of stream once the writer is dropped.
    public consuming func split() -> Split {
        Split(reader: DuplexReader(incoming), writer: DuplexWriter(outgoing))
    }
}

extension DuplexStream {
    /// `split()`, as `StreamHalves`.
    public consuming func halves() -> StreamHalves<DuplexReader, DuplexWriter> {
        let split = split()
        return StreamHalves(reader: split.reader, writer: split.writer)
    }
}

/// The read side of a split `DuplexStream`.
public struct DuplexReader: ~Copyable, Sendable, AsyncReader {
    private let pipe: Pipe

    fileprivate init(_ pipe: Pipe) {
        pipe.retain(.reader)
        self.pipe = pipe
    }

    deinit { pipe.release(.reader) }

    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        try await pipe.read(into: &buffer)
    }

    /// Bytes waiting to be read.
    public var available: Int { pipe.buffered }
}

/// The write side of a split `DuplexStream`.
public struct DuplexWriter: ~Copyable, Sendable, AsyncWriter {
    private let pipe: Pipe

    fileprivate init(_ pipe: Pipe) {
        pipe.retain(.writer)
        self.pipe = pipe
    }

    deinit { pipe.release(.writer) }

    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        try await pipe.write(bytes)
    }

    /// End the stream for the peer's reads.
    public func shutdownWrite() {
        pipe.closeWrite()
    }
}

/// One direction: a bounded byte queue with waiting readers and writers.
fileprivate final class Pipe: @unchecked Sendable {
    private struct Waiter {
        let id: UInt64
        let continuation: UnsafeContinuation<Bool, Never>
    }

    private struct State {
        var bytes: [UInt8] = []
        /// `bytes[head...]` are unread.
        var head = 0
        var readClosed = false
        var writeClosed = false
        /// Ends holding each side; a side closes when its count drops to 0.
        var readHandles = 1
        var writeHandles = 1
        var readers: [Waiter] = []
        var writers: [Waiter] = []

        var buffered: Int { bytes.count - head }
    }

    fileprivate enum Side { case reader, writer }

    private let capacity: Int
    private let state = Locked(State())
    private let nextID = Atomic<UInt64>(0)

    init(capacity: Int) {
        self.capacity = capacity
    }

    var buffered: Int { state.withLock { $0.buffered } }

    func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        guard buffer.spareCapacity > 0 else { return 0 }
        while true {
            let want = buffer.spareCapacity, before = buffer.count
            var woken: [Waiter] = []
            buffer.withUnsafeSpareCapacity { spare in
                let (n, w) = state.withLock { s -> (Int, [Waiter]) in
                    let n = min(want, s.buffered)
                    guard n > 0 else { return (0, []) }
                    s.bytes.withUnsafeBytes { all in
                        spare.baseAddress!.copyMemory(from: all.baseAddress! + s.head, byteCount: n)
                    }
                    s.head += n
                    if s.head == s.bytes.count {
                        s.bytes.removeAll(keepingCapacity: true)
                        s.head = 0
                    } else if s.head >= s.bytes.count / 2 {
                        s.bytes.removeFirst(s.head)
                        s.head = 0
                    }
                    let woken = s.writers
                    s.writers.removeAll()
                    return (n, woken)
                }
                woken = w
                return n
            }
            for w in woken { w.continuation.resume(returning: true) }
            let n = buffer.count - before
            if n > 0 {
                await Runtime.consumeBudget()
                return n
            }
            // End of stream only when closed with nothing left: the writer
            // may have added its last bytes and closed since we looked.
            switch state.withLock({ s -> Bool? in s.buffered > 0 ? nil : s.writeClosed }) {
            case nil: continue
            case true?: return 0
            case false?: guard await park(.reader) else { throw .cancelled }
            }
        }
    }

    func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        var at = 0
        while at < bytes.count {
            let rest = UnsafeRawBufferPointer(rebasing: bytes[at...])
            let capacity = self.capacity
            let result = state.withLock { s -> (Int, [Waiter])? in
                if s.readClosed || s.writeClosed { return nil }
                let n = min(rest.count, capacity - s.buffered)
                guard n > 0 else { return (0, []) }
                s.bytes.append(contentsOf: rest[0..<n])
                let woken = s.readers
                s.readers.removeAll()
                return (n, woken)
            }
            guard let (n, woken) = result else { throw .brokenPipe }
            for w in woken { w.continuation.resume(returning: true) }
            if n > 0 {
                at += n
                await Runtime.consumeBudget()
            } else {
                guard await park(.writer) else { throw .cancelled }
            }
        }
    }

    func closeWrite() { close(.writer) }

    func retain(_ side: Side) {
        state.withLock { s in
            switch side {
            case .reader: s.readHandles += 1
            case .writer: s.writeHandles += 1
            }
        }
    }

    func release(_ side: Side) {
        let last = state.withLock { s -> Bool in
            switch side {
            case .reader: s.readHandles -= 1; return s.readHandles == 0
            case .writer: s.writeHandles -= 1; return s.writeHandles == 0
            }
        }
        if last { close(side) }
    }

    /// Close one side and wake everyone waiting on the other (and on this
    /// one, so it notices).
    private func close(_ side: Side) {
        let woken = state.withLock { s -> [Waiter] in
            switch side {
            case .reader: s.readClosed = true
            case .writer: s.writeClosed = true
            }
            let all = s.readers + s.writers
            s.readers.removeAll()
            s.writers.removeAll()
            return all
        }
        for w in woken { w.continuation.resume(returning: true) }
    }

    /// Wait until `side` might make progress. Returns false if the task was
    /// cancelled.
    private func park(_ side: Side) async -> Bool {
        let id = nextID.add(1, ordering: .relaxed).newValue
        let capacity = self.capacity
        let woken = await withTaskCancellationHandler {
            await withUnsafeContinuation { (c: UnsafeContinuation<Bool, Never>) in
                let now = state.withLock { s -> Bool? in
                    // Checked under the lock: either the cancel handler runs
                    // after this and finds the waiter, or the flag shows here.
                    if Task.isCancelled { return false }
                    switch side {
                    case .reader:
                        if s.buffered > 0 || s.writeClosed { return true }
                        s.readers.append(Waiter(id: id, continuation: c))
                    case .writer:
                        if s.buffered < capacity || s.readClosed || s.writeClosed { return true }
                        s.writers.append(Waiter(id: id, continuation: c))
                    }
                    return nil
                }
                if let now { c.resume(returning: now) }
            }
        } onCancel: {
            let waiter = state.withLock { s -> Waiter? in
                if let i = s.readers.firstIndex(where: { $0.id == id }) { return s.readers.remove(at: i) }
                if let i = s.writers.firstIndex(where: { $0.id == id }) { return s.writers.remove(at: i) }
                return nil
            }
            waiter?.continuation.resume(returning: false)
        }
        // The other side can resume us before we suspend; see cv_tsan_acquire.
        cv_tsan_acquire(cv_task_current())
        return woken
    }
}

/// A value behind Vega's C lock. Not `Synchronization.Mutex`: TSan can't see
/// the uninstrumented stdlib lock order its critical sections, and reports
/// every access inside them as a race.
private final class Locked<Value>: @unchecked Sendable {
    private let lock = cv_lock_new()!
    private var value: Value

    init(_ value: Value) {
        self.value = value
    }

    deinit { cv_lock_free(lock) }

    func withLock<R>(_ body: (inout Value) -> R) -> R {
        cv_lock_lock(lock)
        defer { cv_lock_unlock(lock) }
        return body(&value)
    }
}
