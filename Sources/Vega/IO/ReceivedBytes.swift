import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// How `receive()` gets its buffer under the io_uring driver (see
/// RingReceive.swift); the other drivers always read into a receive block.
enum ReceiveMode: Sendable {
    /// One RECV_MULTISHOT per connection, into the worker's buffer pool.
    /// It stays armed on the ring of the worker that armed it, and only that
    /// worker reaps it: a connection whose task is stolen away waits for
    /// that worker, when busy, to poll its ring between jobs.
    case multishot
    /// One RECV with buffer select per `receive()`, on the ring of the
    /// worker running the reader.
    case single
    /// No pool: wait for readiness, then read into a receive block.
    case readiness

    /// `VEGA_RECV=single|multishot|readiness`; single by default.
    static let environment: ReceiveMode = {
        guard let v = getenv("VEGA_RECV") else { return .single }
        switch String(cString: v) {
        case "multishot": return .multishot
        case "readiness", "poll": return .readiness
        default: return .single
        }
    }()

    /// Buffers in each worker's pool: `count`, else `VEGA_RECV_BUFS`, else
    /// 256 (4 MiB of address space, touched as used); down to a power of
    /// two, at most 32768.
    static func poolSize(_ count: UInt32?) -> UInt32 {
        var n: UInt32 = 256
        if let count {
            n = count
        } else if let v = getenv("VEGA_RECV_BUFS"), let parsed = UInt32(String(cString: v)) {
            n = parsed
        }
        n = min(max(n, 1), 32768)
        return 1 << (31 - UInt32(n.leadingZeroBitCount))
    }
}

/// The runtime's receive blocks: storage of `ReceiveBlocks.size` bytes, kept
/// in a short list on each worker so a connection that has read what it
/// needs can give its buffer back while it waits, and take one again when
/// bytes come, without a trip through malloc each time.
///
/// `IOBuffer`s of exactly that size take their storage here and give it
/// back here (`IOBuffer.releaseStorage()`), and `receive()` reads into these
/// blocks on the readiness drivers. Each worker's list is touched only by
/// its own thread; off the workers it is plain allocation.
enum ReceiveBlocks {
    /// The size of a block: what Garuda and most servers read into.
    static let size = 16 * 1024
    /// Blocks each worker keeps; more are freed.
    static let keep = 64

    /// A block: this worker's spare, or a new one.
    @inline(__always)
    static func take() -> UnsafeMutableRawPointer {
        if let worker = Worker.current, let block = worker._withUnsafeGuaranteedRef({ $0.popBlock() }) {
            return block
        }
        return .allocate(byteCount: size, alignment: 16)
    }

    /// Give `block` back: to this worker's list, or freed.
    @inline(__always)
    static func give(_ block: UnsafeMutableRawPointer) {
        if let worker = Worker.current, worker._withUnsafeGuaranteedRef({ $0.pushBlock(block) }) { return }
        block.deallocate()
    }
}

extension Worker {
    /// This worker's spare receive block, if it has one. Owner only.
    @inline(__always)
    func popBlock() -> UnsafeMutableRawPointer? {
        guard let block = blockHead else { return nil }
        blockHead = block.load(as: UnsafeMutableRawPointer?.self)
        blockCount -= 1
        return block
    }

    /// Keep `block`, unless this worker keeps enough already. Owner only.
    @inline(__always)
    func pushBlock(_ block: UnsafeMutableRawPointer) -> Bool {
        guard blockCount < ReceiveBlocks.keep else { return false }
        block.storeBytes(of: blockHead, as: UnsafeMutableRawPointer?.self)
        blockHead = block
        blockCount += 1
        return true
    }

    /// Free the blocks this worker kept.
    func freeBlocks() {
        while let block = popBlock() { block.deallocate() }
    }
}

/// Bytes `receive()` read, in storage lent by the runtime: a receive block,
/// or under the io_uring driver a buffer the kernel picked from the ring's
/// pool when the bytes arrived. Dropping it gives the storage back, so keep
/// it no longer than it takes to use or copy the bytes.
///
/// A connection that waits with `receive()` holds no buffer of its own
/// while nothing arrives: the storage is taken when bytes come and given
/// back once they are dealt with. Empty means the peer closed its side.
///
/// ```swift
/// while true {
///     let bytes = try await stream.receive()
///     if bytes.isEmpty { break }          // end of stream
///     input.append(bytes)                 // or parse in place
/// }
/// ```
public struct ReceivedBytes: ~Copyable, @unchecked Sendable {
    @usableFromInline var base: UnsafeRawPointer
    /// How many bytes are left: 0 at the end of the stream.
    public private(set) var count: Int
    /// The storage, to give back: its start and size (0: none), or a ring
    /// buffer (`ring` set, `bid` its id).
    let storage: UnsafeMutableRawPointer
    let capacity: Int
    let ring: OpaquePointer?
    let bid: Int32

    /// The end of the stream: no bytes, no storage.
    init() {
        base = UnsafeRawPointer(IOBuffer.noStorage)
        storage = IOBuffer.noStorage
        count = 0
        capacity = 0
        ring = nil
        bid = 0
    }

    /// `count` bytes at the start of `storage`, heap storage of `capacity`
    /// bytes (a receive block when that is `ReceiveBlocks.size`).
    init(storage: UnsafeMutableRawPointer, capacity: Int, count: Int) {
        base = UnsafeRawPointer(storage)
        self.storage = storage
        self.capacity = capacity
        self.count = count
        ring = nil
        bid = 0
    }

    /// `count` bytes in buffer `bid` of `ring`'s pool, at `storage`.
    init(ring: OpaquePointer, bid: Int32, storage: UnsafeMutableRawPointer, count: Int) {
        base = UnsafeRawPointer(storage)
        self.storage = storage
        self.ring = ring
        self.bid = bid
        self.count = count
        capacity = 0
    }

    /// The bytes `buffer` holds, in its storage, which the result now owns.
    public init(_ buffer: consuming IOBuffer) {
        let (storage, capacity, count) = buffer.takeStorage()
        self.init(storage: storage, capacity: capacity, count: count)
    }

    deinit {
        #if os(Linux)
        if let ring {
            cv_uring_buf_return(ring, bid)
            return
        }
        #endif
        IOBuffer.freeStorage(storage, capacity: capacity)
    }

    /// The size of the receive blocks `receive()` reads into where the
    /// kernel doesn't pick the buffer, and the most it returns at once
    /// there: 16 KiB. `IOBuffer`s of this capacity share those blocks.
    public static var blockSize: Int { ReceiveBlocks.size }

    /// No bytes: what `receive()` returns at the end of the stream.
    @inlinable public var isEmpty: Bool { count == 0 }

    /// The bytes, for the length of `body`.
    @inlinable
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try body(UnsafeRawBufferPointer(start: base, count: count))
    }

    /// Drop the first `n` bytes: those dealt with in place.
    public mutating func removeFirst(_ n: Int) {
        precondition(n >= 0 && n <= count, "removeFirst past the received bytes")
        base += n
        count -= n
    }
}

extension IOBuffer {
    /// Append `bytes`, growing the buffer if they don't fit.
    public mutating func append(_ bytes: borrowing ReceivedBytes) {
        bytes.withUnsafeBytes { append($0) }
    }
}
