import Synchronization
import Vega
import VegaIO

/// What a `FaultyStream` does to the bytes passing through, drawn from a
/// seed so a failure comes back with the same one.
public struct FaultPlan: Sendable {
    public var seed: UInt64
    /// How often a read returns fewer bytes than it could have: a frame
    /// split anywhere, as TCP may split it.
    public var shortReads: Double
    /// How often a write goes out in pieces, with the task yielding
    /// between them.
    public var shortWrites: Double
    /// How often a read or write is held up first, and for up to how long.
    public var delays: Double
    public var maxDelay: Duration
    /// Once this many bytes have been read (or written), reads (or writes)
    /// fail with `.connectionReset`, as if the peer reset the connection.
    public var resetAfterRead: Int?
    public var resetAfterWritten: Int?

    public init(seed: UInt64, shortReads: Double = 0.5, shortWrites: Double = 0.5,
                delays: Double = 0.1, maxDelay: Duration = .milliseconds(2),
                resetAfterRead: Int? = nil, resetAfterWritten: Int? = nil) {
        self.seed = seed
        self.shortReads = shortReads
        self.shortWrites = shortWrites
        self.delays = delays
        self.maxDelay = maxDelay
        self.resetAfterRead = resetAfterRead
        self.resetAfterWritten = resetAfterWritten
    }
}

/// A stream with faults injected between its user and the stream under it:
/// short reads, writes in pieces, delays and resets, as `plan` says. For
/// testing that protocol code holds up to what networks do.
///
/// ```swift
/// let pair = duplex()
/// var frames = FramedRead(reading: FaultyStream(pair.second, plan: FaultPlan(seed: seed)), decoder: LinesCodec())
/// ```
public struct FaultyStream<Inner: AsyncReader & AsyncWriter & ~Copyable>: ~Copyable, AsyncReader, AsyncWriter {
    public let inner: Inner
    let plan: FaultPlan
    let state: Faults

    public init(_ inner: consuming Inner, plan: FaultPlan) {
        self.inner = inner
        self.plan = plan
        state = Faults(seed: plan.seed)
    }

    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        try await state.maybeDelay(plan)
        if let limit = plan.resetAfterRead, state.read >= limit { throw .connectionReset }
        let spare = buffer.spareCapacity
        guard spare > 1, state.chance(plan.shortReads) else {
            return state.counted(read: try await inner.read(into: &buffer))
        }
        // A smaller read, into a buffer of its own.
        var part = IOBuffer(capacity: 1 + Int(state.next() % UInt64(spare - 1)))
        let n = try await inner.read(into: &part)
        _ = part.withUnsafeBytes { buffer.append($0) }
        return state.counted(read: n)
    }

    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        try await state.maybeDelay(plan)
        var at = 0
        while at < bytes.count {
            if let limit = plan.resetAfterWritten, state.written >= limit { throw .connectionReset }
            var n = bytes.count - at
            if n > 1 && state.chance(plan.shortWrites) { n = 1 + Int(state.next() % UInt64(n - 1)) }
            if let limit = plan.resetAfterWritten { n = min(n, max(1, limit - state.written)) }
            try await inner.write(UnsafeRawBufferPointer(rebasing: bytes[at..<(at + n)]))
            state.counted(written: n)
            at += n
            if at < bytes.count { await Runtime.yield() }
        }
    }
}

extension FaultyStream: Sendable where Inner: Sendable & ~Copyable {}

/// A `FaultyStream`'s generator and counts, shared by its reads and writes.
final class Faults: Sendable {
    private struct State {
        var random: UInt64
        var read = 0
        var written = 0
    }

    private let state: Mutex<State>

    init(seed: UInt64) {
        state = Mutex(State(random: seed))
    }

    /// SplitMix64.
    func next() -> UInt64 {
        state.withLock { s in
            s.random &+= 0x9E37_79B9_7F4A_7C15
            var z = s.random
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
    }

    func chance(_ p: Double) -> Bool {
        p > 0 && Double(next() >> 11) / Double(1 << 53) < p
    }

    var read: Int { state.withLock { $0.read } }
    var written: Int { state.withLock { $0.written } }

    func counted(read n: Int) -> Int {
        state.withLock { $0.read += n }
        return n
    }

    func counted(written n: Int) {
        state.withLock { $0.written += n }
    }

    func maybeDelay(_ plan: FaultPlan) async throws(IOError) {
        guard chance(plan.delays) else { return }
        let ns = plan.maxDelay.components.seconds * 1_000_000_000 + plan.maxDelay.components.attoseconds / 1_000_000_000
        guard ns > 0 else { return }
        do {
            try await Runtime.sleep(for: .nanoseconds(Int64(next() % UInt64(ns)) + 1))
        } catch {
            throw .cancelled
        }
    }
}
