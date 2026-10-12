import Synchronization

/// A channel for exactly one value: Tokio's `oneshot`.
///
/// ```swift
/// let ch = Oneshot<Int>()
/// rt.spawn(with: ch.sender) { tx in try? tx.send(42) }
/// var rx = ch.receiver
/// let v = try await rx.receive()
/// ```
///
/// Both halves are `~Copyable`, so the value can be too (a socket, a buffer).
/// Dropping the sender without sending wakes the receiver with `.closed`.
///
/// No lock: one atomic word of flags, which each side sets with a single
/// read-modify-write, so the two always agree on who saw what first.
@frozen
public struct Oneshot<Value: ~Copyable & Sendable>: ~Copyable, Sendable {
    public var sender: Sender
    public var receiver: Receiver

    @inlinable
    public init() {
        let core = OneshotCore<Value>()
        sender = Sender(core)
        receiver = Receiver(core)
    }

    @frozen
    public struct Sender: ~Copyable, Sendable {
        @usableFromInline unowned(unsafe) let core: OneshotCore<Value>

        @inlinable
        init(_ core: OneshotCore<Value>) {
            self.core = core
            _ = Unmanaged.passRetained(core)
        }

        deinit {
            core.dropSender()
            Unmanaged.passUnretained(core).release()
        }

        /// Deliver `value`. Throws `.closed`, dropping the value, if the
        /// receiver is gone.
        @inlinable
        public consuming func send(_ value: consuming Value) throws(ChannelError) {
            let delivered = core.send(value)
            Unmanaged.passUnretained(core).release()
            discard self
            if !delivered { throw .closed }
        }

        /// True once the receiver is gone: a send would fail.
        @inlinable
        public var isClosed: Bool { core.state.load(ordering: .acquiring) & OneshotCore<Value>.rxDropped != 0 }
    }

    @frozen
    public struct Receiver: ~Copyable, Sendable {
        @usableFromInline unowned(unsafe) let core: OneshotCore<Value>

        @inlinable
        init(_ core: OneshotCore<Value>) {
            self.core = core
            _ = Unmanaged.passRetained(core)
        }

        deinit {
            core.dropReceiver()
            Unmanaged.passUnretained(core).release()
        }

        /// Wait for the value. Throws `.closed` if the sender dropped without
        /// sending (or the value was already received), `.cancelled` if the
        /// task is cancelled first; the value can still be received later.
        @inlinable
        public mutating func receive() async throws(ChannelError) -> Value {
            try await core.receive()
        }

        /// The value if it has been sent, without waiting.
        @inlinable
        public mutating func tryReceive() throws(TryReceiveError) -> Value {
            try core.tryReceive()
        }
    }
}

@usableFromInline
final class OneshotCore<Value: ~Copyable & Sendable>: @unchecked Sendable {
    /// `state` bits.
    @inlinable static var sent: Int { 1 }
    @inlinable static var txDropped: Int { 2 }
    @inlinable static var rxWaiting: Int { 4 }
    @inlinable static var cancelled: Int { 8 }
    @inlinable static var rxDropped: Int { 16 }

    @usableFromInline
    struct Slot: ~Copyable {
        /// Written by the sender before it sets `sent`; read by the receiver after.
        @usableFromInline var value: Value? = nil
        /// Written by the receiver before it sets `rxWaiting`.
        @usableFromInline var continuation: UnsafeContinuation<Void, Never>? = nil
        /// Receiver-only: the value has been taken.
        @usableFromInline var taken = false

        @inlinable init() {}
    }

    @usableFromInline let state = Atomic<Int>(0)
    @usableFromInline let slot: UnsafeMutablePointer<Slot>

    @inlinable
    init() {
        slot = .allocate(capacity: 1)
        slot.initialize(to: Slot())
    }

    deinit {
        slot.deinitialize(count: 1)
        slot.deallocate()
    }

    /// Whoever sets a flag the parked receiver waits for resumes it, unless
    /// a cancellation got there first (and resumed it).
    @inlinable @inline(__always)
    func wakeIfParked(_ prev: Int) {
        if prev & (Self.rxWaiting | Self.cancelled) == Self.rxWaiting {
            slot.pointee.continuation!.resume()
        }
    }

    @inlinable
    func send(_ value: consuming Value) -> Bool {
        slot.pointee.value = consume value
        let prev = state.bitwiseOr(Self.sent, ordering: .acquiringAndReleasing).oldValue
        if prev & Self.rxDropped != 0 {
            slot.pointee.value = nil // nobody will take it
            return false
        }
        wakeIfParked(prev)
        return true
    }

    @inlinable
    func dropSender() {
        let prev = state.bitwiseOr(Self.txDropped, ordering: .acquiringAndReleasing).oldValue
        wakeIfParked(prev)
    }

    @inlinable
    func dropReceiver() {
        let prev = state.bitwiseOr(Self.rxDropped, ordering: .acquiringAndReleasing).oldValue
        if prev & Self.sent != 0 { slot.pointee.value = nil }
    }

    /// The value, `.closed`, or nil (not sent yet).
    @inlinable @inline(__always)
    func take(_ s: Int) throws(ChannelError) -> Value? {
        if s & Self.sent != 0 && !slot.pointee.taken {
            slot.pointee.taken = true
            return slot.pointee.value.take()!
        }
        if s & (Self.sent | Self.txDropped) != 0 { throw .closed }
        return nil
    }

    @inlinable
    func tryReceive() throws(TryReceiveError) -> Value {
        do {
            if let v = try take(state.load(ordering: .acquiring)) { return v }
        } catch {
            throw .closed
        }
        throw .empty
    }

    @inlinable
    func receive() async throws(ChannelError) -> Value {
        if let v = try take(state.load(ordering: .acquiring)) { return v }
        await withTaskCancellationHandler {
            await withUnsafeContinuation { (c: UnsafeContinuation<Void, Never>) in
                slot.pointee.continuation = c
                let prev = state.bitwiseOr(Self.rxWaiting, ordering: .acquiringAndReleasing).oldValue
                // Already sent, closed or cancelled: nobody else will resume us.
                if prev & (Self.sent | Self.txDropped | Self.cancelled) != 0 { c.resume() }
            }
        } onCancel: {
            let prev = state.bitwiseOr(Self.cancelled, ordering: .acquiringAndReleasing).oldValue
            if prev & (Self.rxWaiting | Self.sent | Self.txDropped) == Self.rxWaiting {
                slot.pointee.continuation!.resume()
            }
        }
        // The handler is gone: reset for a later receive.
        let s = state.bitwiseAnd(~(Self.rxWaiting | Self.cancelled), ordering: .acquiring).oldValue
        slot.pointee.continuation = nil
        if let v = try take(s) { return v }
        throw .cancelled
    }
}
