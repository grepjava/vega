/// Why a broadcast receive gave up.
///
/// A struct rather than an enum, so that kinds of failure can be added
/// without breaking anyone's exhaustive `switch`: switch over `code`, or
/// compare the error itself where its kind carries nothing more
/// (`catch BroadcastError.closed`, `error == .closed`).
public struct BroadcastError: Error, Hashable, Sendable, CustomStringConvertible {
    /// What kind of failure this is.
    public let code: Code
    public let missed: UInt64

    /// The kinds of `BroadcastError`.
    public struct Code: Hashable, Sendable, CustomStringConvertible {
        let rawValue: UInt8

        /// The channel is closed and this receiver has seen everything sent.
        public static let closed = Code(rawValue: 0)
        /// This receiver fell behind and `missed` values were overwritten
        /// before it got to them. The next receive returns the oldest kept.
        public static let lagged = Code(rawValue: 1)
        /// The waiting task was cancelled. The receiver is still usable.
        public static let cancelled = Code(rawValue: 2)

        public var description: String {
            let names = ["closed", "lagged", "cancelled"]
            return Int(rawValue) < names.count ? names[Int(rawValue)] : "code \(rawValue)"
        }
    }

    init(_ code: Code, missed: UInt64 = 0) {
        self.code = code
        self.missed = missed
    }

    /// The channel is closed and this receiver has seen everything sent.
    public static let closed = BroadcastError(.closed)
    /// This receiver fell behind and `missed` values were overwritten
    /// before it got to them. The next receive returns the oldest kept.
    public static func lagged(missed: UInt64) -> BroadcastError { BroadcastError(.lagged, missed: missed) }
    /// The waiting task was cancelled. The receiver is still usable.
    public static let cancelled = BroadcastError(.cancelled)

    public var description: String {
        switch code {
        case .closed: "closed"
        case .lagged: "lagged: \(missed) missed"
        case .cancelled: "cancelled"
        default: "\(code)"
        }
    }
}

/// Every value to every receiver: Tokio's `broadcast` channel. Senders never
/// wait: the channel keeps the last `capacity` values, and a receiver that
/// falls further behind is told how many it missed (`.lagged`) and skips
/// ahead.
///
/// ```swift
/// let events = Broadcast<Event>(capacity: 64)
/// var mine = events.subscribe()
/// rt.spawn { while let e = try? await mine.receive() { handle(e) } }
/// events.send(.started)
/// ```
///
/// A receiver gets the values sent after it subscribed.
public final class Broadcast<Value: Sendable>: @unchecked Sendable {
    public let capacity: Int

    private struct State {
        /// Sequence number of the oldest kept value, and of the next to send.
        var head: UInt64 = 0
        var tail: UInt64 = 0
        var closed = false
    }

    // Wake codes.
    private static var ready: UInt8 { 0 }
    private static var cancelled: UInt8 { 1 }

    private let lock = RawLock()
    private let state = Guarded(State())
    private let slots: UnsafeMutablePointer<Value?>
    private let waiters = Guarded(WaitList())

    public init(capacity: Int) {
        precondition(capacity > 0, "a Broadcast needs room for one value")
        self.capacity = capacity
        slots = .allocate(capacity: capacity)
        slots.initialize(repeating: nil, count: capacity)
    }

    deinit {
        slots.deinitialize(count: capacity)
        slots.deallocate()
        waiters.pointer.pointee.destroy()
        waiters.destroy()
        state.destroy()
        lock.destroy()
    }

    /// Send `value` to every receiver, overwriting the oldest kept value if
    /// the channel is full. False (nothing sent) once closed.
    @discardableResult
    public func send(_ value: Value) -> Bool {
        let s = state.pointer
        let woken = lock.withLock { () -> [WaitList.Waiter]? in
            guard !s.pointee.closed else { return nil }
            slots[Int(s.pointee.tail % UInt64(capacity))] = value
            s.pointee.tail += 1
            if s.pointee.tail - s.pointee.head > UInt64(capacity) { s.pointee.head += 1 }
            return waiters.pointer.pointee.takeAll()
        }
        guard let woken else { return false }
        for w in woken { w.continuation.resume(returning: Broadcast.ready) }
        return true
    }

    /// No more values. Receivers still get what is kept, then `.closed`.
    public func close() {
        let s = state.pointer
        let woken = lock.withLock { () -> [WaitList.Waiter] in
            s.pointee.closed = true
            return waiters.pointer.pointee.takeAll()
        }
        for w in woken { w.continuation.resume(returning: Broadcast.ready) }
    }

    /// A receiver for the values sent from now on.
    public func subscribe() -> Receiver {
        Receiver(channel: self, next: lock.withLock { state.pointer.pointee.tail })
    }

    /// One subscriber's position in the channel.
    public struct Receiver: Sendable {
        public let channel: Broadcast
        private var next: UInt64

        fileprivate init(channel: Broadcast, next: UInt64) {
            self.channel = channel
            self.next = next
        }

        /// The next value, waiting for one if this receiver is caught up.
        public mutating func receive() async throws(BroadcastError) -> Value {
            while true {
                let r = channel.take(at: next)
                switch r {
                case .value(let v):
                    next += 1
                    await Runtime.consumeBudget()
                    return v
                case .lagged(let head):
                    let missed = head - next
                    next = head
                    throw .lagged(missed: missed)
                case .closed:
                    throw .closed
                case .empty:
                    try await channel.wait(after: next)
                }
            }
        }

        /// The next value if one is there now; nil if caught up.
        public mutating func tryReceive() throws(BroadcastError) -> Value? {
            switch channel.take(at: next) {
            case .value(let v):
                next += 1
                return v
            case .lagged(let head):
                let missed = head - next
                next = head
                throw .lagged(missed: missed)
            case .closed:
                throw .closed
            case .empty:
                return nil
            }
        }
    }

    private enum Take {
        case value(Value), lagged(head: UInt64), closed, empty
    }

    private func take(at seq: UInt64) -> Take {
        let s = state.pointer
        return lock.withLock { () -> Take in
            if seq < s.pointee.head { return .lagged(head: s.pointee.head) }
            if seq < s.pointee.tail { return .value(slots[Int(seq % UInt64(capacity))]!) }
            return s.pointee.closed ? .closed : .empty
        }
    }

    /// Wait until something is sent past `seq`, or the channel closes.
    private func wait(after seq: UInt64) async throws(BroadcastError) {
        let s = state.pointer
        let code = await park(WaitListRef(lock: lock, list: waiters.pointer),
                              cancelled: Broadcast.cancelled) { () -> UInt8? in
            seq < s.pointee.tail || s.pointee.closed ? Broadcast.ready : nil
        }
        if code == Broadcast.cancelled { throw .cancelled }
    }
}
