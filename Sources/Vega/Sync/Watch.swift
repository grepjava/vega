/// One value that receivers watch for changes: Tokio's `watch` channel.
/// Receivers see the latest value, not every value: a sender may replace it
/// several times before a slow receiver looks.
///
/// ```swift
/// let config = Watch(Config.defaults)
/// var updates = config.subscribe()
/// rt.spawn {
///     while (try? await updates.changed()) != nil { apply(updates.value) }
/// }
/// config.send(newConfig)
/// ```
public final class Watch<Value: Sendable>: @unchecked Sendable {
    private struct State {
        var value: Value
        var version: UInt64 = 0
        var closed = false
    }

    // Wake codes.
    private static var codeChanged: UInt8 { 0 }
    private static var codeClosed: UInt8 { 1 }
    private static var codeCancelled: UInt8 { 2 }

    private let lock = RawLock()
    private let state: Guarded<State>
    private let waiters = Guarded(WaitList())

    public init(_ value: Value) {
        state = Guarded(State(value: value))
    }

    deinit {
        waiters.pointer.pointee.destroy()
        waiters.destroy()
        state.destroy()
        lock.destroy()
    }

    /// The current value.
    public var value: Value { lock.withLock { state.pointer.pointee.value } }

    public var isClosed: Bool { lock.withLock { state.pointer.pointee.closed } }

    /// Replace the value and wake every receiver waiting in `changed()`.
    /// Ignored once closed.
    public func send(_ value: Value) {
        modify { $0 = value }
    }

    /// Change the value in place, then wake waiting receivers. Ignored once
    /// closed.
    public func modify(_ body: (inout Value) -> Void) {
        let s = state.pointer
        let woken = lock.withLock { () -> [WaitList.Waiter] in
            guard !s.pointee.closed else { return [] }
            body(&s.pointee.value)
            s.pointee.version &+= 1
            return waiters.pointer.pointee.takeAll()
        }
        for w in woken { w.continuation.resume(returning: Watch.codeChanged) }
    }

    /// No more values: waiting and future `changed()` calls throw `.closed`
    /// once they have seen the last value.
    public func close() {
        let s = state.pointer
        let woken = lock.withLock { () -> [WaitList.Waiter] in
            s.pointee.closed = true
            return waiters.pointer.pointee.takeAll()
        }
        for w in woken { w.continuation.resume(returning: Watch.codeClosed) }
    }

    /// A receiver that has seen the current value.
    public func subscribe() -> Receiver {
        Receiver(watch: self, seen: lock.withLock { state.pointer.pointee.version })
    }

    /// Waits for values newer than the last one it saw.
    public struct Receiver: Sendable {
        public let watch: Watch
        private var seen: UInt64

        fileprivate init(watch: Watch, seen: UInt64) {
            self.watch = watch
            self.seen = seen
        }

        /// The current value; it counts as seen.
        public var value: Value {
            mutating get {
                let (v, version) = watch.snapshot()
                seen = version
                return v
            }
        }

        /// Whether a value arrived that this receiver hasn't seen.
        public var hasChanged: Bool { watch.snapshot().1 != seen }

        /// Wait until there is a value this receiver hasn't seen, and mark it
        /// seen; read it with `value`. Throws `.closed` once the watch is
        /// closed and nothing new is left, `.cancelled` if cancelled.
        public mutating func changed() async throws(ChannelError) {
            let w = watch, s = w.state.pointer, last = seen
            var now: UInt64 = 0
            let code = await park(WaitListRef(lock: w.lock, list: w.waiters.pointer),
                                  cancelled: Watch.codeCancelled) { () -> UInt8? in
                now = s.pointee.version
                if now != last { return Watch.codeChanged }
                return s.pointee.closed ? Watch.codeClosed : nil
            }
            switch code {
            case Watch.codeChanged:
                // Found at once, or woken by a send: then read it afresh.
                seen = now != last ? now : watch.snapshot().1
                await Runtime.consumeBudget()
            case Watch.codeClosed:
                throw .closed
            default:
                throw .cancelled
            }
        }
    }

    fileprivate func snapshot() -> (Value, UInt64) {
        lock.withLock { (state.pointer.pointee.value, state.pointer.pointee.version) }
    }
}
