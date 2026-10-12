/// A multi-producer, single-consumer queue: Tokio's `mpsc`.
///
/// ```swift
/// let ch = Channel<Job>(capacity: 64)
/// for _ in 0..<4 { rt.spawn(with: ch.sender.clone()) { tx in try? await tx.send(work()) } }
/// var rx = ch.receiver
/// while let job = try? await rx.receive() { ... }
/// ```
///
/// - A bounded channel holds up to `capacity` values; `send` waits for room.
///   Waiting senders are served in order: each receive moves the oldest
///   parked value into the buffer and wakes its sender.
/// - `Channel.unbounded()` never waits for room. Use `trySend` to send
///   without `await`.
/// - Senders are `~Copyable`; make more with `clone()`. When the last one
///   drops, the receiver drains what is buffered, then gets `.closed`.
/// - Dropping the receiver fails every send, and drops what was buffered.
///
/// Values may be `~Copyable` (sockets, buffers). A send that fails drops its
/// value. Handles hold the channel without per-operation reference counting.
@frozen
public struct Channel<Element: ~Copyable & Sendable>: ~Copyable, Sendable {
    public var sender: Sender
    public var receiver: Receiver

    /// A bounded channel: `send` waits while `capacity` values are queued.
    @inlinable
    public init(capacity: Int) {
        precondition(capacity > 0, "capacity must be positive")
        let core = ChannelCore<Element>(capacity: capacity)
        sender = Sender(core)
        receiver = Receiver(core)
    }

    /// A channel without a bound: sends never wait.
    @inlinable
    public static func unbounded() -> Channel { Channel(capacity: .max) }

    @frozen
    public struct Sender: ~Copyable, Sendable {
        @usableFromInline unowned(unsafe) let core: ChannelCore<Element>

        @inlinable
        init(_ core: ChannelCore<Element>) {
            self.core = core
            _ = Unmanaged.passRetained(core)
        }

        deinit {
            core.dropSender()
            Unmanaged.passUnretained(core).release()
        }

        /// Another sender on the same channel.
        @inlinable
        public func clone() -> Sender {
            core.addSender()
            return Sender(core)
        }

        /// Queue `value`, waiting for room if the channel is full. Throws,
        /// dropping the value, if the receiver is gone (`.closed`) or the
        /// task is cancelled while waiting (`.cancelled`).
        @inlinable
        public func send(_ value: consuming Element) async throws(ChannelError) {
            try await core.send(value)
        }

        /// Queue `value` if there is room now. Throws, dropping the value,
        /// if the channel is full or closed.
        @inlinable
        public func trySend(_ value: consuming Element) throws(TrySendError) {
            try core.trySend(value)
        }

        /// True once the receiver is gone or closed the channel.
        @inlinable
        public var isClosed: Bool { core.isClosed }
    }

    @frozen
    public struct Receiver: ~Copyable, Sendable {
        @usableFromInline unowned(unsafe) let core: ChannelCore<Element>

        @inlinable
        init(_ core: ChannelCore<Element>) {
            self.core = core
            _ = Unmanaged.passRetained(core)
        }

        deinit {
            core.dropReceiver()
            Unmanaged.passUnretained(core).release()
        }

        /// The next value, waiting for one. Throws `.closed` once every
        /// sender is gone and the buffer is empty, `.cancelled` if the task
        /// is cancelled while waiting (nothing is lost).
        @inlinable
        public mutating func receive() async throws(ChannelError) -> Element {
            try await core.receive()
        }

        /// The next value if one is queued.
        @inlinable
        public mutating func tryReceive() throws(TryReceiveError) -> Element {
            try core.tryReceive()
        }

        /// Stop further sends; what is queued can still be received.
        @inlinable
        public func close() { core.close() }

        /// Values queued now.
        @inlinable
        public var count: Int { core.count }
    }
}

@usableFromInline
final class ChannelCore<Element: ~Copyable & Sendable>: @unchecked Sendable {
    /// A sender waiting for room, with the value it will send.
    @usableFromInline
    struct Parked: ~Copyable {
        @usableFromInline let id: UInt
        @usableFromInline var value: Element
        /// Resumed with 0 (queued), 1 (closed) or 2 (cancelled).
        @usableFromInline let continuation: UnsafeContinuation<UInt8, Never>

        @inlinable
        init(id: UInt, value: consuming Element, continuation: UnsafeContinuation<UInt8, Never>) {
            self.id = id
            self.value = value
            self.continuation = continuation
        }
    }

    @usableFromInline
    struct State {
        @usableFromInline var buffer: RawRing<Element>
        /// Never empty unless the buffer is full.
        @usableFromInline var parked = RawRing<Parked>(capacity: 4)
        @usableFromInline var receiver: UnsafeContinuation<Void, Never>? = nil
        @usableFromInline var senders = 1
        @usableFromInline var closed = false

        @inlinable init(buffer: RawRing<Element>) { self.buffer = buffer }
    }

    @usableFromInline let capacity: Int
    @usableFromInline let lock = RawLock()
    @usableFromInline let state: UnsafeMutablePointer<State>

    @inlinable
    init(capacity: Int) {
        self.capacity = capacity
        // Grows as needed; a big bound doesn't allocate up front.
        var initial = 16
        while initial < min(capacity, 256) { initial <<= 1 }
        state = .allocate(capacity: 1)
        state.initialize(to: State(buffer: RawRing(capacity: initial)))
    }

    deinit {
        state.pointee.buffer.destroy()
        state.pointee.parked.destroy()
        state.deinitialize(count: 1)
        state.deallocate()
        lock.destroy()
    }

    @inlinable var isClosed: Bool { lock.withLock { state.pointee.closed } }

    @inlinable var count: Int { lock.withLock { state.pointee.buffer.count } }

    @inlinable
    func addSender() { lock.withLock { state.pointee.senders += 1 } }

    @inlinable
    func dropSender() {
        let s = state
        lock.lock()
        s.pointee.senders -= 1
        let waiter = s.pointee.senders == 0 ? s.pointee.receiver.take() : nil
        lock.unlock()
        waiter?.resume()
    }

    /// Under the lock: room for one more without overtaking a parked sender.
    @inlinable @inline(__always)
    func hasRoom(_ s: UnsafeMutablePointer<State>) -> Bool {
        s.pointee.parked.isEmpty && s.pointee.buffer.count < capacity
    }

    @inlinable
    func trySend(_ value: consuming Element) throws(TrySendError) {
        let s = state
        lock.lock()
        if s.pointee.closed {
            lock.unlock()
            throw .closed
        }
        guard hasRoom(s) else {
            lock.unlock()
            throw .full
        }
        s.pointee.buffer.pushBack(value)
        let waiter = s.pointee.receiver.take()
        lock.unlock()
        waiter?.resume()
    }

    @inlinable
    func send(_ value: consuming Element) async throws(ChannelError) {
        let s = state
        var item = Optional(value)
        lock.lock()
        if s.pointee.closed {
            lock.unlock()
            throw .closed
        }
        if hasRoom(s) {
            s.pointee.buffer.pushBack(item.take()!)
            let waiter = s.pointee.receiver.take()
            lock.unlock()
            waiter?.resume()
            await Runtime.consumeBudget()
            return
        }
        lock.unlock()

        // Full: park the value with the continuation.
        let id = currentTaskID()
        let code = await withTaskCancellationHandler {
            await withUnsafeContinuation { (c: UnsafeContinuation<UInt8, Never>) in
                lock.lock()
                if s.pointee.closed {
                    lock.unlock()
                    c.resume(returning: 1)
                    return
                }
                if hasRoom(s) { // a receive made room meanwhile
                    s.pointee.buffer.pushBack(item.take()!)
                    let waiter = s.pointee.receiver.take()
                    lock.unlock()
                    waiter?.resume()
                    c.resume(returning: 0)
                    return
                }
                // Checked under the lock: either the cancel handler runs
                // after this and finds the parked sender, or the flag is set.
                if Task.isCancelled {
                    lock.unlock()
                    c.resume(returning: 2)
                    return
                }
                s.pointee.parked.pushBack(Parked(id: id, value: item.take()!, continuation: c))
                lock.unlock()
            }
        } onCancel: {
            lock.lock()
            let parked = state.pointee.parked.remove { $0.id == id }
            lock.unlock()
            // Its value drops here, outside the lock.
            if let parked { parked.continuation.resume(returning: 2) }
        }
        switch code {
        case 0: return
        case 1: throw .closed
        default: throw .cancelled
        }
    }

    /// Under the lock: the next value, refilling from the oldest parked
    /// sender, whose continuation goes in `wake`.
    @inlinable @inline(__always)
    func pop(_ s: UnsafeMutablePointer<State>,
             _ wake: inout UnsafeContinuation<UInt8, Never>?) -> Element? {
        guard let x = s.pointee.buffer.popFront() else { return nil }
        if let p = s.pointee.parked.popFront() {
            wake = p.continuation
            s.pointee.buffer.pushBack(p.value)
        }
        return x
    }

    @inlinable
    func tryReceive() throws(TryReceiveError) -> Element {
        let s = state
        var wake: UnsafeContinuation<UInt8, Never>? = nil
        lock.lock()
        if let x = pop(s, &wake) {
            lock.unlock()
            wake?.resume(returning: 0)
            return x
        }
        let done = s.pointee.closed || s.pointee.senders == 0
        lock.unlock()
        throw done ? .closed : .empty
    }

    @inlinable
    func receive() async throws(ChannelError) -> Element {
        let s = state
        while true {
            var wake: UnsafeContinuation<UInt8, Never>? = nil
            lock.lock()
            if let x = pop(s, &wake) {
                lock.unlock()
                wake?.resume(returning: 0)
                await Runtime.consumeBudget()
                return x
            }
            if s.pointee.closed || s.pointee.senders == 0 {
                lock.unlock()
                throw .closed
            }
            lock.unlock()
            if Task.isCancelled { throw .cancelled }

            await withTaskCancellationHandler {
                await withUnsafeContinuation { (c: UnsafeContinuation<Void, Never>) in
                    lock.lock()
                    if !s.pointee.buffer.isEmpty || s.pointee.closed || s.pointee.senders == 0 || Task.isCancelled {
                        lock.unlock()
                        c.resume()
                        return
                    }
                    s.pointee.receiver = c
                    lock.unlock()
                }
            } onCancel: {
                lock.lock()
                let waiter = state.pointee.receiver.take()
                lock.unlock()
                waiter?.resume()
            }
        }
    }

    /// Fail parked and future sends. Returns the parked senders.
    @inlinable
    func closeLocked() -> RawRing<Parked> {
        state.pointee.closed = true
        let parked = state.pointee.parked
        state.pointee.parked = RawRing(capacity: 1)
        return parked
    }

    @inlinable
    func fail(_ parked: consuming RawRing<Parked>) {
        while let p = parked.popFront() { p.continuation.resume(returning: 1) }
        parked.destroy()
    }

    @inlinable
    func close() {
        let parked = lock.withLock { closeLocked() }
        fail(parked)
    }

    @inlinable
    func dropReceiver() {
        lock.lock()
        let parked = closeLocked()
        let buffered = state.pointee.buffer
        state.pointee.buffer = RawRing(capacity: 1)
        lock.unlock()
        // Values drop outside the lock: their deinits may do anything.
        fail(parked)
        var b = buffered
        b.destroy()
    }
}
