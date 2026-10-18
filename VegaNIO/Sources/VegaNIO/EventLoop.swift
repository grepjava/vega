import Dispatch
import NIOConcurrencyHelpers
import NIOCore
import Synchronization
import class Vega.Runtime
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// A SwiftNIO event loop on a Vega runtime.
///
/// NIO promises a channel's handlers run one at a time, never at once, so a
/// loop is a serial queue of work: whoever holds the loop runs what is
/// queued, in order, until nothing is. That is the loop's own task when work
/// arrives from outside, or a channel's I/O task delivering what it read,
/// which takes the loop when it is free and so skips a hop. Either way it
/// runs on a Vega worker, though not always the same one: like
/// NIOTransportServices' loops on Dispatch, a loop is serial but not tied
/// to a thread. `inEventLoop` is true on the thread running the loop, while
/// it runs it.
///
/// Swift tasks isolated to the loop (`eventLoop.executor`) run there too,
/// inline, so `assumeIsolated` and `preconditionInEventLoop` hold in them.
public final class VegaEventLoop: EventLoop, @unchecked Sendable {
    /// The runtime the loop runs on.
    public let runtime: Runtime

    private enum Work {
        case closure(@Sendable () -> Void)
        case job(UnownedJob)
    }

    private struct State {
        var queue = CircularBuffer<Work>(initialCapacity: 64)
        /// Someone is running the loop.
        var owned = false
        /// The loop's task, waiting for work: true to run it, false to stop.
        var waiter: UnsafeContinuation<Bool, Never>?
        /// The loop is stopped: work is dropped.
        var stopped = false
    }

    private let state = NIOLockedValueBox(State())
    /// The owner's spare queue, swapped with the shared one to run a batch.
    private nonisolated(unsafe) var spare = CircularBuffer<Work>(initialCapacity: 64)
    /// Channels registered here (on the loop only), to close at shutdown.
    private nonisolated(unsafe) var channels: [ObjectIdentifier: Channel] = [:]
    private nonisolated(unsafe) var closing = false
    private let id: Int

    init(runtime: Runtime, id: Int) {
        self.runtime = runtime
        self.id = id
    }

    /// Start the loop's task.
    func start() {
        runtime.spawn { [self] in
            while await park() { await drain() }
        }
    }

    // MARK: Running

    /// Wait until there is work and nobody running it; then the loop is ours.
    // Not inlined: Swift 6.3.3's optimizer miscompiles a continuation stored
    // under a pthread lock (NIOLock) once this is inlined into a loop whose
    // body also awaits; resuming it then jumps to address 0 (release only).
    @inline(never)
    private func park() async -> Bool {
        await withUnsafeContinuation { (c: UnsafeContinuation<Bool, Never>) in
            let now: Bool? = state.withLockedValue { s in
                if s.stopped { return false }
                if !s.owned && !s.queue.isEmpty {
                    s.owned = true
                    return true
                }
                s.waiter = c
                return nil
            }
            if let now { c.resume(returning: now) }
        }
    }

    /// Run queued work until there is none; the caller owns the loop, and
    /// doesn't after.
    private func drain() async {
        while true {
            let previous = CurrentLoop.enter(self)
            var ran = 0
            var done = false
            while ran < 1024 {
                let more = state.withLockedValue { s -> Bool in
                    if s.queue.isEmpty {
                        s.owned = false
                        return false
                    }
                    swap(&s.queue, &spare)
                    return true
                }
                guard more else {
                    done = true
                    break
                }
                ran += spare.count
                while let work = spare.popFirst() {
                    switch work {
                    case .closure(let body): body()
                    case .job(let job): job.runSynchronously(on: asUnownedSerialExecutor())
                    }
                }
            }
            CurrentLoop.leave(previous)
            if done { return }
            // A busy loop lets the worker run other tasks now and then; it
            // still owns the loop meanwhile.
            await Task.yield()
        }
    }

    private func enqueue(_ work: Work) {
        let wake = state.withLockedValue { s -> UnsafeContinuation<Bool, Never>? in
            guard !s.stopped else { return nil }
            s.queue.append(work)
            guard !s.owned, let w = s.waiter else { return nil }
            s.waiter = nil
            s.owned = true
            return w
        }
        wake?.resume(returning: true)
    }

    /// Run `body` on the loop: now, on this task, if nobody is running the
    /// loop; otherwise after what is queued, by whoever is.
    func run(_ body: @escaping @Sendable () -> Void) async {
        let mine = state.withLockedValue { s -> Bool in
            guard !s.stopped else { return false }
            s.queue.append(.closure(body))
            guard !s.owned else { return false }
            s.owned = true
            return true
        }
        if mine { await drain() }
    }

    /// Stop the loop: its task ends and later work is dropped.
    func stop() {
        let wake = state.withLockedValue { s -> UnsafeContinuation<Bool, Never>? in
            s.stopped = true
            s.queue.removeAll()
            defer { s.waiter = nil }
            return s.waiter
        }
        wake?.resume(returning: false)
    }

    // MARK: EventLoop

    public var inEventLoop: Bool { CurrentLoop.current == Unmanaged.passUnretained(self).toOpaque() }

    public func execute(_ task: @escaping @Sendable () -> Void) {
        enqueue(.closure(task))
    }

    public func enqueue(_ job: consuming ExecutorJob) {
        enqueue(.job(UnownedJob(job)))
    }

    public func scheduleTask<T>(deadline: NIODeadline, _ task: @escaping @Sendable () throws -> T) -> Scheduled<T> {
        let promise = makePromise(of: T.self)
        let delay = deadline.uptimeNanoseconds &- NIODeadline.now().uptimeNanoseconds
        let cancelled = CancelFlag()
        let timer = runtime.spawn { [self] in
            if Int64(bitPattern: delay) > 0 {
                do { try await Runtime.sleep(for: .nanoseconds(Int64(bitPattern: delay))) } catch { return }
            }
            execute {
                // Cancelled on the loop before this ran: it doesn't.
                guard !cancelled.value.load(ordering: .acquiring) else { return }
                promise.assumeIsolated().completeWith(Result { try task() })
            }
        }
        return Scheduled(promise: promise, cancellationTask: {
            cancelled.value.store(true, ordering: .releasing)
            timer.cancel()
        })
    }

    public func scheduleTask<T>(in delay: TimeAmount, _ task: @escaping @Sendable () throws -> T) -> Scheduled<T> {
        scheduleTask(deadline: .now() + delay, task)
    }

    public func preconditionInEventLoop(file: StaticString, line: UInt) {
        precondition(inEventLoop, "not on this event loop", file: file, line: line)
    }

    public func preconditionNotInEventLoop(file: StaticString, line: UInt) {
        precondition(!inEventLoop, "on this event loop", file: file, line: line)
    }

    public func shutdownGracefully(queue: DispatchQueue, _ callback: @escaping @Sendable (Error?) -> Void) {
        queue.async { callback(EventLoopError.unsupportedOperation) }
    }

    // MARK: Channels

    /// Record `channel` as on this loop until it deregisters. On the loop.
    func register(_ channel: Channel) throws {
        guard !closing else { throw EventLoopError.shutdown }
        channels[ObjectIdentifier(channel)] = channel
    }

    func deregister(_ channel: Channel) {
        channels[ObjectIdentifier(channel)] = nil
    }

    /// Close every channel here and take no more. On the loop.
    func closeChannels() -> EventLoopFuture<Void> {
        closing = true
        let futures = channels.values.map { channel in
            channel.close().recover { _ in }
        }
        return EventLoopFuture.andAllComplete(futures, on: self)
    }
}

extension VegaEventLoop: NIOSerialEventLoopExecutor {}

extension VegaEventLoop: CustomStringConvertible {
    public var description: String { "VegaEventLoop(\(id))" }
}

private final class CancelFlag: Sendable {
    let value = Atomic<Bool>(false)
}

/// Run `body` on a new, detached thread.
private func detachThread(_ body: @escaping @Sendable () -> Void) {
    final class Box { let body: @Sendable () -> Void; init(_ body: @escaping @Sendable () -> Void) { self.body = body } }
    let context = Unmanaged.passRetained(Box(body)).toOpaque()
    #if canImport(Darwin)
    var thread: pthread_t?
    #else
    var thread = pthread_t()
    #endif
    let result = pthread_create(&thread, nil, { context in
        #if canImport(Darwin)
        let box = Unmanaged<Box>.fromOpaque(context).takeRetainedValue()
        #else
        let box = Unmanaged<Box>.fromOpaque(context!).takeRetainedValue()
        #endif
        box.body()
        return nil
    }, context)
    precondition(result == 0, "pthread_create failed: \(result)")
    #if canImport(Darwin)
    pthread_detach(thread!)
    #else
    pthread_detach(thread)
    #endif
}

/// Which loop the calling thread is running, if any.
enum CurrentLoop {
    private static let key: pthread_key_t = {
        var key = pthread_key_t()
        precondition(pthread_key_create(&key, nil) == 0)
        return key
    }()

    static var current: UnsafeMutableRawPointer? { pthread_getspecific(key) }

    static func enter(_ loop: VegaEventLoop) -> UnsafeMutableRawPointer? {
        let previous = pthread_getspecific(key)
        pthread_setspecific(key, Unmanaged.passUnretained(loop).toOpaque())
        return previous
    }

    static func leave(_ previous: UnsafeMutableRawPointer?) {
        pthread_setspecific(key, previous)
    }
}

/// SwiftNIO's `EventLoopGroup` over a Vega runtime: hand it to code written
/// for NIO in place of a `MultiThreadedEventLoopGroup`.
///
/// ```swift
/// let group = VegaEventLoopGroup(loops: 8)
/// let server = try await VegaServerBootstrap(group: group)
///     .childChannelInitializer { $0.pipeline.addHandler(Echo()) }
///     .bind(host: "127.0.0.1", port: 8080).get()
/// ```
///
/// Loops are serial queues, not threads: a group can have more loops than
/// the runtime has workers, and the runtime's workers run whichever loops
/// have work.
public final class VegaEventLoopGroup: EventLoopGroup, Sendable {
    public let runtime: Runtime
    private let loops: [VegaEventLoop]
    private let index = Atomic<Int>(0)
    private let ownsRuntime: Bool
    private let shutDown = Atomic<Bool>(false)

    /// `loops` event loops on `runtime`.
    public init(runtime: Runtime, loops: Int? = nil) {
        precondition(loops ?? 1 > 0, "a group needs at least one loop")
        self.runtime = runtime
        ownsRuntime = false
        self.loops = (0..<(loops ?? runtime.workerCount)).map { VegaEventLoop(runtime: runtime, id: $0) }
        for loop in self.loops { loop.start() }
    }

    /// `loops` event loops on a runtime of their own, with a worker for each
    /// (`loops` defaults to the CPU count). Shutting the group down shuts
    /// the runtime down.
    public init(loops: Int? = nil, name: String = "vega-nio") {
        let runtime = Runtime(workers: loops, name: name)
        self.runtime = runtime
        ownsRuntime = true
        self.loops = (0..<runtime.workerCount).map { VegaEventLoop(runtime: runtime, id: $0) }
        for loop in self.loops { loop.start() }
    }

    public func next() -> EventLoop {
        loops[index.wrappingAdd(1, ordering: .relaxed).oldValue % loops.count]
    }

    /// The loop the caller is running on, if it is one of these.
    public func any() -> EventLoop {
        if let current = CurrentLoop.current, let loop = loops.first(where: {
            Unmanaged.passUnretained($0).toOpaque() == current
        }) {
            return loop
        }
        return next()
    }

    public func makeIterator() -> EventLoopIterator {
        EventLoopIterator(loops)
    }

    /// Close every channel, stop the loops, and shut down the runtime if the
    /// group made it.
    public func shutdownGracefully(queue: DispatchQueue, _ callback: @escaping @Sendable (Error?) -> Void) {
        shutdown { error in queue.async { callback(error) } }
    }

    /// NIO's `syncShutdownGracefully`, without Dispatch: NIO's waits for a
    /// callback on `DispatchQueue.global()`, which on Darwin doesn't come
    /// while every thread of Swift's cooperative pool is blocked the same way
    /// (as when more tests shut a group down at once than there are CPUs).
    @available(*, noasync, message: "this can end up blocking the calling thread", renamed: "shutdownGracefully()")
    public func syncShutdownGracefully() throws {
        _preconditionSafeToSyncShutdown(file: #fileID, line: #line)
        let failure = NIOLockedValueBox<Error?>(nil)
        let semaphore = DispatchSemaphore(value: 0)
        shutdown { error in
            failure.withLockedValue { $0 = error }
            semaphore.signal()
        }
        semaphore.wait()
        if let error = failure.withLockedValue({ $0 }) { throw error }
    }

    /// Shut down, then call `done` from a thread of its own.
    private func shutdown(_ done: @escaping @Sendable (Error?) -> Void) {
        guard !shutDown.exchange(true, ordering: .acquiringAndReleasing) else {
            done(EventLoopError.shutdown)
            return
        }
        let closed = loops.map { loop in loop.flatSubmit { loop.closeChannels() } }
        let loops = self.loops, runtime = self.runtime, ownsRuntime = self.ownsRuntime
        // Wait off the loops (the runtime can't be shut down from a worker)
        // and off Dispatch's pool (see syncShutdownGracefully).
        detachThread {
            for future in closed { _ = try? future.wait() }
            for loop in loops { loop.stop() }
            if ownsRuntime { runtime.shutdown() }
            done(nil)
        }
    }

    public func _preconditionSafeToSyncShutdown(file: StaticString, line: UInt) {
        precondition(CurrentLoop.current == nil, "syncShutdownGracefully on an event loop would deadlock",
                     file: file, line: line)
    }
}
