import CVega
import Synchronization
#if os(Linux)
@_spi(ExperimentalCustomExecutors) import _Concurrency
#endif

/// A Vega runtime: a pool of worker threads that run Swift tasks with work
/// stealing.
///
/// ```swift
/// let rt = Runtime()
/// let n = try rt.block { await work() }      // from a plain thread
/// rt.spawn { await serve() }                 // fire and forget
/// ```
///
/// Tasks started with ``spawn(_:)``, and everything they `await`, run on the
/// runtime. A plain `Task {}` started inside one does **not** inherit it
/// (Swift drops the executor preference for unstructured tasks) unless the
/// runtime was made the process's global executor with ``installGlobal(workers:name:)``.
public final class Runtime: Sendable {
    let scheduler: Scheduler

    public var workerCount: Int { scheduler.workers.count }

    /// - Parameters:
    ///   - workers: worker threads; defaults to the number of online CPUs.
    ///   - name: thread name prefix.
    ///   - pinThreads: pin worker *i* to CPU *i*.
    ///   - io: the I/O driver; see ``IOBackend``.
    ///   - blockingThreads: most threads ``blocking(_:)`` runs at once.
    ///   - blockingKeepAlive: how long an idle blocking thread lives.
    public init(workers: Int? = nil, name: String = "vega", pinThreads: Bool = false,
                io: IOBackend = .automatic,
                blockingThreads: Int = 512, blockingKeepAlive: Duration = .seconds(10)) {
        scheduler = Scheduler(workers: workers ?? Int(cv_cpu_count()), name: name, pin: pinThreads,
                              io: io, blockingThreads: blockingThreads,
                              blockingKeepAlive: blockingKeepAlive)
    }

    /// A runtime with no threads of its own (Tokio's `current_thread`): its
    /// tasks run only while some thread is inside ``block(_:)``, on that
    /// thread. For tests, clients and command-line tools that want
    /// everything on one thread; spawned tasks wait for the next `block`.
    ///
    /// One `block` at a time. It uses the readiness driver (epoll, kqueue):
    /// an io_uring takes submissions from a single thread, and `block` may
    /// be called from different ones.
    public static func currentThread(name: String = "vega",
                                     blockingThreads: Int = 512,
                                     blockingKeepAlive: Duration = .seconds(10)) -> Runtime {
        Runtime(scheduler: Scheduler(workers: 1, name: name, pin: false, io: .readiness, currentThread: true,
                                     blockingThreads: blockingThreads, blockingKeepAlive: blockingKeepAlive))
    }

    init(scheduler: Scheduler) {
        self.scheduler = scheduler
    }

    /// Whether this is a ``currentThread(name:blockingThreads:blockingKeepAlive:)`` runtime.
    public var isCurrentThread: Bool { scheduler.isCurrentThread }

    /// The I/O driver running: `.ioUring` or `.readiness`.
    public var ioBackend: IOBackend { scheduler.usesRings ? .ioUring : .readiness }

    /// The runtime as a `TaskExecutor`, for `Task(executorPreference:)`,
    /// `withTaskExecutorPreference` and `TaskGroup.addTask(executorPreference:)`.
    public var executor: any TaskExecutor { scheduler }

    @discardableResult
    public func spawn<Success: Sendable>(
        priority: TaskPriority? = nil,
        _ operation: sending @escaping () async -> Success
    ) -> Task<Success, Never> {
        Task(executorPreference: scheduler, priority: priority, operation: operation)
    }

    @discardableResult
    public func spawn<Success: Sendable>(
        priority: TaskPriority? = nil,
        _ operation: sending @escaping () async throws -> Success
    ) -> Task<Success, any Error> {
        Task(executorPreference: scheduler, priority: priority, operation: operation)
    }

    /// Spawn a task that takes ownership of `value`, such as a `TCPStream`
    /// (a closure can't capture a `~Copyable` value):
    ///
    /// ```swift
    /// let stream = try await listener.accept()
    /// rt.spawn(with: stream) { stream in await serve(stream) }
    /// ```
    @discardableResult
    public func spawn<Value: ~Copyable & Sendable, Success: Sendable>(
        with value: consuming Value,
        priority: TaskPriority? = nil,
        _ operation: sending @escaping (consuming Value) async -> Success
    ) -> Task<Success, Never> {
        let box = Handoff(value)
        return Task(executorPreference: scheduler, priority: priority) { await operation(box.take()) }
    }

    /// Run `operation` on the runtime and block the calling thread until it
    /// finishes. Must not be called from a worker thread of any Vega runtime.
    public func block<T: Sendable, E: Error>(
        _ operation: sending @escaping () async throws(E) -> T
    ) throws(E) -> T {
        precondition(Worker.current == nil, "Runtime.block called on a Vega worker thread")
        if scheduler.isCurrentThread { return try blockDriving(operation) }
        let waiter = BlockWaiter<T, E>()
        Task(executorPreference: scheduler) {
            let result: Result<T, E>
            do throws(E) {
                result = .success(try await operation())
            } catch {
                result = .failure(error)
            }
            waiter.finish(result)
        }
        return try waiter.wait().get()
    }

    /// `block` on a current-thread runtime: run the worker's loop here until
    /// the operation's task has finished.
    private func blockDriving<T: Sendable, E: Error>(
        _ operation: sending @escaping () async throws(E) -> T
    ) throws(E) -> T {
        let worker = scheduler.workers[0]
        precondition(scheduler.driving.exchange(true, ordering: .acquiring) == false,
                     "Runtime.block: a current-thread runtime runs one block at a time")
        defer { scheduler.driving.store(false, ordering: .releasing) }
        let result = DriveResult<T, E>()
        Task(executorPreference: scheduler) {
            let r: Result<T, E>
            do throws(E) {
                r = .success(try await operation())
            } catch {
                r = .failure(error)
            }
            result.value.withLock { $0 = r }
            worker.driveDone.store(true, ordering: .releasing)
            cv_unpark(worker.parker)
        }
        worker.drive()
        guard let r = result.value.withLock({ $0.take() }) else {
            preconditionFailure("Runtime.block: the runtime was shut down first")
        }
        return try r.get()
    }

    /// Stop the workers. Jobs still queued are dropped, so shut down only
    /// once the tasks you care about have finished. Idle blocking threads
    /// exit; running blocking jobs finish first.
    public func shutdown() {
        scheduler.shutdown()
    }

    /// Suspend the calling task for `duration`, on Vega's own timers.
    ///
    /// Prefer this to `Task.sleep` when the runtime is not the global
    /// executor: `Task.sleep` wakes through a helper task that Swift runs on
    /// the *global* executor, so a busy global pool delays it. This parks the
    /// caller's continuation directly and resumes it on the firing worker.
    /// Cancelling the task ends the sleep at once and frees its timer.
    /// Off a Vega worker it falls back to `Task.sleep`.
    ///
    /// Timers have millisecond resolution and never fire early.
    public static func sleep(for duration: Duration) async throws {
        let now = nowNanos
        let ns = UInt64(clamping: Scheduler.nanoseconds(duration))
        try await sleep(untilNanos: ns > UInt64.max - now ? UInt64.max - 1 : now + ns, now: now)
    }

    /// Suspend the calling task until `deadline`, on Vega's own timers. See
    /// `sleep(for:)`.
    public static func sleep(until deadline: ContinuousClock.Instant) async throws {
        guard let s = Worker.currentScheduler else {
            try await sleep(for: ContinuousClock.now.duration(to: deadline))
            return
        }
        let now = s.clock.now
        try await sleep(untilNanos: max(s.clock.nanos(deadline), now), now: now)
    }

    /// Sleep until `deadline`, a runtime-clock time.
    static func sleep(untilNanos deadline: UInt64, now: UInt64) async throws {
        guard let worker = Worker.current,
              let scheduler = worker._withUnsafeGuaranteedRef({ $0.scheduler }) else {
            try await Task.sleep(for: .nanoseconds(deadline > now ? Int64(clamping: deadline - now) : 0))
            return
        }
        try Task.checkCancellation()
        let waiter = SleepWaiter(shard: worker._withUnsafeGuaranteedRef { $0.index })
        try await withTaskCancellationHandler {
            try await withUnsafeThrowingContinuation { (c: UnsafeContinuation<Void, any Error>) in
                if waiter.arm(c) {
                    scheduler.addTimer(.waiter(.passRetained(waiter)), deadline: deadline, now: now, shard: waiter.shard)
                } else {
                    c.resume(throwing: CancellationError())
                }
            }
        } onCancel: {
            if waiter.cancel() { scheduler.removeSleep(waiter) }
        }
    }

    /// The index of the Vega worker running the caller, or nil off-runtime.
    public static var currentWorker: Int? { Worker.current?._withUnsafeGuaranteedRef { $0.index } }

    /// Per-worker counters.
    public var metrics: [(jobs: UInt64, steals: UInt64)] {
        scheduler.workers.map { ($0.jobsRun.load(ordering: .relaxed), $0.steals.load(ordering: .relaxed)) }
    }

    /// Enqueues since start: timed ones (sleeps and timeouts, and on Linux
    /// `Task.sleep` too), and ones from threads outside the runtime.
    public var enqueueCounts: (timed: UInt64, foreign: UInt64) {
        (scheduler.timedEnqueues.load(ordering: .relaxed), scheduler.foreignEnqueues.load(ordering: .relaxed))
    }

    /// I/O driver counters since start (zeros where there is no driver).
    public var ioMetrics: IOMetrics {
        #if os(Linux)
        if scheduler.usesRings {
            var m = IOMetrics()
            for w in scheduler.workers {
                let s = cv_uring_get_stats(w.ring)
                m.parkedPolls &+= s.parked_turns
                m.busyPolls &+= s.busy_turns
                m.events &+= s.events
                m.wakes &+= s.wakes
                m.fullBatches &+= s.full_batches
            }
            return m
        }
        #endif
        #if os(Linux) || canImport(Darwin)
        if let d = scheduler.driver {
            let s = cv_driver_get_stats(d.raw)
            return IOMetrics(parkedPolls: s.parked_turns, busyPolls: s.busy_turns, events: s.events,
                             wakes: s.wakes, fullBatches: s.full_batches)
        }
        #endif
        return IOMetrics()
    }

    /// Make a new runtime the global executor, so every `Task {}`,
    /// `Task.detached` and `Task.sleep` in the process runs on Vega.
    ///
    /// Must be called before the first task is created (first thing in a
    /// synchronous `main`). Uses Swift's experimental custom-executor SPI.
    /// Apple's SDKs leave that SPI out, so there only global enqueues come
    /// to Vega (through the runtime's enqueue hook), and `Task.sleep` keeps
    /// the platform's timers.
    public static func installGlobal(workers: Int? = nil, name: String = "vega") -> Runtime {
        precondition(installedGlobal == nil, "Runtime.installGlobal called twice")
        let rt = Runtime(workers: workers, name: name)
        installedGlobal = rt.scheduler
        #if os(Linux)
        _createExecutors(factory: VegaExecutorFactory.self)
        #endif
        rt.scheduler.installEnqueueGlobalHook()
        return rt
    }
}

/// Carries a `~Copyable` value into a task: taken exactly once, by the task.
private final class Handoff<Value: ~Copyable>: @unchecked Sendable {
    private var value: Value?

    init(_ value: consuming Value) { self.value = consume value }

    func take() -> Value { value.take()! }
}

/// Hands a result from a task to a blocked plain thread.
/// The outcome of a current-thread `block`'s operation.
private final class DriveResult<T: Sendable, E: Error>: Sendable {
    let value = Mutex<Result<T, E>?>(nil)
}

private final class BlockWaiter<T: Sendable, E: Error>: @unchecked Sendable {
    private let parker = cv_parker_new()!
    private let result = Mutex<Result<T, E>?>(nil)

    deinit { cv_parker_free(parker) }

    func finish(_ r: sending Result<T, E>) {
        result.withLock { $0 = r }
        cv_unpark(parker)
    }

    func wait() -> Result<T, E> {
        while true {
            if let r = result.withLock({ $0.take() }) { return r }
            cv_park(parker, -1)
        }
    }
}
