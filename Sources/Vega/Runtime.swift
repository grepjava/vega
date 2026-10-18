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
/// runtime is the process's global executor: made so with
/// ``installGlobal(workers:name:)``, or a shard's on Linux (``sharded(_:_:)``).
/// Then nothing carries a preference, and an executor hop costs a compare
/// rather than a look-up under the task's status-record lock.
public final class Runtime: Sendable {
    let scheduler: Scheduler

    public var workerCount: Int { scheduler.workers.count }

    /// - Parameters:
    ///   - workers: worker threads; defaults to the number of online CPUs.
    ///   - name: thread name prefix.
    ///   - pinThreads: pin worker *i* to CPU *i*.
    ///   - io: the I/O driver; see ``IOBackend``.
    ///   - blockingThreads: most threads ``blocking(_:)`` runs at once.
    ///   - blockingQueue: most work ``tryBlocking(_:)`` lets wait for one of
    ///     those threads; past it, it refuses (returns nil). ``blocking(_:)``
    ///     always waits. nil: no bound.
    ///   - blockingKeepAlive: how long an idle blocking thread lives.
    ///   - idleSpin: how long a worker with nothing to do spins before it
    ///     sleeps in the kernel; nil for the platform's default (50 µs on
    ///     Linux, none on Darwin). While work keeps coming, a spin saves
    ///     the syscalls of a wake; it takes the CPU from whatever shares
    ///     it, a load generator or another server. Left nil,
    ///     `VEGA_SPIN_NS` sets it when present.
    public init(workers: Int? = nil, name: String = "vega", pinThreads: Bool = false,
                io: IOBackend = .automatic,
                blockingThreads: Int = 512, blockingQueue: Int? = nil,
                blockingKeepAlive: Duration = .seconds(10), idleSpin: Duration? = nil) {
        scheduler = Scheduler(workers: workers ?? Int(cv_cpu_count()), name: name, pin: pinThreads,
                              io: io, idleSpin: idleSpin, blockingThreads: blockingThreads,
                              blockingQueue: blockingQueue, blockingKeepAlive: blockingKeepAlive)
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

    /// A current-thread runtime that runs its tasks in an order drawn from
    /// `seed`, for tests: each time it picks the next job, it picks at
    /// random among all those ready, not the oldest. Its clock is paused
    /// and moves on by itself when everything waits on a timer, as
    /// `MockClock` does.
    ///
    /// The same seed gives the same interleaving of the tasks, as long as
    /// what wakes them is in the runtime: its timers, its sync primitives,
    /// VegaTest's in-memory streams. Real I/O, `blocking` threads and other
    /// threads wake them when they happen to. VegaTest's `Simulation` runs
    /// a test under many seeds, and names the one that fails.
    public static func seeded(_ seed: UInt64, name: String = "vega-seeded") -> Runtime {
        let rt = Runtime(scheduler: Scheduler(workers: 1, name: name, pin: false, io: .readiness, currentThread: true,
                                              seed: seed))
        rt.pauseClock(autoAdvance: true)
        return rt
    }

    /// The seed of a ``seeded(_:name:)`` runtime.
    public var seed: UInt64? { scheduler.seed }

    init(scheduler: Scheduler) {
        self.scheduler = scheduler
    }

    /// Whether this is a ``currentThread(name:blockingThreads:blockingKeepAlive:)`` runtime.
    public var isCurrentThread: Bool { scheduler.isCurrentThread }

    /// The I/O driver running: `.ioUring`, `.network`, `.iocp` or `.readiness`.
    public var ioBackend: IOBackend {
        scheduler.usesNetwork ? .network : scheduler.usesRings ? .ioUring : scheduler.usesIOCP ? .iocp : .readiness
    }

    /// The runtime as a `TaskExecutor`, for `Task(executorPreference:)`,
    /// `withTaskExecutorPreference` and `TaskGroup.addTask(executorPreference:)`.
    public var executor: any TaskExecutor { scheduler }

    @discardableResult
    public func spawn<Success: Sendable>(
        priority: TaskPriority? = nil,
        _ operation: sending @escaping () async -> Success
    ) -> Task<Success, Never> {
        scheduler.task(priority: priority) { await IOTaskHook.run(operation) }
    }

    @discardableResult
    public func spawn<Success: Sendable>(
        priority: TaskPriority? = nil,
        _ operation: sending @escaping () async throws -> Success
    ) -> Task<Success, any Error> {
        scheduler.task(priority: priority) { try await IOTaskHook.run(operation) }
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
        return scheduler.task(priority: priority) {
            await IOTaskHook.run { await operation(box.take()) }
        }
    }

    /// Run `operation` on the runtime and block the calling thread until it
    /// finishes. Must not be called from a worker thread of any Vega runtime.
    public func block<T: Sendable, E: Error>(
        _ operation: sending @escaping () async throws(E) -> T
    ) throws(E) -> T {
        precondition(Worker.current == nil, "Runtime.block called on a Vega worker thread")
        if scheduler.isCurrentThread { return try blockDriving(operation) }
        let waiter = BlockWaiter<T, E>()
        scheduler.task {
            await IOTaskHook.run {
                let result: Result<T, E>
                do throws(E) {
                    result = .success(try await operation())
                } catch {
                    result = .failure(error)
                }
                waiter.finish(result)
            }
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
        scheduler.task {
            let r: Result<T, E> = await IOTaskHook.run {
                do throws(E) {
                    return .success(try await operation())
                } catch {
                    return .failure(error)
                }
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

    /// Spawn a task on the runtime running the caller, as `tokio::spawn`
    /// does: for code that runs on a runtime it was not handed, such as a
    /// library's background reader. Off a Vega worker the task has no
    /// executor preference, and runs where `Task {}` would.
    @discardableResult
    public static func spawn<Success: Sendable>(
        priority: TaskPriority? = nil,
        _ operation: sending @escaping () async -> Success
    ) -> Task<Success, Never> {
        guard let scheduler = Worker.currentScheduler else {
            return Task(priority: priority) { await IOTaskHook.run(operation) }
        }
        return scheduler.task(priority: priority) { await IOTaskHook.run(operation) }
    }

    /// The index of the Vega worker running the caller, or nil off-runtime.
    public static var currentWorker: Int? { Worker.current?._withUnsafeGuaranteedRef { $0.index } }

    /// The physical core the calling thread is running on now, numbered from
    /// 0 up: the hardware threads of one core (hyperthreads) give the same
    /// number, on whichever runtime. nil where the platform does not say
    /// (only Linux does). A pinned worker's answer never changes; a thread
    /// not pinned may have moved by the time it acts on it.
    public static var currentCore: Int? { Scheduler.core(of: Int(cv_current_cpu())) }

    /// How many physical cores this runtime's workers run on: those they are
    /// pinned to, or else those of every CPU the process may use. 0 where
    /// `currentCore` is nil. Two workers on hyperthreads of one core share
    /// it, and work that holds both for long runs at about half speed.
    public var coreCount: Int { scheduler.coreCount }

    /// Which job the caller is running in: the worker, and how many jobs it
    /// had finished when this one started. Equal stamps on either side of a
    /// stretch of code mean it ran without suspending, so the time it took
    /// was all spent holding the worker -- what a server needs to tell a
    /// handler that computes from one that waits.
    ///
    /// ```swift
    /// let stamp = Runtime.currentPollStamp, start = ContinuousClock.now
    /// try await handler()
    /// if Runtime.currentPollStamp == stamp { heldFor(ContinuousClock.now - start) }
    /// ```
    ///
    /// Off a Vega worker it is nil.
    @inlinable
    public static var currentPollStamp: PollStamp? { PollStamp.current() }
}

/// One poll on a Vega worker: see `Runtime.currentPollStamp`.
public struct PollStamp: Sendable, Hashable {
    @usableFromInline let worker: UInt
    @usableFromInline let polls: UInt64

    @usableFromInline init(worker: UInt, polls: UInt64) {
        self.worker = worker
        self.polls = polls
    }

    @usableFromInline static func current() -> PollStamp? {
        guard let w = Worker.current else { return nil }
        return PollStamp(worker: UInt(bitPattern: w.toOpaque()),
                         polls: w._withUnsafeGuaranteedRef { $0.jobsRun.load(ordering: .relaxed) })
    }
}

extension Runtime {

    /// The runtime's counters now (Tokio's `RuntimeMetrics`). Cheap enough
    /// to sample every second; counters are read without stopping the
    /// workers, so they're consistent only to within a few jobs.
    public var metrics: RuntimeMetrics {
        let now = cv_now_ns(), coarse = cv_now_coarse_ns()
        let timing = scheduler.pollTiming.load(ordering: .relaxed)
        let workers = scheduler.workers.map { w -> RuntimeMetrics.Worker in
            let since = w.activeSince.load(ordering: .relaxed)
            let busy = w.busyNanos.load(ordering: .relaxed) &+ (since != 0 && coarse > since ? coarse - since : 0)
            var histogram: [UInt64] = []
            if timing || w.longestPoll.load(ordering: .relaxed) > 0 {
                histogram = (0..<Worker.pollBuckets).map { (w.pollHistogram + $0).pointee.load(ordering: .relaxed) }
            }
            return RuntimeMetrics.Worker(
                polls: w.jobsRun.load(ordering: .relaxed),
                steals: w.steals.load(ordering: .relaxed),
                parks: w.parks.load(ordering: .relaxed),
                overflows: w.queue.overflows.load(ordering: .relaxed),
                forcedYields: w.forcedYields.load(ordering: .relaxed),
                localQueueDepth: w.queue.count,
                busyTime: .nanoseconds(Int64(clamping: busy)),
                pollTimeHistogram: histogram,
                slowPolls: w.slowPolls.load(ordering: .relaxed),
                longestPoll: .nanoseconds(Int64(clamping: w.longestPoll.load(ordering: .relaxed))),
                totalPollTime: .nanoseconds(Int64(clamping: w.pollNanos.load(ordering: .relaxed))))
        }
        let blocking = scheduler.blocking.counts
        return RuntimeMetrics(
            elapsed: .nanoseconds(Int64(clamping: now &- scheduler.startedAt)),
            workers: workers,
            injectQueueDepth: scheduler.inject.count.load(ordering: .relaxed),
            blockingThreads: blocking.threads,
            idleBlockingThreads: blocking.idle,
            blockingQueueDepth: blocking.queued,
            timedEnqueues: scheduler.timedEnqueues.load(ordering: .relaxed),
            foreignEnqueues: scheduler.foreignEnqueues.load(ordering: .relaxed),
            io: ioMetrics)
    }

    /// Time every job the workers run, for `metrics`' poll-time histogram,
    /// slow-poll count and longest poll. Off by default: it costs two clock
    /// reads per job. Takes effect from each worker's next job.
    public var measurePollTimes: Bool {
        get { scheduler.pollTiming.load(ordering: .relaxed) }
        set { scheduler.pollTiming.store(newValue, ordering: .relaxed) }
    }

    /// With `measurePollTimes`, a job that runs this long or longer counts
    /// in `RuntimeMetrics.Worker.slowPolls`: it held its worker, and every
    /// task queued behind it, that long. nil counts none.
    public var slowPollThreshold: Duration? {
        get {
            let ns = scheduler.slowPollNanos.load(ordering: .relaxed)
            return ns == .max ? nil : .nanoseconds(Int64(clamping: ns))
        }
        set {
            scheduler.slowPollNanos.store(newValue.map { UInt64(Scheduler.nanoseconds($0)) } ?? .max,
                                          ordering: .relaxed)
        }
    }

    /// Called on the worker, right after a job that ran `slowPollThreshold`
    /// or longer (with `measurePollTimes` on): the place to log it, or count
    /// it in your own metrics, as tokio-console flags a task that blocked
    /// its worker. Keep it quick: it runs before the worker's next job.
    public var onSlowPoll: (@Sendable (SlowPoll) -> Void)? {
        get { scheduler.slowPollLock.withLock { scheduler.slowPollHandler } }
        set { scheduler.slowPollLock.withLock { scheduler.slowPollHandler = newValue } }
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
        #if os(Linux) || canImport(Darwin) || os(Windows)
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
        precondition(installedGlobal == nil,
                     "Runtime.installGlobal called twice, or in a shard, whose runtime is the global executor")
        #if os(Linux)
        let rt = Runtime(scheduler: Scheduler(workers: workers ?? Int(cv_cpu_count()), name: name, pin: false,
                                              global: true))
        #else
        let rt = Runtime(workers: workers, name: name)
        #endif
        rt.scheduler.becomeGlobal()
        return rt
    }
}

/// Carries a `~Copyable` value into a task: taken exactly once, by the task.
final class Handoff<Value: ~Copyable>: @unchecked Sendable {
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
