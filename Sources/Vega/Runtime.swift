import CVega
import Synchronization
@_spi(ExperimentalCustomExecutors) import _Concurrency

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
    public init(workers: Int? = nil, name: String = "vega", pinThreads: Bool = false) {
        scheduler = Scheduler(workers: workers ?? Int(cv_cpu_count()), name: name, pin: pinThreads)
    }

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

    /// Run `operation` on the runtime and block the calling thread until it
    /// finishes. Must not be called from a worker thread of any Vega runtime.
    public func block<T: Sendable, E: Error>(
        _ operation: sending @escaping () async throws(E) -> T
    ) throws(E) -> T {
        precondition(Worker.current == nil, "Runtime.block called on a Vega worker thread")
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

    /// Stop the workers. Jobs still queued are dropped, so shut down only
    /// once the tasks you care about have finished.
    public func shutdown() {
        scheduler.shutdown()
    }

    /// Suspend the calling task for `duration`, on Vega's own timers.
    ///
    /// Prefer this to `Task.sleep` when the runtime is not the global
    /// executor: `Task.sleep` wakes through a helper task that Swift runs on
    /// the *global* executor, so a busy global pool delays it. This parks the
    /// caller's continuation directly and resumes it on the firing worker.
    /// Off a Vega worker it falls back to `Task.sleep`.
    public static func sleep(for duration: Duration) async throws {
        guard let scheduler = Worker.currentScheduler else {
            try await Task.sleep(for: duration)
            return
        }
        try Task.checkCancellation()
        let waiter = SleepWaiter()
        try await withTaskCancellationHandler {
            try await withUnsafeThrowingContinuation { (c: UnsafeContinuation<Void, any Error>) in
                if waiter.arm(c) {
                    scheduler.addTimer(.waiter(.passRetained(waiter)), in: Scheduler.nanoseconds(duration))
                } else {
                    c.resume(throwing: CancellationError())
                }
            }
        } onCancel: {
            waiter.cancel()
        }
    }

    /// The index of the Vega worker running the caller, or nil off-runtime.
    public static var currentWorker: Int? { Worker.current?._withUnsafeGuaranteedRef { $0.index } }

    /// Per-worker counters.
    public var metrics: [(jobs: UInt64, steals: UInt64)] {
        scheduler.workers.map { ($0.jobsRun.load(ordering: .relaxed), $0.steals.load(ordering: .relaxed)) }
    }

    /// Make a new runtime the global executor, so every `Task {}`,
    /// `Task.detached` and `Task.sleep` in the process runs on Vega.
    ///
    /// Must be called before the first task is created (first thing in a
    /// synchronous `main`). Uses Swift's experimental custom-executor SPI.
    public static func installGlobal(workers: Int? = nil, name: String = "vega") -> Runtime {
        precondition(installedGlobal == nil, "Runtime.installGlobal called twice")
        let rt = Runtime(workers: workers, name: name)
        installedGlobal = rt.scheduler
        _createExecutors(factory: VegaExecutorFactory.self)
        rt.scheduler.installEnqueueGlobalHook()
        return rt
    }
}

/// Hands a result from a task to a blocked plain thread.
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
