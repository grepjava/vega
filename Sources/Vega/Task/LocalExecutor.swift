import Synchronization

/// Work bound to one worker thread of a runtime, as Tokio's `LocalSet`: what
/// runs isolated to it runs only on that worker, one job at a time, and is
/// never stolen.
///
/// Swift's isolation does what `!Send` does in Rust: state that isn't
/// `Sendable` can be shared by every task isolated to the executor.
///
/// ```swift
/// let local = LocalExecutor(runtime: rt)
/// local.spawn { local in await serveAll(local) }
///
/// func serveAll(_ local: isolated LocalExecutor) async {
///     let cache = Cache()                   // not Sendable
///     for conn in conns {
///         local.spawnLocal { await serve(conn, cache) }
///     }
/// }
/// ```
///
/// An actor can run on it too, by returning its executor:
///
/// ```swift
/// actor Session {
///     let local: LocalExecutor
///     nonisolated var unownedExecutor: UnownedSerialExecutor { local.unownedExecutor }
/// }
/// ```
///
/// Also for thread-affine code (a C library that must be called from the
/// thread that set it up), and for keeping a group of tasks on one core's
/// caches and, with io_uring, its ring.
public actor LocalExecutor {
    private let executor: PinnedExecutor
    /// The runtime it runs on.
    public nonisolated let runtime: Runtime
    /// The worker it runs on.
    public nonisolated var worker: Int { executor.worker.index }

    private static let nextWorker = Atomic<Int>(0)

    /// - Parameter worker: the index of the worker to run on; by default
    ///   the runtime's workers in turn.
    public init(runtime: Runtime, worker: Int? = nil) {
        let workers = runtime.scheduler.workers
        let index = worker ?? Self.nextWorker.add(1, ordering: .relaxed).oldValue % workers.count
        precondition(workers.indices.contains(index), "LocalExecutor: no worker \(index)")
        self.runtime = runtime
        executor = PinnedExecutor(workers[index])
    }

    public nonisolated var unownedExecutor: UnownedSerialExecutor {
        executor.asUnownedSerialExecutor()
    }

    /// Start a task isolated to the executor, from anywhere. State that
    /// isn't `Sendable` is made inside it, and shared with `spawnLocal`.
    @discardableResult
    public nonisolated func spawn<Success: Sendable>(
        priority: TaskPriority? = nil,
        _ operation: @Sendable @escaping (isolated LocalExecutor) async -> Success
    ) -> Task<Success, Never> {
        Task(executorPreference: runtime.executor, priority: priority) {
            await self.run(operation)
        }
    }

    /// Start a task isolated to the executor from code already isolated to
    /// it: `operation` may capture state that isn't `Sendable`, and share it
    /// with the task running now and with others started this way.
    @discardableResult
    public func spawnLocal<Success: Sendable>(
        priority: TaskPriority? = nil,
        _ operation: @escaping () async -> Success
    ) -> Task<Success, Never> {
        Task(priority: priority) {
            _ = self // isolated to it, as this method is
            return await operation()
        }
    }

    private func run<Success: Sendable>(
        _ operation: @Sendable (isolated LocalExecutor) async -> Success
    ) async -> Success {
        await operation(self)
    }
}

/// The serial executor under a `LocalExecutor`: its jobs go to one worker's
/// pinned queue, and run there isolated to it.
final class PinnedExecutor: SerialExecutor, @unchecked Sendable {
    let worker: Worker

    init(_ worker: Worker) {
        self.worker = worker
    }

    func enqueue(_ job: consuming ExecutorJob) {
        worker.pushPinned(UnownedJob(job), isolatedTo: asUnownedSerialExecutor())
    }

    func asUnownedSerialExecutor() -> UnownedSerialExecutor {
        UnownedSerialExecutor(ordinary: self)
    }
}
