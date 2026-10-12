import CVega
import Synchronization
@_spi(ExperimentalCustomExecutors) @_spi(ExperimentalScheduling) import _Concurrency

/// The work-stealing executor. Internal: a public type may not conform to the
/// SPI `SchedulingExecutor`, and users reach Vega through `Runtime`.
final class Scheduler: TaskExecutor, SchedulingExecutor, @unchecked Sendable {
    /// Strong references, for cold paths (metrics, teardown).
    let workers: [Worker]
    let workerCount: Int
    /// Hot-path views of the workers, ARC-free: queues to steal from, parkers to wake.
    let queues: UnsafeMutablePointer<Unmanaged<LocalQueue>>
    let parkers: UnsafeMutablePointer<OpaquePointer>
    let inject = InjectQueue()
    let idle: Idle
    let timers = TimerQueue()
    let isShutdown = Atomic<Bool>(false)
    /// Index of the parked worker sleeping on the next timer deadline, or -1.
    let timerOwner = Atomic<Int>(-1)

    init(workers count: Int, name: String, pin: Bool) {
        precondition(count >= 1, "a runtime needs at least one worker")
        idle = Idle(workers: count)
        workerCount = count
        workers = (0..<count).map(Worker.init(index:))
        queues = .allocate(capacity: count)
        parkers = .allocate(capacity: count)
        for (i, w) in workers.enumerated() {
            (queues + i).initialize(to: .passUnretained(w.queue))
            (parkers + i).initialize(to: w.parker)
        }
        let me = Unmanaged.passUnretained(self).toOpaque()
        for w in workers {
            w.scheduler = self
            w.owner = me
        }

        let cpus = Int(cv_cpu_count())
        for w in workers {
            _ = Unmanaged.passRetained(self) // released by the thread when it exits
            let arg = Unmanaged.passRetained(w).toOpaque()
            let rc = cv_thread_spawn({ raw in
                Unmanaged<Worker>.fromOpaque(raw!).takeRetainedValue().run()
            }, arg, "\(name)-\(w.index)", pin ? Int32(w.index % cpus) : -1)
            precondition(rc == 0, "vega: cannot start worker thread (errno \(rc))")
        }
    }

    // MARK: Executor

    deinit {
        queues.deallocate()
        parkers.deallocate()
    }

    func enqueue(_ job: consuming ExecutorJob) {
        let job = UnownedJob(job)
        if let w = Worker.current,
           w._withUnsafeGuaranteedRef({ $0.owner == Unmanaged.passUnretained(self).toOpaque() }) {
            w._withUnsafeGuaranteedRef { $0.schedule(job, self) }
        } else {
            foreignEnqueues.add(1, ordering: .relaxed)
            Scheduler.foreignEnqueueHook?()
            inject.push(job)
            notifyParked()
        }
    }

    /// Jobs enqueued from threads that aren't this runtime's workers.
    let foreignEnqueues = Atomic<UInt64>(0)
    /// Diagnostics only: called on every foreign enqueue.
    nonisolated(unsafe) static var foreignEnqueueHook: (() -> Void)?

    func enqueue<C: Clock>(_ job: consuming ExecutorJob, after delay: C.Duration,
                           tolerance: C.Duration?, clock: C) {
        addTimer(.job(UnownedJob(job)), in: Self.nanoseconds(delay))
    }

    func enqueue<C: Clock>(_ job: consuming ExecutorJob, at instant: C.Instant,
                           tolerance: C.Duration?, clock: C) {
        addTimer(.job(UnownedJob(job)), in: Self.nanoseconds(clock.now.duration(to: instant)))
    }

    @inline(__always) static func nanoseconds<D>(_ d: D) -> Int64 {
        guard let d = d as? Duration else { return 0 }
        let (s, atto) = d.components
        if s < 0 { return 0 }
        let (ns, overflow) = s.multipliedReportingOverflow(by: 1_000_000_000)
        return overflow ? .max : ns &+ atto / 1_000_000_000
    }

    /// Timed enqueues received (Task.sleep etc.), for tests and metrics.
    let timedEnqueues = Atomic<UInt64>(0)

    func addTimer(_ action: TimerAction, in ns: Int64) {
        timedEnqueues.add(1, ordering: .relaxed)
        if ns <= 0 {
            if let w = Worker.current {
                w._withUnsafeGuaranteedRef { fire(action, on: $0) }
            } else {
                fire(action, on: nil)
            }
            return
        }
        let now = cv_now_ns()
        let deadline = UInt64(ns) > UInt64.max - now ? UInt64.max - 1 : now + UInt64(ns)
        guard timers.add(action, deadline: deadline) else { return }
        // A new earliest deadline: the timer owner must re-arm its sleep.
        // seq_cst pairs with the owner's claim-then-read in Worker.park: one of
        // the two sides is guaranteed to see the other (store-load ordering).
        let owner = timerOwner.load(ordering: .sequentiallyConsistent)
        if owner >= 0 {
            cv_unpark(parkers[owner])
        } else {
            notifyParked()
        }
    }

    // MARK: worker support

    func notifyParked() {
        if let i = idle.workerToNotify() { cv_unpark(parkers[i]) }
    }

    func hasPendingWork() -> Bool {
        if !inject.isEmpty { return true }
        for i in 0..<workerCount where !queues[i]._withUnsafeGuaranteedRef({ $0.isEmpty }) { return true }
        return false
    }

    /// Run due timers on `worker`'s thread: jobs go onto its queue, sleepers
    /// are resumed (which schedules them on this worker). Returns how many.
    func fireDueTimers(on worker: Worker) -> Int {
        let now = cv_now_ns()
        var fired = 0
        while let action = timers.popDue(now: now) {
            fire(action, on: worker)
            fired += 1
        }
        if fired > 1 { notifyParked() }
        return fired
    }

    private func fire(_ action: TimerAction, on worker: Worker?) {
        switch action {
        case .waiter(let w):
            w.takeRetainedValue().fire() // drops the retain the heap held
        case .job(let job):
            if let worker, worker.owner == Unmanaged.passUnretained(self).toOpaque() {
                worker.pushLocal(job, self)
            } else {
                inject.push(job)
                notifyParked()
            }
        }
    }

    func shutdown() {
        isShutdown.store(true, ordering: .sequentiallyConsistent)
        for i in 0..<workerCount { cv_unpark(parkers[i]) }
    }
}

// MARK: - global install

nonisolated(unsafe) var installedGlobal: Scheduler?

struct VegaExecutorFactory: ExecutorFactory {
    static var mainExecutor: any MainExecutor { PlatformExecutorFactory.mainExecutor }
    static var defaultExecutor: any TaskExecutor { installedGlobal! }
}
