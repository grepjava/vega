import CVega
import Synchronization
@_spi(ExperimentalCustomExecutors) @_spi(ExperimentalScheduling) import _Concurrency

/// The work-stealing executor. Internal: a public type may not conform to the
/// SPI `SchedulingExecutor`, and users reach Vega through `Runtime`.
final class Scheduler: TaskExecutor, SchedulingExecutor, @unchecked Sendable {
    /// Swift retains the executor all the time (Task.yield reads
    /// Task.currentExecutor, spawns store the preference, global enqueues
    /// fetch the default executor), from every worker: the refcount in the
    /// object header is a contended line. Keep the read-mostly fields that
    /// workers touch on every loop off it.
    private let headerPad = Pad112()

    /// Strong references, for cold paths (metrics, teardown).
    let workers: [Worker]
    let workerCount: Int
    /// Hot-path views of the workers, ARC-free: queues to steal from, parkers to wake.
    let queues: UnsafeMutablePointer<Unmanaged<LocalQueue>>
    let parkers: UnsafeMutablePointer<OpaquePointer>
    let inject = InjectQueue()
    let idle: Idle
    let timers: TimerWheel
    /// Threads for blocking work (`Runtime.blocking`).
    let blocking: BlockingPool
    #if os(Linux)
    /// Sockets; the timer owner blocks in it while parked. nil if it can't be created.
    let driver: IODriver?
    #endif
    let isShutdown = Atomic<Bool>(false)

    /// Written fields below, away from the read-mostly ones above.
    private let writePad = Pad128()
    /// Index of the parked worker sleeping on the next timer deadline, or -1.
    let timerOwner = Atomic<Int>(-1)
    /// Jobs enqueued from threads that aren't this runtime's workers.
    let foreignEnqueues = Atomic<UInt64>(0)
    /// Timed enqueues received (Task.sleep etc.), for tests and metrics.
    let timedEnqueues = Atomic<UInt64>(0)

    init(workers count: Int, name: String, pin: Bool,
         blockingThreads: Int = 512, blockingKeepAlive: Duration = .seconds(10)) {
        precondition(count >= 1, "a runtime needs at least one worker")
        idle = Idle(workers: count)
        workerCount = count
        timers = TimerWheel(shards: count, origin: cv_now_ns())
        blocking = BlockingPool(maxThreads: blockingThreads, keepAlive: blockingKeepAlive, name: name)
        workers = (0..<count).map(Worker.init(index:))
        queues = .allocate(capacity: count)
        parkers = .allocate(capacity: count)
        #if os(Linux)
        driver = IODriver.make()
        #endif
        for (i, w) in workers.enumerated() {
            (queues + i).initialize(to: .passUnretained(w.queue))
            (parkers + i).initialize(to: w.parker)
            #if os(Linux)
            if let driver { cv_parker_attach_driver(w.parker, driver.raw) }
            #endif
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
        #if os(Linux)
        driver?.destroy()
        #endif
    }

    /// Busy worker: pick up I/O readiness without blocking.
    @inline(__always) func pollIO(on worker: Worker) -> Int {
        #if os(Linux)
        if let driver { return driver.poll(on: worker) }
        #endif
        return 0
    }

    func enqueue(_ job: consuming ExecutorJob) {
        enqueueUnowned(UnownedJob(job))
    }

    @inline(__always) func enqueueUnowned(_ job: UnownedJob) {
        #if VEGA_JOB_AUDIT
        JobAudit.enqueued(job, "enqueue")
        #endif
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

    func addTimer(_ action: TimerAction, in ns: Int64) {
        let now = cv_now_ns()
        let deadline = ns <= 0 ? now : UInt64(ns) > UInt64.max - now ? UInt64.max - 1 : now + UInt64(ns)
        addTimer(action, deadline: deadline, now: now, shard: currentShard)
    }

    /// The timer shard for a timer added on this thread: the worker's own,
    /// or shard 0 from outside.
    @inline(__always) var currentShard: Int {
        if let w = Worker.current {
            return w._withUnsafeGuaranteedRef {
                $0.owner == Unmanaged.passUnretained(self).toOpaque() ? $0.index : 0
            }
        }
        return 0
    }

    /// `deadline` and `now` are `cv_now_ns()` times. Returns the linked
    /// timer, or nil if it fired at once (or was dropped).
    @discardableResult
    func addTimer(_ action: TimerAction, deadline: UInt64, now: UInt64, shard: Int) -> TimerHandle? {
        timedEnqueues.add(1, ordering: .relaxed)
        let added: TimerWheel.Added = deadline <= now ? .due : timers.add(action, deadline: deadline, now: now, shard: shard)
        switch added {
        case .due:
            if let w = Worker.current {
                w._withUnsafeGuaranteedRef { fire(action, on: $0) }
            } else {
                fire(action, on: nil)
            }
            return nil
        case .dropped:
            if case .waiter(let u) = action { u.release() }
            return nil
        case .inserted(let earliest, let handle):
            // A new earliest deadline: the timer owner must re-arm its sleep.
            // seq_cst pairs with the owner's claim-then-read in Worker.park:
            // one of the two sides is guaranteed to see the other.
            guard earliest, timers.isEarliest(shard) else { return handle }
            let owner = timerOwner.load(ordering: .sequentiallyConsistent)
            if owner >= 0 {
                cv_unpark(parkers[owner])
            } else {
                notifyParked()
            }
            return handle
        }
    }

    /// A cancelled `Runtime.sleep`: unlink its timer now rather than at the
    /// deadline, and drop the retain the wheel held.
    func removeSleep(_ waiter: SleepWaiter) {
        if timers.remove(waiter) { Unmanaged.passUnretained(waiter).release() }
    }

    /// A `Runtime.timeout` whose operation finished: unlink the timer that
    /// would cancel `task`. True if it hadn't fired; the retain on `task`
    /// the wheel held is then dropped here.
    func removeTimeout(_ handle: TimerHandle, task: UnsafeRawPointer) -> Bool {
        guard timers.remove(handle) else { return false }
        Unmanaged<AnyObject>.fromOpaque(task).release()
        return true
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
        worker.inOrder {
            for i in 0..<timers.shardCount {
                fired += timers.fireDue(shard: i, now: now) { fire($0, on: worker) }
            }
        }
        if fired > 1 { notifyParked() }
        return fired
    }

    private func fire(_ action: TimerAction, on worker: Worker?) {
        switch action {
        case .waiter(let w):
            w.takeRetainedValue().fire() // drops the retain the wheel held
        case .cancel(let task):
            cv_task_cancel(UnsafeMutableRawPointer(mutating: task))
            Unmanaged<AnyObject>.fromOpaque(task).release()
        case .job(let job):
            #if VEGA_JOB_AUDIT
            JobAudit.enqueued(job, "timer")
            #endif
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
        blocking.shutdown()
    }
}

// MARK: - global install

nonisolated(unsafe) var installedGlobal: Scheduler?

extension Scheduler {
    /// Take global enqueues straight from the runtime's hook: Swift's own
    /// route copies `Task.defaultExecutor` (a retain and release of this
    /// object, from every worker) and calls through an existential.
    func installEnqueueGlobalHook() {
        _ = cv_install_enqueue_global_hook({ job, ctx in
            let job = unsafeBitCast(job, to: UnownedJob.self)
            Unmanaged<Scheduler>.fromOpaque(ctx!)._withUnsafeGuaranteedRef { $0.enqueueUnowned(job) }
        }, Unmanaged.passUnretained(self).toOpaque())
    }
}

struct VegaExecutorFactory: ExecutorFactory {
    static var mainExecutor: any MainExecutor { PlatformExecutorFactory.mainExecutor }
    static var defaultExecutor: any TaskExecutor { installedGlobal! }
}
