// Phase 0 spike: a deliberately simple multi-threaded executor (one locked FIFO,
// not work stealing) used only to learn which Swift 6.3 hooks reach it.
import Glibc
import Synchronization
@_spi(ExperimentalCustomExecutors) @_spi(ExperimentalScheduling) import _Concurrency

nonisolated(unsafe) private var poolThreadKey: pthread_key_t = 0
private let keyOnce: Void = { pthread_key_create(&poolThreadKey, nil); return () }()

/// Worker index + 1 of the pool thread we're on, or 0 off-pool.
public func currentPoolWorker() -> Int {
    _ = keyOnce
    return Int(bitPattern: pthread_getspecific(poolThreadKey))
}

@_spi(Vega) public final class Pool: TaskExecutor, SchedulingExecutor, @unchecked Sendable {
    private let lock = UnsafeMutablePointer<pthread_mutex_t>.allocate(capacity: 1)
    private let cond = UnsafeMutablePointer<pthread_cond_t>.allocate(capacity: 1)
    private var ready: [UnownedJob] = []
    private var head = 0
    private var timers: [(deadline: ContinuousClock.Instant, job: UnownedJob)] = []
    public let enqueues = Atomic<Int>(0)
    public let timedEnqueues = Atomic<Int>(0)

    public init(threads n: Int) {
        _ = keyOnce
        pthread_mutex_init(lock, nil)
        pthread_cond_init(cond, nil)
        ready.reserveCapacity(1 << 16)
        for i in 0..<n {
            let box = Unmanaged.passRetained(WorkerArg(pool: self, index: i + 1)).toOpaque()
            var t = pthread_t()
            pthread_create(&t, nil, { raw in
                let arg = Unmanaged<WorkerArg>.fromOpaque(raw!).takeRetainedValue()
                pthread_setspecific(poolThreadKey, UnsafeRawPointer(bitPattern: arg.index))
                arg.pool.workerLoop()
                return nil
            }, box)
            pthread_detach(t)
        }
    }

    public func enqueue(_ job: consuming ExecutorJob) {
        enqueues.add(1, ordering: .relaxed)
        let u = UnownedJob(job)
        pthread_mutex_lock(lock)
        ready.append(u)
        pthread_cond_signal(cond)
        pthread_mutex_unlock(lock)
    }

    public func enqueue<C: Clock>(_ job: consuming ExecutorJob, after delay: C.Duration,
                                  tolerance: C.Duration?, clock: C) {
        enqueue(job, at: clock.now.advanced(by: delay), tolerance: tolerance, clock: clock)
    }

    public func enqueue<C: Clock>(_ job: consuming ExecutorJob, at instant: C.Instant,
                                  tolerance: C.Duration?, clock: C) {
        timedEnqueues.add(1, ordering: .relaxed)
        let wait = (clock.now.duration(to: instant) as? Duration) ?? .zero
        let u = UnownedJob(job)
        pthread_mutex_lock(lock)
        timers.append((ContinuousClock.now.advanced(by: wait), u))
        pthread_cond_signal(cond)
        pthread_mutex_unlock(lock)
    }

    fileprivate func workerLoop() {
        let me = asUnownedTaskExecutor()
        while true {
            pthread_mutex_lock(lock)
            var job: UnownedJob? = nil
            while job == nil {
                let now = ContinuousClock.now
                if let i = timers.firstIndex(where: { $0.deadline <= now }) {
                    job = timers.remove(at: i).job
                } else if head < ready.count {
                    job = ready[head]; head += 1
                    if head == ready.count { ready.removeAll(keepingCapacity: true); head = 0 }
                } else if let next = timers.map(\.deadline).min() {
                    var ts = timespec(); clock_gettime(CLOCK_REALTIME, &ts)
                    let (s, a) = now.duration(to: next).components
                    var ns = Int(ts.tv_nsec) + Int(a / 1_000_000_000)
                    ts.tv_sec += Int(s) + ns / 1_000_000_000; ns %= 1_000_000_000; ts.tv_nsec = ns
                    pthread_cond_timedwait(cond, lock, &ts)
                } else {
                    pthread_cond_wait(cond, lock)
                }
            }
            pthread_mutex_unlock(lock)
            job!.runSynchronously(on: me)
        }
    }
}

private final class WorkerArg {
    let pool: Pool; let index: Int
    init(pool: Pool, index: Int) { self.pool = pool; self.index = index }
}

/// A trivial main executor so the factory spike can install itself; it just
/// forwards to the platform one.
@_spi(Vega) public final class ForwardingMain: MainExecutor, @unchecked Sendable {
    let base = PlatformExecutorFactory.mainExecutor
    public init() {}
    public func enqueue(_ job: consuming ExecutorJob) { base.enqueue(job) }
    public func run() throws { try base.run() }
    public func runUntil(_ condition: () -> Bool) throws { try base.runUntil(condition) }
    public func stop() { base.stop() }
    public func checkIsolated() { base.checkIsolated() }
}
