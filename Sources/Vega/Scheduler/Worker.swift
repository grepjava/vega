import CVega
import Synchronization
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// One scheduler thread. Everything below the `let`s is touched only by the
/// worker's own thread.
final class Worker: @unchecked Sendable {
    /// After this many jobs in a row from the LIFO slot, the slot's job goes to
    /// the back of the queue instead, so two tasks waking each other can't
    /// starve the rest (Tokio: `MAX_LIFO_POLLS_PER_TICK`).
    static let lifoLimit = 3
    /// Check the inject queue first every this many ticks, so jobs from
    /// outside are not starved by a busy local queue.
    static let injectInterval: UInt32 = 31
    /// Check timers every this many ticks while busy.
    static let timerInterval: UInt32 = 61
    /// How long a worker with nothing to do spins before sleeping in the
    /// kernel. Work that arrives meanwhile wakes it with a plain store
    /// instead of a futex syscall on both sides. `VEGA_SPIN_NS` overrides.
    static let spinNanos: Int64 = {
        if let v = getenv("VEGA_SPIN_NS"), let n = Int64(String(cString: v)) { return n }
        return 50_000
    }()

    let index: Int
    let queue = LocalQueue()
    let parker = cv_parker_new()!
    /// Back-reference, set once right after init. `unowned(unsafe)`: reading it
    /// costs no retain. The scheduler is kept alive by one retain per worker
    /// thread, taken in `Scheduler.init` and dropped when the thread exits.
    unowned(unsafe) var scheduler: Scheduler? = nil
    /// The scheduler's address, to recognise "this thread belongs to me" in
    /// `Scheduler.enqueue` without touching reference counts.
    var owner: UnsafeMutableRawPointer? = nil

    private var lifo: UnownedJob?
    private var lifoStreak = 0
    private var tick: UInt32 = 0
    private var isSearching = false
    private var rng: UInt32
    /// The job running right now, to spot `Task.yield` re-enqueuing itself.
    private var running: UnsafeRawPointer?
    /// A task that called `Runtime.yield`, to resume once its job returns.
    private var deferred: UnsafeContinuation<Void, Never>?
    /// While set, jobs scheduled here go to the back of the queue instead of
    /// the LIFO slot: a resumed yielder, or timers fired in deadline order
    /// (through the LIFO slot a batch of them would run newest first).
    private var toBack = false
    /// Cooperative budget left for the running task (`Runtime.consumeBudget`).
    var budget: Int32 = 0
    /// Tokio's per-poll budget.
    static let budgetPerPoll: Int32 = 128

    /// Jobs this worker has run, stolen. Only this worker writes them (plain
    /// load + store, no locked add); metrics read them racily.
    let jobsRun = Atomic<UInt64>(0)
    let steals = Atomic<UInt64>(0)

    init(index: Int) {
        self.index = index
        rng = UInt32(truncatingIfNeeded: index &* 0x9E37_79B9) | 1
    }

    deinit { cv_parker_free(parker) }

    /// The worker running on this thread, unretained.
    @inline(__always) static var current: Unmanaged<Worker>? {
        guard let p = cv_current_get() else { return nil }
        return Unmanaged<Worker>.fromOpaque(p)
    }

    /// The current worker's scheduler, if this is a worker thread.
    @inline(__always) static var currentScheduler: Scheduler? {
        current?._withUnsafeGuaranteedRef { $0.scheduler }
    }

    @inline(__always) static func identity(_ job: UnownedJob) -> UnsafeRawPointer {
        unsafeBitCast(job, to: UnsafeRawPointer.self)
    }

    // MARK: scheduling from this thread

    /// A job became runnable on this worker's thread.
    @inline(__always) func schedule(_ job: UnownedJob, _ s: Scheduler) {
        #if VEGA_JOB_AUDIT
        JobAudit.note(job, toBack || Self.identity(job) == running ? "->back" : (lifo == nil ? "->lifo" : "->lifo(displace)"))
        if let p = lifo { JobAudit.note(p, "displaced->queue") }
        #endif
        if toBack || Self.identity(job) == running {
            // Task.yield (or any self-reschedule): go to the back, let others run.
            queue.push(job, overflow: s.inject)
            s.notifyParked()
        } else if let previous = lifo {
            // Newest wins the slot: it is the one whose data is hot in cache.
            lifo = job
            queue.push(previous, overflow: s.inject)
            s.notifyParked()
        } else {
            lifo = job
        }
    }

    /// Push to this worker's queue from its own thread. A method rather than
    /// `worker.queue.push(...)` at the call site: here `self` is guaranteed,
    /// so loading `queue` and `s.inject` costs no retain.
    @inline(never) func pushLocal(_ job: UnownedJob, _ s: Scheduler) {
        queue.push(job, overflow: s.inject)
    }

    /// Run `body` (which schedules jobs here) with FIFO placement.
    @inline(__always) func inOrder<R>(_ body: () -> R) -> R {
        toBack = true
        defer { toBack = false }
        return body()
    }

    /// Park a yielding task's continuation until the running job returns.
    func deferYield(_ c: UnsafeContinuation<Void, Never>) {
        // One job can run several tasks (an actor draining its queue); an
        // earlier yielder in the same job is suspended by now, release it.
        if let previous = deferred { resumeToBack(previous) }
        deferred = c
    }

    /// Resume a suspended task; it is enqueued here, at the back of the queue.
    private func resumeToBack(_ c: UnsafeContinuation<Void, Never>) {
        toBack = true
        c.resume()
        toBack = false
    }

    #if VEGA_JOB_AUDIT
    private var source: StaticString = ""
    @inline(__always) private func audit(_ s: StaticString) { source = s }
    #else
    @inline(__always) private func audit(_ s: StaticString) {}
    #endif

    // MARK: the loop

    func run() {
        cv_current_set(Unmanaged.passUnretained(self).toOpaque())
        let s = scheduler.unsafelyUnwrapped
        let executor = s.asUnownedTaskExecutor()
        while !s.isShutdown.load(ordering: .relaxed) {
            if let job = nextJob(s) ?? steal(s) {
                runJob(job, s, executor)
            } else {
                park(s)
            }
        }
        cv_current_set(nil)
        Unmanaged.passUnretained(s).release() // the retain Scheduler.init took for this thread
    }

    @inline(__always) private func runJob(_ job: UnownedJob, _ s: Scheduler, _ executor: UnownedTaskExecutor) {
        if isSearching {
            isSearching = false
            if s.idle.transitionFromSearching() { s.notifyParked() }
        }
        #if VEGA_JOB_AUDIT
        JobAudit.running(job, source)
        #endif
        running = Self.identity(job)
        budget = Self.budgetPerPoll
        job.runSynchronously(on: executor)
        #if VEGA_JOB_AUDIT
        JobAudit.note(job, "done")
        #endif
        running = nil
        if let c = deferred {
            // Runtime.yield: the task has suspended now.
            deferred = nil
            resumeToBack(c)
        }
        jobsRun.store(jobsRun.load(ordering: .relaxed) &+ 1, ordering: .relaxed)
    }

    private func nextJob(_ s: Scheduler) -> UnownedJob? {
        tick &+= 1
        if tick % Self.timerInterval == 0 { _ = s.fireDueTimers(on: self) }

        if let job = lifo {
            lifo = nil
            if lifoStreak < Self.lifoLimit {
                lifoStreak += 1
                audit("lifo")
                return job
            }
            queue.push(job, overflow: s.inject)
        }
        lifoStreak = 0

        if tick % Self.injectInterval == 0, let job = s.inject.pop() { audit("inject.pop"); return job }
        if let job = queue.pop() { audit("local.pop"); return job }
        audit("inject.popBatch")
        return s.inject.popBatch(into: queue, workers: s.workerCount)
    }

    private func steal(_ s: Scheduler) -> UnownedJob? {
        if !isSearching {
            guard s.idle.transitionToSearching() else { return nil }
            isSearching = true
        }
        let n = s.workerCount
        rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5
        let start = Int(rng % UInt32(n))
        for i in 0..<n {
            let victim = (start + i) % n
            if victim == index { continue }
            if let job = s.queues[victim]._withUnsafeGuaranteedRef({ $0.steal(into: queue) }) {
                steals.store(steals.load(ordering: .relaxed) &+ 1, ordering: .relaxed)
                audit("steal")
                return job
            }
        }
        if let job = s.inject.popBatch(into: queue, workers: n) { audit("steal.popBatch"); return job }
        audit("timers")
        guard s.fireDueTimers(on: self) > 0 else { return nil }
        // A fired sleeper resumes into the LIFO slot, a fired job onto the
        // queue: take either, or we would park with work in hand.
        if let job = lifo {
            lifo = nil
            return job
        }
        return queue.pop()
    }

    private func park(_ s: Scheduler) {
        if s.idle.transitionToParked(index, searching: isSearching), s.hasPendingWork() {
            s.notifyParked() // we were the last searcher and work arrived meanwhile
        }
        isSearching = false

        while !s.isShutdown.load(ordering: .relaxed) {
            if lifo != nil {
                // Never sleep on a runnable job of our own.
                reclaim(s)
                return
            }
            // One parked worker owns the timers and sleeps only until the next deadline.
            let ownsTimers = s.timerOwner.compareExchange(expected: -1, desired: index,
                                                          ordering: .sequentiallyConsistent).exchanged
            var timeout: Int64 = -1
            if ownsTimers {
                if s.fireDueTimers(on: self) > 0 {
                    s.timerOwner.store(-1, ordering: .releasing)
                    reclaim(s)
                    return
                }
                timeout = s.timers.timeout(now: cv_now_ns())
            }

            cv_park_spin(parker, timeout, Self.spinNanos)

            var fired = 0
            if ownsTimers {
                s.timerOwner.store(-1, ordering: .sequentiallyConsistent)
                fired = s.fireDueTimers(on: self)
            }
            if !s.idle.isParked(index) {
                // Woken by workerToNotify: it already counted us as searching.
                isSearching = true
                if ownsTimers { handOverTimers(s) }
                return
            }
            if fired > 0 || lifo != nil {
                reclaim(s)
                return
            }
            // Spurious, or a timer owner whose deadline moved: go round.
        }
    }

    /// Leaving park while timers are pending: nudge another sleeper so it wakes,
    /// finds itself still parked, and takes over the timers. Otherwise they
    /// would wait for a busy worker's every-61-ticks check.
    private func handOverTimers(_ s: Scheduler) {
        guard s.timers.next.load(ordering: .acquiring) != .max,
              let other = s.idle.anySleeper(except: index) else { return }
        cv_unpark(s.parkers[other])
    }

    /// We woke on our own (a timer fired) and still sit on the sleeper list.
    private func reclaim(_ s: Scheduler) {
        isSearching = !s.idle.unpark(index) // lost the race: notified, counted searching
    }
}
