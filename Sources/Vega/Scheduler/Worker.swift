import CVega
import Synchronization
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
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
        #if canImport(Darwin)
        // Apple machines usually share cores with whatever drives them, where
        // a spin costs battery and the client's CPU (M1: docs/BENCHMARKS.md).
        return 0
        #else
        return 50_000
        #endif
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
    #if os(Linux)
    /// This worker's io_uring when the runtime uses the uring driver.
    /// Created with the runtime, enabled in `run` (its single issuer is this
    /// thread), freed by the scheduler.
    var ring: OpaquePointer? = nil
    #endif

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
    /// While set, jobs scheduled here go to the inject queue: a busy worker's
    /// I/O poll, so its batch doesn't push older queued jobs out of turn.
    private var toInject = false
    /// The jobs scheduled while `toInject`, pushed in one locked batch.
    private let injectBuffer = UnsafeMutablePointer<UnownedJob>.allocate(capacity: Worker.injectBufferCapacity)
    private var injectCount = 0
    /// Two per I/O event (read and write), for a full driver batch.
    static let injectBufferCapacity = 2048
    /// Cooperative budget left for the running task (`Runtime.consumeBudget`).
    var budget: Int32 = 0
    /// Tokio's per-poll budget.
    static let budgetPerPoll: Int32 = 128

    /// Jobs this worker has run, stolen. Only this worker writes them (plain
    /// load + store, no locked add); metrics read them racily.
    let jobsRun = Atomic<UInt64>(0)
    /// Current-thread runtimes: set when `drive`'s caller has what it waited
    /// for, so the loop returns (from `park` too) instead of sleeping on.
    let driveDone = Atomic<Bool>(false)
    let steals = Atomic<UInt64>(0)
    /// Times this worker parked, and its time out of park (busy), in ns.
    /// `activeSince` is when it last unparked (0 while parked).
    let parks = Atomic<UInt64>(0)
    let busyNanos = Atomic<UInt64>(0)
    let activeSince = Atomic<UInt64>(0)
    /// Tasks made to yield by an exhausted budget (`Runtime.consumeBudget`).
    let forcedYields = Atomic<UInt64>(0)
    /// With poll timing on: jobs by duration (`Worker.pollBucket`), those
    /// over the slow threshold, and the longest, in ns.
    let pollHistogram: UnsafeMutablePointer<Atomic<UInt64>>
    let slowPolls = Atomic<UInt64>(0)
    let longestPoll = Atomic<UInt64>(0)
    let pollNanos = Atomic<UInt64>(0)
    static let pollBuckets = 24

    init(index: Int) {
        self.index = index
        rng = UInt32(truncatingIfNeeded: index &* 0x9E37_79B9) | 1
        pollHistogram = .allocate(capacity: Self.pollBuckets)
        for i in 0..<Self.pollBuckets { (pollHistogram + i).initialize(to: Atomic(0)) }
    }

    deinit {
        cv_parker_free(parker)
        injectBuffer.deallocate()
        pollHistogram.deinitialize(count: Self.pollBuckets)
        pollHistogram.deallocate()
    }

    /// The histogram bucket of a poll that took `ns`: 0 under 1 µs, then
    /// one per doubling (bucket b holds [2^(b-1), 2^b) µs); the last is open.
    @inline(__always) static func pollBucket(_ ns: UInt64) -> Int {
        let micros = ns / 1000
        return min(UInt64.bitWidth - micros.leadingZeroBitCount, pollBuckets - 1)
    }

    /// Owner only: one poll took `ns`.
    @inline(never) private func recordPoll(_ ns: UInt64, _ s: Scheduler) {
        let b = pollHistogram + Self.pollBucket(ns)
        b.pointee.store(b.pointee.load(ordering: .relaxed) &+ 1, ordering: .relaxed)
        pollNanos.store(pollNanos.load(ordering: .relaxed) &+ ns, ordering: .relaxed)
        if ns > longestPoll.load(ordering: .relaxed) { longestPoll.store(ns, ordering: .relaxed) }
        if ns >= s.slowPollNanos.load(ordering: .relaxed) {
            slowPolls.store(slowPolls.load(ordering: .relaxed) &+ 1, ordering: .relaxed)
        }
    }

    /// Park, counting it and the busy stretch it ends. On the coarse clock:
    /// busy time is read over seconds, and a precise clock read on each
    /// side of every park showed in ping-pong.
    @inline(__always) private func parkCounted(_ s: Scheduler) {
        let start = cv_now_coarse_ns()
        let since = activeSince.load(ordering: .relaxed)
        if since != 0 { busyNanos.store(busyNanos.load(ordering: .relaxed) &+ (start &- since), ordering: .relaxed) }
        activeSince.store(0, ordering: .relaxed)
        parks.store(parks.load(ordering: .relaxed) &+ 1, ordering: .relaxed)
        park(s)
        activeSince.store(cv_now_coarse_ns(), ordering: .relaxed)
    }

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
        if toInject {
            if injectCount == Self.injectBufferCapacity { flushInject(s) }
            (injectBuffer + injectCount).initialize(to: job)
            injectCount += 1
        } else if toBack || Self.identity(job) == running {
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

    /// Run `body` (which schedules jobs here) with jobs going to the inject
    /// queue, then wake a sleeper for them.
    ///
    /// For an I/O batch picked up by a busy worker: on the local queue it
    /// would overflow, and overflow sends the *oldest* half to the inject
    /// queue, where it is served once every 31 ticks while newer wakes keep
    /// refilling the local queues. Under load (1,024 echo connections) that
    /// starved some connections for tens of milliseconds. Through the inject
    /// queue every woken task waits in one FIFO, which workers drain in fair
    /// shares as soon as their local queues empty.
    @inline(__always) func viaInject<R>(_ s: Scheduler, _ body: () -> R) -> R {
        toInject = true
        defer {
            toInject = false
            flushInject(s)
            s.notifyParked()
        }
        return body()
    }

    private func flushInject(_ s: Scheduler) {
        guard injectCount > 0 else { return }
        let buf = injectBuffer
        s.inject.pushBatch(UInt32(injectCount - 1)) { buf[Int($0)] }
        injectCount = 0
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
        #if os(Linux)
        if let ring {
            let e = cv_uring_enable(ring)
            precondition(e == 0, "vega: cannot enable io_uring (errno \(e))")
        }
        #endif
        activeSince.store(cv_now_coarse_ns(), ordering: .relaxed)
        while !s.isShutdown.load(ordering: .relaxed) {
            if let job = nextJob(s) ?? ringJob() ?? steal(s) {
                runJob(job, s, executor)
            } else {
                parkCounted(s)
            }
        }
        #if os(Linux)
        if let ring { cv_uring_close(ring) }
        #endif
        cv_current_set(nil)
        Unmanaged.passUnretained(s).release() // the retain Scheduler.init took for this thread
    }

    /// A current-thread runtime's loop, run by the thread in `Runtime.block`
    /// until `driveDone` is set (then cleared again for the next call).
    func drive() {
        cv_current_set(Unmanaged.passUnretained(self).toOpaque())
        let s = scheduler.unsafelyUnwrapped
        let executor = s.asUnownedTaskExecutor()
        activeSince.store(cv_now_coarse_ns(), ordering: .relaxed)
        while !s.isShutdown.load(ordering: .relaxed) && !driveDone.load(ordering: .acquiring) {
            if let job = nextJob(s) ?? steal(s) {
                runJob(job, s, executor)
            } else {
                parkCounted(s)
            }
        }
        // Out of `block`: not busy, as far as metrics go.
        let since = activeSince.load(ordering: .relaxed)
        busyNanos.store(busyNanos.load(ordering: .relaxed) &+ (cv_now_coarse_ns() &- since), ordering: .relaxed)
        activeSince.store(0, ordering: .relaxed)
        driveDone.store(false, ordering: .relaxed)
        cv_current_set(nil)
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
        if s.pollTiming.load(ordering: .relaxed) {
            let start = cv_now_ns()
            job.runSynchronously(on: executor)
            recordPoll(cv_now_ns() &- start, s)
        } else {
            job.runSynchronously(on: executor)
        }
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
        if tick % Self.timerInterval == 0 {
            _ = s.fireDueTimers(on: self)
            _ = s.pollIO(on: self)
        }

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

        // A fair share, not one job: busy workers' I/O polls feed the inject
        // queue, and one job per interval would let it grow without bound.
        if tick % Self.injectInterval == 0, let job = s.inject.popBatch(into: queue, workers: s.workerCount) {
            audit("inject.popBatch(interval)")
            return job
        }
        if let job = queue.pop() { audit("local.pop"); return job }
        audit("inject.popBatch")
        return s.inject.popBatch(into: queue, workers: s.workerCount)
    }

    /// Out of local work: submit what our tasks queued on the ring and
    /// collect its completions before looking at other workers. The tasks
    /// they resume are ours anyway (their I/O ran on our ring).
    @inline(__always) private func ringJob() -> UnownedJob? {
        #if os(Linux)
        guard let ring, URing.deliver(cv_uring_poll(ring), ring, on: self, busy: false) > 0 else { return nil }
        if let job = lifo {
            lifo = nil
            return job
        }
        return queue.pop()
        #else
        return nil
        #endif
    }

    /// The uring driver's park: every worker sleeps in its own ring, since
    /// only it can reap its completions. nil without a ring.
    @inline(__always) private func parkInRing(_ timeout: Int64) -> Int? {
        #if os(Linux)
        guard let ring else { return nil }
        return URing.deliver(cv_uring_park(ring, timeout, Self.spinNanos), ring, on: self, busy: false)
        #else
        return nil
        #endif
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
        if s.clock.isPaused { nudgeTimerOwner(s) }

        // Paused time: the last round polled I/O and found nothing to do.
        var idleChecked = false
        while !s.isShutdown.load(ordering: .relaxed) {
            if lifo != nil || driveDone.load(ordering: .acquiring) {
                // Never sleep on a runnable job of our own.
                reclaim(s)
                return
            }
            // One parked worker owns the timers and the I/O driver: it sleeps
            // in the driver, only until the next deadline.
            let ownsTimers = s.timerOwner.compareExchange(expected: -1, desired: index,
                                                          ordering: .sequentiallyConsistent).exchanged
            var timeout: Int64 = -1
            if ownsTimers {
                if s.fireDueTimers(on: self) > 0 {
                    s.timerOwner.store(-1, ordering: .releasing)
                    reclaim(s)
                    return
                }
                if !s.clock.isPaused {
                    timeout = s.timers.timeout(now: s.clock.now)
                } else if s.timers.earliest() != .max, s.canAutoAdvance() {
                    // Everything is idle: first collect ready I/O (it may be
                    // what the next step needs), then jump to the next timer
                    // (Tokio's auto-advance).
                    if idleChecked {
                        s.clock.advance(to: s.timers.earliest())
                        if s.fireDueTimers(on: self) > 0 {
                            s.timerOwner.store(-1, ordering: .releasing)
                            reclaim(s)
                            return
                        }
                    }
                    timeout = 0
                }
                // Otherwise real time doesn't move paused timers: sleep
                // until MockClock.advance or the last busy worker wakes us.
            }

            var fired = 0
            if let n = parkInRing(timeout) {
                fired = n
            } else {
                #if os(Linux) || canImport(Darwin) || os(Windows)
                if ownsTimers, let driver = s.driver {
                    fired = driver.park(parker, timeout: timeout, on: self)
                } else {
                    cv_park_spin(parker, timeout, Self.spinNanos)
                }
                #else
                cv_park_spin(parker, timeout, Self.spinNanos)
                #endif
            }

            if ownsTimers {
                s.timerOwner.store(-1, ordering: .sequentiallyConsistent)
                fired += s.fireDueTimers(on: self)
            }
            if !s.idle.isParked(index) {
                // Woken by workerToNotify: it already counted us as searching.
                isSearching = true
                if ownsTimers { handOverTimers(s) }
                return
            }
            if fired > 0 || lifo != nil || !queue.isEmpty {
                reclaim(s)
                return
            }
            idleChecked = ownsTimers && timeout == 0
            // Spurious, or a timer owner whose deadline moved: go round.
        }
    }

    /// Paused time: the last worker to go idle wakes the timer owner, which
    /// may then auto-advance. (With no owner, this worker becomes it.)
    private func nudgeTimerOwner(_ s: Scheduler) {
        guard s.idle.allParked else { return }
        let owner = s.timerOwner.load(ordering: .sequentiallyConsistent)
        if owner >= 0 && owner != index { cv_unpark(s.parkers[owner]) }
    }

    /// Leaving park while timers are pending: nudge another sleeper so it wakes,
    /// finds itself still parked, and takes over the timers. Otherwise they
    /// would wait for a busy worker's every-61-ticks check.
    private func handOverTimers(_ s: Scheduler) {
        guard s.timers.earliest() != .max,
              let other = s.idle.anySleeper(except: index) else { return }
        cv_unpark(s.parkers[other])
    }

    /// We woke on our own (a timer fired) and still sit on the sleeper list.
    private func reclaim(_ s: Scheduler) {
        isSearching = !s.idle.unpark(index) // lost the race: notified, counted searching
    }
}
