/// A runtime's counters at one moment (`Runtime.metrics`): Tokio's
/// `RuntimeMetrics`. Counters run from the runtime's start; `since(_:)`
/// turns two snapshots into the activity between them.
public struct RuntimeMetrics: Sendable, Equatable {
    /// One worker thread's counters.
    public struct Worker: Sendable, Equatable {
        /// Jobs run: each is one poll of a task, to its next suspension.
        public var polls: UInt64
        /// Successful steals from other workers (each takes up to half a
        /// queue).
        public var steals: UInt64
        /// Times the worker ran out of work and parked.
        public var parks: UInt64
        /// Times its local queue filled and moved half to the inject queue.
        public var overflows: UInt64
        /// Tasks made to yield because their cooperative budget ran out.
        public var forcedYields: UInt64
        /// Jobs in its local queue now.
        public var localQueueDepth: Int
        /// Time spent out of park: running jobs, polling I/O, stealing.
        public var busyTime: Duration
        /// With `Runtime.measurePollTimes`: jobs by run time, bucket b
        /// counting those under `RuntimeMetrics.pollTimeBucketBounds[b]`
        /// (and at least the bound before); the last bucket is open. Empty
        /// if timing was never on.
        public var pollTimeHistogram: [UInt64]
        /// With `measurePollTimes`: jobs at or over `Runtime.slowPollThreshold`.
        public var slowPolls: UInt64
        /// With `measurePollTimes`: the longest job.
        public var longestPoll: Duration
        /// With `measurePollTimes`: the time all timed jobs took.
        public var totalPollTime: Duration

        /// With `measurePollTimes`: the mean time a job took.
        public var meanPollTime: Duration {
            let timed = pollTimeHistogram.reduce(0, &+)
            return timed == 0 ? .zero : totalPollTime / Int(timed)
        }

        public init(polls: UInt64 = 0, steals: UInt64 = 0, parks: UInt64 = 0, overflows: UInt64 = 0,
                    forcedYields: UInt64 = 0, localQueueDepth: Int = 0, busyTime: Duration = .zero,
                    pollTimeHistogram: [UInt64] = [], slowPolls: UInt64 = 0, longestPoll: Duration = .zero,
                    totalPollTime: Duration = .zero) {
            self.polls = polls
            self.steals = steals
            self.parks = parks
            self.overflows = overflows
            self.forcedYields = forcedYields
            self.localQueueDepth = localQueueDepth
            self.busyTime = busyTime
            self.pollTimeHistogram = pollTimeHistogram
            self.slowPolls = slowPolls
            self.longestPoll = longestPoll
            self.totalPollTime = totalPollTime
        }
    }

    /// Since the runtime started (or, after `since(_:)`, between the two).
    public var elapsed: Duration
    public var workers: [Worker]
    /// Jobs in the shared inject queue now: from outside the runtime, and
    /// local queues' overflow.
    public var injectQueueDepth: Int
    /// Blocking-pool threads alive now, and how many of them are idle.
    public var blockingThreads: Int
    public var idleBlockingThreads: Int
    /// `Runtime.blocking` jobs waiting for a thread.
    public var blockingQueueDepth: Int
    /// Timed enqueues (sleeps, timeouts) and enqueues from threads outside
    /// the runtime.
    public var timedEnqueues: UInt64
    public var foreignEnqueues: UInt64
    public var io: IOMetrics

    public init(elapsed: Duration = .zero, workers: [Worker] = [], injectQueueDepth: Int = 0,
                blockingThreads: Int = 0, idleBlockingThreads: Int = 0, blockingQueueDepth: Int = 0,
                timedEnqueues: UInt64 = 0, foreignEnqueues: UInt64 = 0, io: IOMetrics = IOMetrics()) {
        self.elapsed = elapsed
        self.workers = workers
        self.injectQueueDepth = injectQueueDepth
        self.blockingThreads = blockingThreads
        self.idleBlockingThreads = idleBlockingThreads
        self.blockingQueueDepth = blockingQueueDepth
        self.timedEnqueues = timedEnqueues
        self.foreignEnqueues = foreignEnqueues
        self.io = io
    }

    /// The histogram buckets' exclusive upper bounds: 1 µs, then doubling
    /// to about 4.2 s; the last bucket (not listed) has none.
    public static let pollTimeBucketBounds: [Duration] =
        (0..<23).map { .microseconds(1 << $0) }

    // MARK: - Totals

    public var polls: UInt64 { workers.reduce(0) { $0 &+ $1.polls } }
    public var steals: UInt64 { workers.reduce(0) { $0 &+ $1.steals } }
    public var parks: UInt64 { workers.reduce(0) { $0 &+ $1.parks } }
    public var forcedYields: UInt64 { workers.reduce(0) { $0 &+ $1.forcedYields } }
    public var slowPolls: UInt64 { workers.reduce(0) { $0 &+ $1.slowPolls } }
    public var busyTime: Duration { workers.reduce(.zero) { $0 + $1.busyTime } }

    /// Busy time over the time available (`elapsed` × workers), 0 to 1.
    public var utilization: Double {
        let available = elapsed / .nanoseconds(1) * Double(max(workers.count, 1))
        guard available > 0 else { return 0 }
        return min(busyTime / .nanoseconds(1) / available, 1)
    }

    /// The activity between `earlier` and this snapshot: counters become
    /// differences, gauges (queue depths, thread counts) stay as they are
    /// now, and the longest poll stays the longest so far.
    public func since(_ earlier: RuntimeMetrics) -> RuntimeMetrics {
        var d = self
        d.elapsed = elapsed - earlier.elapsed
        for i in d.workers.indices where i < earlier.workers.count {
            let a = earlier.workers[i]
            d.workers[i].polls &-= a.polls
            d.workers[i].steals &-= a.steals
            d.workers[i].parks &-= a.parks
            d.workers[i].overflows &-= a.overflows
            d.workers[i].forcedYields &-= a.forcedYields
            d.workers[i].busyTime -= a.busyTime
            d.workers[i].slowPolls &-= a.slowPolls
            d.workers[i].totalPollTime -= a.totalPollTime
            if a.pollTimeHistogram.count == d.workers[i].pollTimeHistogram.count {
                for b in d.workers[i].pollTimeHistogram.indices {
                    d.workers[i].pollTimeHistogram[b] &-= a.pollTimeHistogram[b]
                }
            }
        }
        d.timedEnqueues &-= earlier.timedEnqueues
        d.foreignEnqueues &-= earlier.foreignEnqueues
        d.io.parkedPolls &-= earlier.io.parkedPolls
        d.io.busyPolls &-= earlier.io.busyPolls
        d.io.events &-= earlier.io.events
        d.io.wakes &-= earlier.io.wakes
        d.io.fullBatches &-= earlier.io.fullBatches
        return d
    }
}
