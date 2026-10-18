import Metrics
import Vega
import VegaMetrics

extension Runtime {
    /// Report the runtime's activity through swift-metrics every
    /// `interval`, to whatever backend the process bootstrapped
    /// (Prometheus, StatsD, ...): counters for what happened since the last
    /// report, gauges for levels. Names start with `prefix`; `dimensions`
    /// go on every one (a runtime's name, say). Returns the reporting task,
    /// which runs on this runtime: cancel it to stop.
    ///
    /// Counters: `_polls`, `_steals`, `_parks`, `_forced_yields`,
    /// `_slow_polls`, `_io_events`. Gauges: `_utilization` (0-1 across the
    /// workers), `_workers`, `_local_queue_depth`, `_inject_queue_depth`,
    /// `_blocking_threads`, `_blocking_queue_depth`. A recorder,
    /// `_longest_poll_seconds`, gets each period's longest poll.
    @discardableResult
    public func reportMetrics(every interval: Duration = .seconds(10), prefix: String = "vega",
                              dimensions: [(String, String)] = []) -> Task<Void, Never> {
        let samples = metricsSamples(every: interval)
        func counter(_ name: String) -> Counter { Counter(label: "\(prefix)_\(name)", dimensions: dimensions) }
        func gauge(_ name: String) -> Gauge { Gauge(label: "\(prefix)_\(name)", dimensions: dimensions) }
        let polls = counter("polls"), steals = counter("steals"), parks = counter("parks")
        let forcedYields = counter("forced_yields"), slowPolls = counter("slow_polls"), ioEvents = counter("io_events")
        let utilization = gauge("utilization"), workers = gauge("workers")
        let localDepth = gauge("local_queue_depth"), injectDepth = gauge("inject_queue_depth")
        let blockingThreads = gauge("blocking_threads"), blockingDepth = gauge("blocking_queue_depth")
        let longestPoll = Recorder(label: "\(prefix)_longest_poll_seconds", dimensions: dimensions, aggregate: true)
        // On this runtime, not `Task {}`: the global executor's threads can
        // all be taken, and then nothing would be reported.
        return spawn {
            for await m in samples {
                polls.increment(by: Int64(clamping: m.polls))
                steals.increment(by: Int64(clamping: m.steals))
                parks.increment(by: Int64(clamping: m.parks))
                forcedYields.increment(by: Int64(clamping: m.forcedYields))
                slowPolls.increment(by: Int64(clamping: m.slowPolls))
                ioEvents.increment(by: Int64(clamping: m.io.events))
                utilization.record(m.utilization)
                workers.record(m.workers.count)
                localDepth.record(m.workers.reduce(0) { $0 + $1.localQueueDepth })
                injectDepth.record(m.injectQueueDepth)
                blockingThreads.record(m.blockingThreads)
                blockingDepth.record(m.blockingQueueDepth)
                let longest = m.workers.map(\.longestPoll).max() ?? .zero
                if longest > .zero {
                    longestPoll.record(Double(longest.components.seconds) + Double(longest.components.attoseconds) / 1e18)
                }
            }
        }
    }
}
