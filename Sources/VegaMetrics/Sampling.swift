import Vega

extension Runtime {
    /// The runtime's activity every `interval`: each element is a snapshot
    /// with counters turned into what happened since the one before
    /// (`RuntimeMetrics.since(_:)`). For a dashboard, a log line, or
    /// watching utilization and slow polls (tokio-metrics'
    /// `RuntimeMonitor`).
    ///
    /// ```swift
    /// for await m in rt.metricsSamples(every: .seconds(10)) {
    ///     log("busy \(Int(m.utilization * 100))%, \(m.polls) polls, \(m.slowPolls) slow")
    /// }
    /// ```
    ///
    /// The sampling task ends when the iteration does.
    public func metricsSamples(every interval: Duration) -> AsyncStream<RuntimeMetrics> {
        AsyncStream { continuation in
            let task = Task { [self] in
                var previous = metrics
                while !Task.isCancelled {
                    do {
                        try await Runtime.sleep(for: interval)
                    } catch {
                        break
                    }
                    let now = metrics
                    if case .terminated = continuation.yield(now.since(previous)) { break }
                    previous = now
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}
