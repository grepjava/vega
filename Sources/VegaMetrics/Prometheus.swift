import Vega

/// Runtime metrics in the Prometheus text exposition format (0.0.4), for a
/// `/metrics` endpoint.
///
/// ```swift
/// let body = PrometheusText.render(rt.metrics, labels: ["runtime": "main"])
/// ```
///
/// Per-worker series carry a `worker` label. The poll-time histogram is
/// summed over the workers, and appears once `Runtime.measurePollTimes`
/// has been on.
public enum PrometheusText {
    /// The content type to serve it with.
    public static let contentType = "text/plain; version=0.0.4; charset=utf-8"

    public static func render(_ m: RuntimeMetrics, prefix: String = "vega",
                              labels: [String: String] = [:]) -> String {
        var out = Output(prefix: prefix, labels: labels)

        out.gauge("workers", "Worker threads.", Double(m.workers.count))
        out.counter("uptime_seconds", "Time since the runtime started.", seconds(m.elapsed))

        out.perWorker(m, "polls_total", .counter, "Jobs run (task polls).") { Double($0.polls) }
        out.perWorker(m, "steals_total", .counter, "Successful steals from other workers.") { Double($0.steals) }
        out.perWorker(m, "parks_total", .counter, "Times the worker parked with no work.") { Double($0.parks) }
        out.perWorker(m, "overflows_total", .counter, "Local queue overflows to the inject queue.") {
            Double($0.overflows)
        }
        out.perWorker(m, "forced_yields_total", .counter, "Tasks yielded by an exhausted budget.") {
            Double($0.forcedYields)
        }
        out.perWorker(m, "busy_seconds_total", .counter, "Time out of park.") { seconds($0.busyTime) }
        out.perWorker(m, "local_queue_depth", .gauge, "Jobs in the worker's local queue.") {
            Double($0.localQueueDepth)
        }

        let timed = m.workers.contains { !$0.pollTimeHistogram.isEmpty }
        if timed {
            out.perWorker(m, "slow_polls_total", .counter, "Polls at or over the slow-poll threshold.") {
                Double($0.slowPolls)
            }
            out.perWorker(m, "longest_poll_seconds", .gauge, "The longest poll so far.") { seconds($0.longestPoll) }
            out.histogram(m)
        }

        out.gauge("inject_queue_depth", "Jobs in the shared inject queue.", Double(m.injectQueueDepth))
        out.gauge("blocking_threads", "Blocking-pool threads alive.", Double(m.blockingThreads))
        out.gauge("blocking_idle_threads", "Blocking-pool threads idle.", Double(m.idleBlockingThreads))
        out.gauge("blocking_queue_depth", "Blocking jobs waiting for a thread.", Double(m.blockingQueueDepth))
        out.counter("timed_enqueues_total", "Sleeps and timeouts scheduled.", Double(m.timedEnqueues))
        out.counter("foreign_enqueues_total", "Jobs enqueued from outside the runtime.", Double(m.foreignEnqueues))
        out.counter("io_parked_polls_total", "I/O driver polls by a parked worker.", Double(m.io.parkedPolls))
        out.counter("io_busy_polls_total", "I/O driver polls by a busy worker.", Double(m.io.busyPolls))
        out.counter("io_events_total", "I/O events from the kernel.", Double(m.io.events))
        out.counter("io_wakes_total", "Tasks woken by I/O events.", Double(m.io.wakes))
        return out.text
    }

    private static func seconds(_ d: Duration) -> Double {
        let (s, atto) = d.components
        return Double(s) + Double(atto) / 1e18
    }

    private enum Kind: String {
        case counter, gauge, histogram
    }

    private struct Output {
        let prefix: String
        let labels: String  // rendered, without braces; "" for none
        var text = ""

        init(prefix: String, labels: [String: String]) {
            self.prefix = prefix
            self.labels = labels.sorted { $0.key < $1.key }
                .map { "\($0.key)=\"\(Output.escape($0.value))\"" }
                .joined(separator: ",")
        }

        static func escape(_ value: String) -> String {
            var s = ""
            for c in value {
                switch c {
                case "\\": s += "\\\\"
                case "\"": s += "\\\""
                case "\n": s += "\\n"
                default: s.append(c)
                }
            }
            return s
        }

        static func number(_ v: Double) -> String {
            if v == v.rounded(), abs(v) < 1e15 { return String(Int64(v)) }
            return "\(v)"
        }

        mutating func header(_ name: String, _ kind: Kind, _ help: String) {
            text += "# HELP \(prefix)_\(name) \(help)\n# TYPE \(prefix)_\(name) \(kind.rawValue)\n"
        }

        mutating func sample(_ name: String, _ extra: String, _ value: Double) {
            let all = [labels, extra].filter { !$0.isEmpty }.joined(separator: ",")
            text += "\(prefix)_\(name)\(all.isEmpty ? "" : "{\(all)}") \(Output.number(value))\n"
        }

        mutating func gauge(_ name: String, _ help: String, _ value: Double) {
            header(name, .gauge, help)
            sample(name, "", value)
        }

        mutating func counter(_ name: String, _ help: String, _ value: Double) {
            header(name, .counter, help)
            sample(name, "", value)
        }

        mutating func perWorker(_ m: RuntimeMetrics, _ name: String, _ kind: Kind, _ help: String,
                                _ value: (RuntimeMetrics.Worker) -> Double) {
            header("worker_" + name, kind, help)
            for (i, w) in m.workers.enumerated() {
                sample("worker_" + name, "worker=\"\(i)\"", value(w))
            }
        }

        /// Poll times over all workers, as a cumulative histogram.
        mutating func histogram(_ m: RuntimeMetrics) {
            let name = "poll_duration_seconds"
            header(name, .histogram, "Time each poll (job) ran.")
            let bounds = RuntimeMetrics.pollTimeBucketBounds
            var buckets = [UInt64](repeating: 0, count: bounds.count + 1)
            var sum = Duration.zero
            for w in m.workers {
                for (b, n) in w.pollTimeHistogram.enumerated() where b < buckets.count {
                    buckets[b] &+= n
                }
                sum += w.totalPollTime
            }
            var cumulative: UInt64 = 0
            for (b, bound) in bounds.enumerated() {
                cumulative &+= buckets[b]
                sample(name + "_bucket", "le=\"\(PrometheusText.seconds(bound))\"", Double(cumulative))
            }
            cumulative &+= buckets[bounds.count]
            sample(name + "_bucket", "le=\"+Inf\"", Double(cumulative))
            sample(name + "_sum", "", PrometheusText.seconds(sum))
            sample(name + "_count", "", Double(cumulative))
        }
    }
}
