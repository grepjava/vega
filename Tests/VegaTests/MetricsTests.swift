import Testing
import Vega
import VegaMetrics
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

@Suite struct MetricsTests {
    @Test func countersMove() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let before = rt.metrics
        try rt.block { () async throws in
            for _ in 0..<200 { await Runtime.yield() }
            usleep(20_000)          // busy past the coarse clock's tick
            try await Runtime.sleep(for: .milliseconds(20))
        }
        let m = rt.metrics
        let d = m.since(before)
        #expect(m.workers.count == 2)
        #expect(d.polls >= 200)
        #expect(d.parks > 0)
        #expect(d.timedEnqueues >= 1)
        #expect(m.busyTime > .zero)
        #expect(m.elapsed > d.elapsed && d.elapsed > .zero)
        #expect(m.utilization >= 0 && m.utilization <= 1)
        // Timing was never on.
        #expect(m.workers.allSatisfy { $0.pollTimeHistogram.isEmpty && $0.slowPolls == 0 })
    }

    @Test func pollTimesAndSlowPolls() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        rt.measurePollTimes = true
        rt.slowPollThreshold = .milliseconds(5)
        #expect(rt.slowPollThreshold == .milliseconds(5))
        try rt.block { () async throws in
            for _ in 0..<50 { await Runtime.yield() }
            usleep(20_000)                      // one poll that holds the worker
            await Runtime.yield()
        }
        rt.measurePollTimes = false
        let w = rt.metrics.workers[0]
        #expect(w.slowPolls >= 1)
        #expect(w.longestPoll >= .milliseconds(15))
        #expect(w.pollTimeHistogram.count == RuntimeMetrics.pollTimeBucketBounds.count + 1)
        #expect(w.pollTimeHistogram.reduce(0, +) >= 50)
        #expect(w.totalPollTime >= .milliseconds(15))
        #expect(w.meanPollTime > .zero)
    }

    @Test func forcedYieldsAndOverflows() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        try rt.block { () async throws in
            for _ in 0..<1000 { await Runtime.consumeBudget() }
            // More runnable tasks than a local queue holds (256).
            let tasks = (0..<1000).map { _ in rt.spawn { 1 } }
            var total = 0
            for t in tasks { total += await t.value }
            #expect(total == 1000)
        }
        let w = rt.metrics.workers[0]
        #expect(w.forcedYields >= 7)
        #expect(w.overflows >= 1)
    }

    @Test func blockingPoolGauges() throws {
        let rt = Runtime(workers: 1, blockingThreads: 1)
        defer { rt.shutdown() }
        let (threads, queued) = try rt.block { () async throws -> (Int, Int) in
            let first = rt.spawn { await Runtime.blocking { _ = usleep(100_000) } }
            let second = rt.spawn { await Runtime.blocking { _ = usleep(100_000) } }
            try await Runtime.sleep(for: .milliseconds(30))
            let m = rt.metrics
            await first.value
            await second.value
            return (m.blockingThreads, m.blockingQueueDepth)
        }
        #expect(threads == 1)
        #expect(queued == 1)
    }

    @Test func samplesArriveAsDeltas() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let samples = try rt.block { () async throws -> [RuntimeMetrics] in
            var out: [RuntimeMetrics] = []
            for await m in rt.metricsSamples(every: .milliseconds(20)) {
                out.append(m)
                if out.count == 3 { break }
            }
            return out
        }
        #expect(samples.count == 3)
        for s in samples {
            #expect(s.elapsed >= .milliseconds(15) && s.elapsed < .seconds(2))
        }
    }

    @Test func prometheusText() throws {
        var m = RuntimeMetrics(elapsed: .seconds(2), injectQueueDepth: 3, blockingThreads: 1)
        m.workers = [
            .init(polls: 10, steals: 1, busyTime: .milliseconds(500),
                  pollTimeHistogram: [4, 6] + Array(repeating: 0, count: 22), totalPollTime: .microseconds(9)),
            .init(polls: 5, pollTimeHistogram: [0, 0, 5] + Array(repeating: 0, count: 21)),
        ]
        let text = PrometheusText.render(m, labels: ["runtime": "a\"b"])
        let lines = Set(text.split(separator: "\n").map(String.init))
        #expect(lines.contains("# TYPE vega_worker_polls_total counter"))
        #expect(lines.contains("vega_worker_polls_total{runtime=\"a\\\"b\",worker=\"0\"} 10"))
        #expect(lines.contains("vega_worker_polls_total{runtime=\"a\\\"b\",worker=\"1\"} 5"))
        #expect(lines.contains("vega_worker_busy_seconds_total{runtime=\"a\\\"b\",worker=\"0\"} 0.5"))
        #expect(lines.contains("vega_inject_queue_depth{runtime=\"a\\\"b\"} 3"))
        #expect(lines.contains("# TYPE vega_poll_duration_seconds histogram"))
        #expect(lines.contains("vega_poll_duration_seconds_bucket{runtime=\"a\\\"b\",le=\"1e-06\"} 4"))
        #expect(lines.contains("vega_poll_duration_seconds_bucket{runtime=\"a\\\"b\",le=\"2e-06\"} 10"))
        #expect(lines.contains("vega_poll_duration_seconds_bucket{runtime=\"a\\\"b\",le=\"4e-06\"} 15"))
        #expect(lines.contains("vega_poll_duration_seconds_bucket{runtime=\"a\\\"b\",le=\"+Inf\"} 15"))
        #expect(lines.contains("vega_poll_duration_seconds_count{runtime=\"a\\\"b\"} 15"))
        // Every sample line is a name, optional labels, and a number.
        for line in lines where !line.hasPrefix("#") {
            #expect(Double(line.split(separator: " ").last!) != nil, "\(line)")
        }
    }
}
