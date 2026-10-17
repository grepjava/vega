import Logging
import Metrics
import MetricsTestKit
import Synchronization
import Testing
import Vega
import VegaLogging
import VegaSwiftMetrics

/// Log messages, kept.
final class Captured: Sendable {
    let messages = Mutex<[(Logger.Level, String, Logger.Metadata?)]>([])
}

struct CapturingHandler: LogHandler {
    let captured: Captured
    var metadata: Logger.Metadata = [:]
    var logLevel: Logger.Level = .trace

    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    func log(level: Logger.Level, message: Logger.Message, metadata: Logger.Metadata?, source: String,
             file: String, function: String, line: UInt) {
        captured.messages.withLock { $0.append((level, message.description, metadata)) }
    }
}

@Suite("Adapters", .serialized)
struct AdapterTests {
    @Test func slowPollsAreLogged() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let captured = Captured()
        rt.logSlowPolls(to: Logger(label: "vega", factory: { _ in CapturingHandler(captured: captured) }),
                        threshold: .milliseconds(20))
        rt.block {
            await rt.spawn {
                let start = ContinuousClock.now
                while ContinuousClock.now - start < .milliseconds(40) {}
            }.value
        }
        let logged = captured.messages.withLock { $0 }
        #expect(logged.count == 1)
        #expect(logged.first?.0 == .warning)
        #expect(logged.first?.2?["worker"] != nil)
    }

    @Test func metricsAreReported() throws {
        let metrics = TestMetrics()
        MetricsSystem.bootstrap(metrics)  // once per process: the only test that does
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let task = rt.reportMetrics(every: .milliseconds(20), prefix: "test", dimensions: [("runtime", "a")])
        rt.block {
            for _ in 0..<200 { await rt.spawn {}.value }
            try? await Runtime.sleep(for: .milliseconds(100))
        }
        task.cancel()
        let polls = try metrics.expectCounter("test_polls", [("runtime", "a")])
        #expect(polls.totalValue > 0)
        let workers = try metrics.expectGauge("test_workers", [("runtime", "a")])
        #expect(workers.lastValue == 2)
    }
}
