import Testing
@testable import Vega

@Suite struct EnqueueCountTests {
    /// Runtime.sleep is a timed enqueue; block starts its task from outside
    /// the runtime, a foreign one.
    @Test func countsTimedAndForeignEnqueues() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let before = rt.metrics
        rt.block {
            try? await Runtime.sleep(for: .milliseconds(1))
            try? await Runtime.sleep(for: .milliseconds(1))
        }
        let after = rt.metrics
        #expect(after.timedEnqueues - before.timedEnqueues == 2)
        #expect(after.foreignEnqueues > before.foreignEnqueues)
    }
}
