import CVega
import Testing
@testable import Vega

@Suite("IOEvent")
struct IOEventTests {
    /// A signal sent before the wait is kept for it.
    @Test func aSignalBeforeTheWaitIsKept() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let outcome = try rt.block { () async throws(IOError) -> String in
            let event = IOEvent()
            event.signal()
            event.signal()
            try await event.wait()
            // Only one was kept.
            do throws(IOError) {
                try await Runtime.withIODeadline(.milliseconds(20)) { () async throws(IOError) in
                    try await event.wait()
                }
                return "woken twice"
            } catch {
                return "\(error)"
            }
        }
        #expect(outcome == "\(IOError.timedOut)")
    }

    /// Signalled from another task, the waiter wakes.
    @Test func aSignalWakesTheWaiter() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        try rt.block { () async throws(IOError) in
            let event = IOEvent()
            rt.spawn {
                try? await Runtime.sleep(for: .milliseconds(10))
                event.signal()
            }
            try await Runtime.withIODeadline(.seconds(10)) { () async throws(IOError) in
                try await event.wait()
            }
        }
    }

    /// The deadline, and a trigger, end the wait as they would a socket's.
    @Test func aDeadlineOrATriggerEndsTheWait() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let start = cv_now_ns()
        let (byDeadline, byTrigger) = try rt.block { () async throws(IOError) -> (String, String) in
            let event = IOEvent()
            var byDeadline = "woken"
            do throws(IOError) {
                try await Runtime.withIODeadline(.milliseconds(20)) { () async throws(IOError) in
                    try await event.wait()
                }
            } catch {
                byDeadline = "\(error)"
            }
            let trigger = IODeadlineTrigger()
            rt.spawn {
                try? await Runtime.sleep(for: .milliseconds(20))
                trigger.fire()
            }
            var byTrigger = "woken"
            do throws(IOError) {
                try await Runtime.withIODeadline(.seconds(30), trigger: trigger) { () async throws(IOError) in
                    try await event.wait()
                }
            } catch {
                byTrigger = "\(error)"
            }
            // Still usable after both.
            event.signal()
            try await event.wait()
            return (byDeadline, byTrigger)
        }
        let elapsed = (cv_now_ns() - start) / 1_000_000
        #expect(byDeadline == "\(IOError.timedOut)")
        #expect(byTrigger == "\(IOError.timedOut)")
        #expect(elapsed < 5_000, "took \(elapsed) ms")
    }

    /// Cancelling the task ends the wait with `.cancelled`.
    @Test func cancellationEndsTheWait() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let outcome = rt.block { () async -> String in
            let event = IOEvent()
            let task = rt.spawn { () async -> String in
                do throws(IOError) {
                    try await event.wait()
                    return "woken"
                } catch {
                    return "\(error)"
                }
            }
            try? await Runtime.sleep(for: .milliseconds(20))
            task.cancel()
            return await task.value
        }
        #expect(outcome == "\(IOError.cancelled)")
    }
}
