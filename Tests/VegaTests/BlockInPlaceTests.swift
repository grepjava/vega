import CVega
import Synchronization
import Testing
@testable import Vega

private final class RanCount: Sendable { let value = Atomic<Int>(0) }

/// Spin until `done` or `limit` ms pass: blocking, without a sleep call
/// that differs by platform. The elapsed ms.
private func spin(upTo limit: UInt64, until done: () -> Bool) -> UInt64 {
    let start = cv_now_ns()
    while !done() && (cv_now_ns() - start) / 1_000_000 < limit {}
    return (cv_now_ns() - start) / 1_000_000
}

@Suite("Runtime.blockInPlace")
struct BlockInPlaceTests {
    /// A task spawned just before blocking sits in the worker's LIFO slot,
    /// which no other worker steals from; blockInPlace hands it over.
    @Test func queuedWorkRunsElsewhere() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let ran = RanCount()
        let elapsed = rt.block { () async -> UInt64 in
            await rt.spawn {
                rt.spawn { ran.value.add(1, ordering: .relaxed) }
                return Runtime.blockInPlace {
                    spin(upTo: 3_000) { ran.value.load(ordering: .relaxed) == 1 }
                }
            }.value
        }
        #expect(ran.value.load(ordering: .relaxed) == 1)
        #expect(elapsed < 2_000, "the spawned task waited \(elapsed) ms for the blocking one")
    }

    /// What the blocking code wakes runs on the other workers meanwhile.
    @Test func wokenWorkRunsElsewhere() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let ran = RanCount()
        let elapsed = rt.block { () async -> UInt64 in
            await rt.spawn {
                let notify = Notify()
                let waiter = rt.spawn {
                    try? await notify.notified()
                    ran.value.add(1, ordering: .relaxed)
                }
                try? await Runtime.sleep(for: .milliseconds(20))
                let elapsed = Runtime.blockInPlace {
                    notify.notifyOne()
                    return spin(upTo: 3_000) { ran.value.load(ordering: .relaxed) == 1 }
                }
                await waiter.value
                return elapsed
            }.value
        }
        #expect(ran.value.load(ordering: .relaxed) == 1)
        #expect(elapsed < 2_000, "the woken task waited \(elapsed) ms for the blocking one")
    }

    @Test func returnsAndThrows() throws {
        struct Nope: Error {}
        #expect(Runtime.blockInPlace { 5 } == 5)
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let threw = rt.block { () async -> Bool in
            do throws(Nope) {
                try Runtime.blockInPlace { () throws(Nope) in throw Nope() }
                return false
            } catch {
                return true
            }
        }
        #expect(threw)
    }
}
