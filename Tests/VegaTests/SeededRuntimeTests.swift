import Synchronization
import Testing
@testable import Vega
import VegaTest

/// What tasks did, in the order they did it.
private final class SeededLog: Sendable {
    let entries = Mutex<[Int]>([])
    func add(_ n: Int) { entries.withLock { $0.append(n) } }
    var all: [Int] { entries.withLock { $0 } }
}

/// Twenty tasks, each logging three times with a yield between.
private func interleaving(_ rt: Runtime) async -> [Int] {
    let log = SeededLog()
    let set = JoinSet<Void, Never>(runtime: rt)
    for id in 0..<20 {
        set.spawn {
            for _ in 0..<3 {
                log.add(id)
                await Runtime.yield()
            }
        }
    }
    while (try? await set.next()) != nil {}
    return log.all
}

/// A lost update: read, yield, write back. Two tasks end at 2 only when
/// one runs both halves before the other starts.
private final class Racy: @unchecked Sendable {
    var value = 0
}

private struct LostUpdate: Error {}

@Suite("Runtime.seeded and Simulation")
struct SeededRuntimeTests {
    @Test func aSeedFixesTheOrder() throws {
        let a = try Simulation.run(seeds: 7..<8) { rt -> [Int] in await interleaving(rt) }
        let b = try Simulation.run(seeds: 7..<8) { rt -> [Int] in await interleaving(rt) }
        #expect(a == b)
        #expect(a[0].count == 60)
        let many = try Simulation.run(seeds: 0..<10) { rt -> [Int] in await interleaving(rt) }
        #expect(Set(many).count > 1, "every seed ran the tasks in the same order")
    }

    /// The race is found, and its seed brings it back.
    @Test func findsALostUpdateAndReplaysIt() throws {
        @Sendable func race(_ rt: Runtime) async throws {
            let shared = Racy()
            let set = JoinSet<Void, Never>(runtime: rt)
            for _ in 0..<2 {
                set.spawn {
                    let v = shared.value
                    await Runtime.yield()
                    shared.value = v + 1
                }
            }
            while (try? await set.next()) != nil {}
            if shared.value != 2 { throw LostUpdate() }
        }
        var failingSeed: UInt64?
        do throws(Simulation.Failure) {
            try Simulation.run(seeds: 0..<200) { rt -> Void in try await race(rt) }
        } catch {
            failingSeed = error.seed
            #expect(error.error is LostUpdate)
        }
        let seed = try #require(failingSeed, "no seed lost the update")
        for _ in 0..<3 {
            #expect(throws: Simulation.Failure.self) {
                try Simulation.run(seeds: seed..<(seed + 1)) { rt -> Void in try await race(rt) }
            }
        }
    }

    /// Time is paused: an hour's sleep ends at once, and in order.
    @Test func timeIsPaused() throws {
        let order = try Simulation.run(seeds: 0..<5) { rt -> [Int] in
            let log = SeededLog()
            let set = JoinSet<Void, Never>(runtime: rt)
            for (id, minutes) in [(1, 60), (2, 5), (3, 30)] {
                set.spawn {
                    try? await Runtime.sleep(for: .seconds(minutes * 60))
                    log.add(id)
                }
            }
            while (try? await set.next()) != nil {}
            return log.all
        }
        #expect(order.allSatisfy { $0 == [2, 3, 1] })
    }
}
