import Synchronization
#if canImport(Glibc)
import Glibc
#endif
import CVega
import Testing
@testable import Vega

/// The scheduler's queue traffic without Swift tasks: every worker pushes new
/// ids (overflowing into the inject queue), pops, takes inject batches and
/// steals from the others, and every id must come out exactly once.
@Suite struct QueueModelTests {
    @Test func everyJobComesOutOnce() {
        let workers = 8
        // VEGA_MODEL_N shrinks it for slow builds (TSan).
        let perWorker = getenv("VEGA_MODEL_N").flatMap { Int(String(cString: $0)) } ?? 2_000_000
        let total = workers * perWorker
        final class World: @unchecked Sendable {
            let queues: [LocalQueue]
            let inject = InjectQueue()
            let seen: UnsafeMutablePointer<Atomic<UInt8>>
            let taken = Atomic<Int>(0)
            let dupes = Atomic<Int>(0)
            init(_ w: Int, _ total: Int) {
                queues = (0..<w).map { _ in LocalQueue() }
                seen = .allocate(capacity: total + 1)
                for i in 0...total { (seen + i).initialize(to: Atomic(0)) }
            }
            func take(_ j: UnownedJob) {
                let id = jobID(j)
                if seen[id].add(1, ordering: .relaxed).newValue != 1 { dupes.add(1, ordering: .relaxed) }
                taken.add(1, ordering: .relaxed)
            }
        }
        let world = World(workers, total)
        onThreads(workers) { me in
            let q = world.queues[me]
            var next = me * perWorker + 1
            let end = next + perWorker
            var rng = UInt32(me * 7919 + 1)
            func rand() -> UInt32 { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng }
            let deadline = cv_now_ns() + 30_000_000_000 // never spin forever if jobs get lost
            while world.taken.load(ordering: .relaxed) < total && cv_now_ns() < deadline {
                let r = rand() % 8
                if r < 3, next < end {
                    // Bursts of pushes, like a spawner.
                    for _ in 0..<(1 + Int(rand() % 64)) where next < end {
                        q.push(fakeJob(next), overflow: world.inject); next += 1
                    }
                } else if r < 5, let j = q.pop() {
                    world.take(j)
                } else if r < 6, q.isEmpty, let j = world.inject.popBatch(into: q, workers: workers) {
                    world.take(j)
                } else if q.isEmpty {
                    let victim = Int(rand() % UInt32(workers))
                    if victim != me, let j = world.queues[victim].steal(into: q) { world.take(j) }
                }
            }
        }
        #expect(world.dupes.load(ordering: .relaxed) == 0)
        #expect(world.taken.load(ordering: .relaxed) == total)
    }
}
