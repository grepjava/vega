import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import Synchronization
import Testing
@testable import Vega

/// Queue tests never run these "jobs": they're just distinct non-null pointers.
func fakeJob(_ i: Int) -> UnownedJob {
    unsafeBitCast(UnsafeRawPointer(bitPattern: i)!, to: UnownedJob.self)
}

func jobID(_ j: UnownedJob) -> Int {
    Int(bitPattern: unsafeBitCast(j, to: UnsafeRawPointer.self))
}

/// Start `n` plain threads running `body(index)` and wait for all of them.
func onThreads(_ n: Int, _ body: @escaping @Sendable (Int) -> Void) {
    final class Ctx: @unchecked Sendable {
        let body: @Sendable (Int) -> Void
        let done = Atomic<Int>(0)
        let index: Int
        let parent: Ctx?
        init(_ body: @escaping @Sendable (Int) -> Void, index: Int = -1, parent: Ctx? = nil) {
            self.body = body; self.index = index; self.parent = parent
        }
    }
    let root = Ctx(body)
    for i in 0..<n {
        let c = Unmanaged.passRetained(Ctx(body, index: i, parent: root)).toOpaque()
        _ = cv_thread_spawn({ raw in
            let c = Unmanaged<Ctx>.fromOpaque(raw!).takeRetainedValue()
            c.body(c.index)
            c.parent!.done.add(1, ordering: .sequentiallyConsistent)
        }, c, "test", -1)
    }
    while root.done.load(ordering: .sequentiallyConsistent) < n { sched_yield() }
}

@Suite struct LocalQueueTests {
    @Test func fifoPushPop() {
        let q = LocalQueue(), inject = InjectQueue()
        for i in 1...100 { q.push(fakeJob(i), overflow: inject) }
        #expect(q.count == 100)
        for i in 1...100 { #expect(jobID(q.pop()!) == i) }
        #expect(q.pop() == nil)
        #expect(inject.isEmpty)
    }

    @Test func overflowMovesHalfPlusOneToInject() {
        let q = LocalQueue(), inject = InjectQueue()
        for i in 1...256 { q.push(fakeJob(i), overflow: inject) }
        #expect(inject.isEmpty)
        q.push(fakeJob(257), overflow: inject)
        #expect(q.count == 128)
        #expect(inject.count.load(ordering: .relaxed) == 129)
        // Oldest half went to inject, in order, then the new job.
        for i in 1...128 { #expect(jobID(inject.pop()!) == i) }
        #expect(jobID(inject.pop()!) == 257)
        for i in 129...256 { #expect(jobID(q.pop()!) == i) }
    }

    @Test func stealTakesHalf() {
        let victim = LocalQueue(), thief = LocalQueue(), inject = InjectQueue()
        for i in 1...10 { victim.push(fakeJob(i), overflow: inject) }
        let got = victim.steal(into: thief)
        #expect(got != nil)
        #expect(victim.count == 5)
        #expect(thief.count == 4) // 5 stolen, one returned to run
        #expect(jobID(got!) == 5)
        for i in 1...4 { #expect(jobID(thief.pop()!) == i) }
        for i in 6...10 { #expect(jobID(victim.pop()!) == i) }
    }

    @Test func stealFromEmptyIsNil() {
        #expect(LocalQueue().steal(into: LocalQueue()) == nil)
    }

    /// The owner pushes and pops while three thieves steal: every job must be
    /// taken exactly once.
    @Test func concurrentStealStress() {
        let total = 400_000
        let owner = LocalQueue(), inject = InjectQueue()
        let thieves = (0..<3).map { _ in LocalQueue() }
        let taken = Atomic<Int>(0), sum = Atomic<Int>(0)
        let ownerDone = Atomic<Bool>(false)

        @Sendable func take(_ j: UnownedJob) {
            taken.add(1, ordering: .relaxed)
            sum.add(jobID(j), ordering: .relaxed)
        }

        onThreads(4) { t in
            if t == 0 {
                var next = 1
                while next <= total {
                    for _ in 0..<7 where next <= total { owner.push(fakeJob(next), overflow: inject); next += 1 }
                    for _ in 0..<3 { if let j = owner.pop() { take(j) } }
                }
                while let j = owner.pop() { take(j) }
                ownerDone.store(true, ordering: .sequentiallyConsistent)
            } else {
                let mine = thieves[t - 1]
                while !ownerDone.load(ordering: .sequentiallyConsistent) || !owner.isEmpty {
                    if let j = owner.steal(into: mine) { take(j) }
                    while let j = mine.pop() { take(j) }
                }
            }
        }
        while let j = inject.pop() { take(j) }
        for q in thieves { while let j = q.pop() { take(j) } }

        #expect(taken.load(ordering: .relaxed) == total)
        #expect(sum.load(ordering: .relaxed) == total * (total + 1) / 2)
    }
}
