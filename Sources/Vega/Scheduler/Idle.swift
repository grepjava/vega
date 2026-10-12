import Synchronization

/// Which workers are parked and how many are searching for work: Tokio's
/// `Idle`. `state` packs the searching count (low 32 bits) and the unparked
/// count (high 32), so "nobody is searching and somebody is asleep" is one
/// load on the enqueue path.
///
/// Rules:
/// - At most half the workers search at once, so thieves don't pile on.
/// - Enqueuing wakes a sleeper only if nobody is searching: a searcher will
///   find the job anyway.
/// - The last searcher to stop wakes one more if work is still pending.
final class Idle: @unchecked Sendable {
    private static let unparkedOne: UInt64 = 1 << 32
    private static let searchingMask: UInt64 = (1 << 32) - 1

    let workers: Int
    private let state: Atomic<UInt64>
    private let lock = RawLock()
    /// Parked worker indices, `sleeperCount` of them; guarded by `lock`.
    private let sleepers: UnsafeMutablePointer<Int>
    private let sleeperCount = Guarded(0)

    init(workers: Int) {
        self.workers = workers
        state = Atomic(UInt64(workers) << 32)
        sleepers = .allocate(capacity: workers)
    }

    deinit {
        sleepers.deallocate()
        sleeperCount.destroy()
        lock.destroy()
    }

    @inline(__always) private static func searching(_ s: UInt64) -> Int { Int(s & searchingMask) }
    @inline(__always) private static func unparked(_ s: UInt64) -> Int { Int(s >> 32) }

    /// Every worker is parked (none notified and on its way).
    var allParked: Bool { Self.unparked(state.load(ordering: .sequentiallyConsistent)) == 0 }

    var searchingCount: Int { Self.searching(state.load(ordering: .sequentiallyConsistent)) }

    @inline(__always) private func shouldWake(_ s: UInt64) -> Bool {
        Self.searching(s) == 0 && Self.unparked(s) < workers
    }

    /// The sleeper to wake for new work, already counted as unparked and
    /// searching; nil if none should be woken.
    ///
    /// The fence pairs with the one in `Scheduler.hasPendingWork`: the job
    /// was published with a release store, and a parking searcher reads the
    /// queues after its RMW here. Without a StoreLoad barrier on both sides
    /// each can miss the other (x86 reorders the push's store after this
    /// load; arm64's RCpc acquire loads pass the parker's RMW), and the job
    /// waits with every worker asleep. Tokio fences here too.
    @inline(__always) func workerToNotify() -> Int? {
        atomicMemoryFence(ordering: .sequentiallyConsistent)
        guard shouldWake(state.load(ordering: .sequentiallyConsistent)) else { return nil }
        return workerToNotifySlow()
    }

    private func workerToNotifySlow() -> Int? {
        let n = sleeperCount.pointer
        return lock.withLock { () -> Int? in
            guard shouldWake(state.load(ordering: .sequentiallyConsistent)), n.pointee > 0 else { return nil }
            n.pointee -= 1
            state.add(Self.unparkedOne + 1, ordering: .sequentiallyConsistent)
            return sleepers[n.pointee]
        }
    }

    func transitionToSearching() -> Bool {
        let s = state.load(ordering: .sequentiallyConsistent)
        if 2 * Self.searching(s) >= workers { return false }
        state.add(1, ordering: .sequentiallyConsistent)
        return true
    }

    /// Returns true if this was the last searcher.
    func transitionFromSearching() -> Bool {
        let (old, _) = state.subtract(1, ordering: .sequentiallyConsistent)
        return Self.searching(old) == 1
    }

    /// Returns true if the worker was the last searcher.
    func transitionToParked(_ index: Int, searching: Bool) -> Bool {
        let n = sleeperCount.pointer
        return lock.withLock {
            let delta = Self.unparkedOne + (searching ? 1 : 0)
            let (old, _) = state.subtract(delta, ordering: .sequentiallyConsistent)
            sleepers[n.pointee] = index
            n.pointee += 1
            return searching && Self.searching(old) == 1
        }
    }

    /// Take `index` off the sleeper list (it woke on its own, e.g. a timer).
    /// False if someone already woke it through `workerToNotify`.
    func unpark(_ index: Int) -> Bool {
        let n = sleeperCount.pointer
        return lock.withLock {
            for i in 0..<n.pointee where sleepers[i] == index {
                n.pointee -= 1
                sleepers[i] = sleepers[n.pointee]
                state.add(Self.unparkedOne, ordering: .sequentiallyConsistent)
                return true
            }
            return false
        }
    }

    /// Any parked worker other than `index`, left parked (for handing over timers).
    func anySleeper(except index: Int) -> Int? {
        let n = sleeperCount.pointer
        return lock.withLock {
            var i = n.pointee
            while i > 0 {
                i -= 1
                if sleepers[i] != index { return sleepers[i] }
            }
            return nil
        }
    }

    func isParked(_ index: Int) -> Bool {
        let n = sleeperCount.pointer
        return lock.withLock {
            for i in 0..<n.pointee where sleepers[i] == index { return true }
            return false
        }
    }
}
