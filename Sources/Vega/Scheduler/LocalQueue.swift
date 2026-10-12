import Synchronization

/// A worker's run queue: a fixed ring that only its owner pushes to and pops
/// from, and that other workers steal half of. This is Tokio's
/// `queue::Local`.
///
/// `head` packs two indices: the lower 32 bits are the real head (the
/// next job to pop) and the upper 32 the steal head. They differ only while a
/// thief is copying jobs out; the slots between them still belong to the
/// thief, so the owner must not write over them. Indices grow without bound and
/// wrap; a slot is `index & mask`.
final class LocalQueue: @unchecked Sendable {
    static let capacity: UInt32 = 256
    static let mask: UInt32 = capacity - 1

    let head = Atomic<UInt64>(0)
    let tail = Atomic<UInt32>(0)
    let buffer: UnsafeMutablePointer<UnownedJob>

    init() {
        buffer = .allocate(capacity: Int(Self.capacity))
    }

    deinit { buffer.deallocate() }

    @inline(__always) static func unpack(_ v: UInt64) -> (steal: UInt32, real: UInt32) {
        (UInt32(truncatingIfNeeded: v >> 32), UInt32(truncatingIfNeeded: v))
    }

    @inline(__always) static func pack(_ steal: UInt32, _ real: UInt32) -> UInt64 {
        UInt64(steal) << 32 | UInt64(real)
    }

    @inline(__always) func slot(_ i: UInt32) -> UnsafeMutablePointer<UnownedJob> {
        buffer + Int(i & Self.mask)
    }

    /// Jobs waiting (approximate when read off the owner thread).
    var count: Int {
        let (_, real) = Self.unpack(head.load(ordering: .acquiring))
        return Int(tail.load(ordering: .acquiring) &- real)
    }

    var isEmpty: Bool { count == 0 }

    /// Owner only: slots free for `pushUnchecked`. Counted from the *steal*
    /// head: slots a thief is still copying out are not free yet, even when
    /// the queue looks empty to its owner (Tokio: `remaining_slots`).
    var remainingSlots: Int {
        let (steal, _) = Self.unpack(head.load(ordering: .acquiring))
        return Int(Self.capacity &- (tail.load(ordering: .relaxed) &- steal))
    }

    /// Owner only. When the ring is full, half of it and `job` move to
    /// `overflow` in one batch.
    func push(_ job: UnownedJob, overflow: InjectQueue) {
        let t = tail.load(ordering: .relaxed) // only the owner writes tail
        while true {
            let (steal, real) = Self.unpack(head.load(ordering: .acquiring))
            if t &- steal < Self.capacity {
                slot(t).initialize(to: job)
                tail.store(t &+ 1, ordering: .releasing)
                return
            }
            if steal != real {
                // A thief is mid-copy and will free room shortly; don't wait for it.
                overflow.push(job)
                return
            }
            if pushOverflow(job, real: real, tail: t, overflow: overflow) { return }
            // A thief took jobs between our load and the CAS: there's room now.
        }
    }

    private func pushOverflow(_ job: UnownedJob, real: UInt32, tail t: UInt32, overflow: InjectQueue) -> Bool {
        let n = Self.capacity / 2
        let prev = Self.pack(real, real)
        let next = Self.pack(real &+ n, real &+ n)
        guard head.compareExchange(expected: prev, desired: next,
                                   successOrdering: .releasing, failureOrdering: .relaxed).exchanged
        else { return false }
        // Slots real ..< real+n are ours now; nobody else can reach them.
        overflow.pushBatch(n) { i in i < n ? self.slot(real &+ i).pointee : job }
        return true
    }

    /// Owner only, and only within `remainingSlots`. Used to move a batch in
    /// from the inject queue.
    func pushUnchecked(_ job: UnownedJob) {
        let t = tail.load(ordering: .relaxed)
        slot(t).initialize(to: job)
        tail.store(t &+ 1, ordering: .releasing)
    }

    /// Owner only.
    func pop() -> UnownedJob? {
        var h = head.load(ordering: .acquiring)
        while true {
            let (steal, real) = Self.unpack(h)
            if real == tail.load(ordering: .relaxed) { return nil }
            let nextReal = real &+ 1
            // No thief: both heads move. Thief active: only the real head.
            let next = steal == real ? Self.pack(nextReal, nextReal) : Self.pack(steal, nextReal)
            let (ok, current) = head.compareExchange(expected: h, desired: next,
                                                     successOrdering: .acquiringAndReleasing,
                                                     failureOrdering: .acquiring)
            if ok { return slot(real).pointee }
            h = current
        }
    }

    /// Called by `dst`'s owner: move half of this queue into `dst` and return
    /// one of the moved jobs to run now.
    func steal(into dst: LocalQueue) -> UnownedJob? {
        let dstTail = dst.tail.load(ordering: .relaxed)
        let (dstSteal, _) = Self.unpack(dst.head.load(ordering: .acquiring))
        // Don't steal into a queue that is already half full.
        if dstTail &- dstSteal > Self.capacity / 2 { return nil }

        var n = stealCopy(into: dst, at: dstTail)
        if n == 0 { return nil }
        n -= 1
        let job = dst.slot(dstTail &+ n).pointee
        if n > 0 { dst.tail.store(dstTail &+ n, ordering: .releasing) }
        return job
    }

    private func stealCopy(into dst: LocalQueue, at dstTail: UInt32) -> UInt32 {
        var prev = head.load(ordering: .acquiring)
        var claimed: UInt64
        var n: UInt32
        while true {
            let (steal, real) = Self.unpack(prev)
            if steal != real { return 0 } // another thief got here first
            let t = tail.load(ordering: .acquiring)
            n = t &- real
            n -= n / 2
            if n == 0 { return 0 }
            claimed = Self.pack(steal, real &+ n) // owner can no longer pop these
            let (ok, current) = head.compareExchange(expected: prev, desired: claimed,
                                                     successOrdering: .acquiringAndReleasing,
                                                     failureOrdering: .acquiring)
            if ok { break }
            prev = current
        }

        let (first, _) = Self.unpack(claimed)
        for i in 0..<n {
            dst.slot(dstTail &+ i).initialize(to: slot(first &+ i).pointee)
        }

        // Release the slots: steal head catches up with the real head. The owner
        // may have popped meanwhile (moving real), so retry until it sticks.
        prev = claimed
        while true {
            let (_, real) = Self.unpack(prev)
            let (ok, current) = head.compareExchange(expected: prev, desired: Self.pack(real, real),
                                                     successOrdering: .acquiringAndReleasing,
                                                     failureOrdering: .acquiring)
            if ok { return n }
            prev = current
        }
    }
}
