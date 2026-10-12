import Synchronization

/// What a timer does when it fires. Trivially copyable: no ARC in the wheel.
enum TimerAction: @unchecked Sendable {
    /// A job handed over by Swift (`Task.sleep` via `SchedulingExecutor`).
    case job(UnownedJob)
    /// A task parked in `Runtime.sleep`. The wheel holds one retain, which
    /// whoever takes the entry out (firing or cancelling) consumes.
    case waiter(Unmanaged<SleepWaiter>)
    /// Cancel a task (a `Runtime.timeout` child): a retained task object,
    /// consumed the same way.
    case cancel(UnsafeRawPointer)
}

/// One pending timer, linked into a wheel slot. Raw memory from the shard's
/// free list: inserting and removing allocate nothing.
struct TimerEntry {
    /// Deadline, in wheel ticks (milliseconds since the wheel's origin).
    var when: UInt64
    var prev: UnsafeMutablePointer<TimerEntry>?
    var next: UnsafeMutablePointer<TimerEntry>?
    /// `level * 64 + slot` while linked into the wheel, -1 otherwise.
    var slot: Int32
    /// Bumped each time the entry is handed out, so a stale `TimerHandle`
    /// to a recycled entry is recognised.
    var gen: UInt32
    var action: TimerAction
}

/// A hierarchical timing wheel: 6 levels of 64 slots, 1 ms per level-0 slot,
/// each level's slot 64 times wider than the one below (Tokio's
/// `runtime/time/wheel`). Insert and remove are O(1); a timer cascades down
/// at most 5 times on its way to firing. Not thread-safe: a `TimerShard`
/// guards it.
struct Wheel {
    static let levels = 6
    /// One full turn of the top level, in ticks: 2^36 ms, about 2.2 years.
    /// Timers further out park in the top level and go round again.
    static let maxDuration: UInt64 = (1 << 36) - 1

    /// Every slot at or before this tick has been processed.
    private(set) var elapsed: UInt64 = 0
    /// Entries linked in, for tests and metrics.
    private(set) var count = 0
    /// Per level, which of its 64 slots hold entries.
    private let occupied: UnsafeMutablePointer<UInt64>
    /// Per slot (`level * 64 + slot`), the first and last entry. Appending
    /// at the tail keeps timers with the same deadline in FIFO order.
    private let heads: UnsafeMutablePointer<UnsafeMutablePointer<TimerEntry>?>
    private let tails: UnsafeMutablePointer<UnsafeMutablePointer<TimerEntry>?>
    private var free: UnsafeMutablePointer<TimerEntry>?
    private var chunks: [UnsafeMutablePointer<TimerEntry>] = []
    static let chunkSize = 64

    init() {
        occupied = .allocate(capacity: Self.levels)
        occupied.initialize(repeating: 0, count: Self.levels)
        heads = .allocate(capacity: Self.levels * 64)
        heads.initialize(repeating: nil, count: Self.levels * 64)
        tails = .allocate(capacity: Self.levels * 64)
        tails.initialize(repeating: nil, count: Self.levels * 64)
    }

    /// Free the wheel's memory. Entries still linked in are dropped without
    /// firing (a waiter's retain leaks, as it did with the heap).
    func destroy() {
        occupied.deallocate()
        heads.deallocate()
        tails.deallocate()
        for c in chunks { c.deallocate() }
    }

    @inline(__always) static func level(elapsed: UInt64, when: UInt64) -> Int {
        // The highest bit where the two differ picks the level; the low 6
        // bits are or-ed in so level 0 covers its whole slot range.
        var masked = (elapsed ^ when) | 63
        if masked >= maxDuration { masked = maxDuration - 1 }
        return (63 - masked.leadingZeroBitCount) / 6
    }

    // MARK: entries

    private mutating func allocate() -> UnsafeMutablePointer<TimerEntry> {
        if let e = free {
            free = e.pointee.next
            e.pointee.gen &+= 1
            return e
        }
        // TimerEntry is trivial: zeroed memory is a valid free entry, and
        // only `next` matters until `insert` fills in the rest.
        let chunk = UnsafeMutablePointer<TimerEntry>.allocate(capacity: Self.chunkSize)
        UnsafeMutableRawPointer(chunk).initializeMemory(as: UInt8.self, repeating: 0,
                                                        count: MemoryLayout<TimerEntry>.stride * Self.chunkSize)
        chunks.append(chunk)
        for i in 1..<Self.chunkSize - 1 { chunk[i].next = chunk + i + 1 }
        free = chunk + 1
        chunk.pointee.gen = 1
        return chunk
    }

    /// Return a detached list (linked through `next`) to the free list.
    mutating func recycle(_ head: UnsafeMutablePointer<TimerEntry>, _ tail: UnsafeMutablePointer<TimerEntry>) {
        tail.pointee.next = free
        free = head
    }

    // MARK: linking

    private mutating func link(_ e: UnsafeMutablePointer<TimerEntry>) {
        let level = Self.level(elapsed: elapsed, when: e.pointee.when)
        let slot = Int(truncatingIfNeeded: e.pointee.when &>> UInt64(6 * level)) & 63
        let i = level * 64 + slot
        e.pointee.slot = Int32(i)
        e.pointee.next = nil
        e.pointee.prev = tails[i]
        if let t = tails[i] { t.pointee.next = e } else { heads[i] = e }
        tails[i] = e
        occupied[level] |= 1 &<< UInt64(slot)
    }

    private mutating func unlink(_ e: UnsafeMutablePointer<TimerEntry>) {
        let i = Int(e.pointee.slot)
        if let p = e.pointee.prev { p.pointee.next = e.pointee.next } else { heads[i] = e.pointee.next }
        if let n = e.pointee.next { n.pointee.prev = e.pointee.prev } else { tails[i] = e.pointee.prev }
        if heads[i] == nil { occupied[i / 64] &= ~(1 &<< UInt64(i & 63)) }
        e.pointee.slot = -1
    }

    /// Link a new timer. `when` must be after `elapsed`.
    mutating func insert(when: UInt64, _ action: TimerAction) -> UnsafeMutablePointer<TimerEntry> {
        let e = allocate()
        e.pointee.when = when
        e.pointee.action = action
        link(e)
        count += 1
        return e
    }

    /// Whether `e` is linked in and still the timer handed out as `gen`.
    func isLinked(_ e: UnsafeMutablePointer<TimerEntry>, gen: UInt32) -> Bool {
        e.pointee.slot >= 0 && e.pointee.gen == gen
    }

    /// Unlink a timer and free its entry.
    mutating func remove(_ e: UnsafeMutablePointer<TimerEntry>) {
        unlink(e)
        count -= 1
        e.pointee.next = free
        free = e
    }

    // MARK: expiry

    /// The earliest slot that holds entries: its level, index and the tick
    /// it expires at. Lower levels always expire first.
    func nextExpiration() -> (level: Int, slot: Int, deadline: UInt64)? {
        for level in 0..<Self.levels {
            let occ = occupied[level]
            if occ == 0 { continue }
            let shift = UInt64(6 * level)
            let slotRange: UInt64 = 1 &<< shift
            let levelRange = slotRange &<< 6
            let nowSlot = (elapsed &>> shift) & 63
            // Rotate so the current slot is bit 0: the first set bit is then
            // the first occupied slot from now, wrapping round.
            let rotated = (occ &>> nowSlot) | (occ &<< (64 - nowSlot))
            let slot = (rotated.trailingZeroBitCount + Int(nowSlot)) & 63
            var deadline = (elapsed & ~(levelRange - 1)) + UInt64(slot) * slotRange
            // Only the top level wraps (timers beyond one turn).
            if deadline <= elapsed { deadline += levelRange }
            return (level, slot, deadline)
        }
        return nil
    }

    /// The earliest expiry as an absolute time, or `.max` if empty.
    func nextDeadline(origin: UInt64) -> UInt64 {
        guard let exp = nextExpiration() else { return .max }
        return origin &+ exp.deadline &* TimerWheel.tickNanos
    }

    /// Advance to `now`, unlinking every timer due by then into a list in
    /// deadline order (FIFO among equal deadlines). Timers in a wider slot
    /// that aren't due yet cascade down to a finer level.
    mutating func poll(_ now: UInt64) -> (head: UnsafeMutablePointer<TimerEntry>, tail: UnsafeMutablePointer<TimerEntry>, count: Int)? {
        var head: UnsafeMutablePointer<TimerEntry>? = nil
        var tail: UnsafeMutablePointer<TimerEntry>? = nil
        var n = 0
        while let exp = nextExpiration(), exp.deadline <= now {
            let i = exp.level * 64 + exp.slot
            var e = heads[i]
            heads[i] = nil
            tails[i] = nil
            occupied[exp.level] &= ~(1 &<< UInt64(exp.slot))
            elapsed = exp.deadline
            while let cur = e {
                e = cur.pointee.next
                if cur.pointee.when <= exp.deadline {
                    cur.pointee.slot = -1
                    cur.pointee.next = nil
                    if let t = tail { t.pointee.next = cur } else { head = cur }
                    tail = cur
                    n += 1
                } else {
                    link(cur)
                }
            }
        }
        if now > elapsed { elapsed = now }
        count -= n
        guard let head, let tail else { return nil }
        return (head, tail, n)
    }
}

/// One worker's part of the timers: a wheel behind its own lock, so workers
/// adding timers don't contend. Firing workers check every shard's `next`.
final class TimerShard: @unchecked Sendable {
    let lock = RawLock()
    let wheel = Guarded(Wheel())
    /// `next` is written under the lock on every add and poll, and read by
    /// every busy worker each timer interval: keep it on its own line.
    private let pad = Pad112()
    /// Absolute time of the earliest slot expiry, or `.max` when empty.
    let next = Atomic<UInt64>(.max)
    private let tailPad = Pad112()

    deinit {
        wheel.pointer.pointee.destroy()
        wheel.destroy()
        lock.destroy()
    }
}

/// A linked timer, for removing it later. Trivial to copy; stale once the
/// timer fires or is removed (the entry's generation moves on).
struct TimerHandle: @unchecked Sendable {
    let entry: UnsafeMutablePointer<TimerEntry>
    let gen: UInt32
    let shard: Int
}

/// The runtime's timers: one `TimerShard` per worker. Times are absolute
/// `cv_now_ns()` nanoseconds, rounded *up* to whole milliseconds on insert,
/// so a timer never fires early.
final class TimerWheel: @unchecked Sendable {
    static let tickNanos: UInt64 = 1_000_000

    /// Tick 0.
    let origin: UInt64
    let shardCount: Int
    /// Strong references, for teardown.
    private let owned: [TimerShard]
    /// ARC-free views.
    let shards: UnsafeMutablePointer<Unmanaged<TimerShard>>

    enum Added {
        /// Linked in; `earliest` if it lowered its shard's `next`.
        case inserted(earliest: Bool, TimerHandle)
        /// Already due: the caller fires it now.
        case due
        /// A sleeper cancelled before it got here: nothing linked, the
        /// caller drops the retain.
        case dropped
    }

    init(shards count: Int, origin: UInt64) {
        self.origin = origin
        shardCount = count
        owned = (0..<count).map { _ in TimerShard() }
        shards = .allocate(capacity: count)
        for (i, s) in owned.enumerated() { (shards + i).initialize(to: .passUnretained(s)) }
    }

    deinit { shards.deallocate() }

    @inline(__always) func tick(floor ns: UInt64) -> UInt64 {
        ns > origin ? (ns - origin) / Self.tickNanos : 0
    }

    @inline(__always) func tick(ceiling ns: UInt64) -> UInt64 {
        ns > origin ? (ns - origin - 1) / Self.tickNanos + 1 : 0
    }

    func add(_ action: TimerAction, deadline: UInt64, now: UInt64, shard i: Int) -> Added {
        let when = tick(ceiling: deadline)
        let nowTick = tick(floor: now)
        let shard = shards[i]
        return shard._withUnsafeGuaranteedRef { s in
            let w = s.wheel.pointer
            s.lock.lock()
            defer { s.lock.unlock() }
            if case .waiter(let u) = action, u._withUnsafeGuaranteedRef({ $0.isDone }) {
                // Cancelled between arm and here: cancel found no entry to
                // remove, so don't link one.
                return .dropped
            }
            if when <= nowTick || when <= w.pointee.elapsed { return .due }
            let e = w.pointee.insert(when: when, action)
            if case .waiter(let u) = action {
                u._withUnsafeGuaranteedRef { $0.entry.store(UnsafeMutableRawPointer(e), ordering: .relaxed) }
            }
            let before = s.next.load(ordering: .relaxed)
            let after = w.pointee.nextDeadline(origin: origin)
            let handle = TimerHandle(entry: e, gen: e.pointee.gen, shard: i)
            guard after < before else { return .inserted(earliest: false, handle) }
            s.next.store(after, ordering: .sequentiallyConsistent)
            return .inserted(earliest: true, handle)
        }
    }

    /// Unlink a cancelled sleeper's entry. True if it was still linked: the
    /// caller then owns the retain the wheel held.
    func remove(_ waiter: SleepWaiter) -> Bool {
        shards[waiter.shard]._withUnsafeGuaranteedRef { s in
            let w = s.wheel.pointer
            s.lock.lock()
            defer { s.lock.unlock() }
            guard let raw = waiter.entry.load(ordering: .relaxed) else { return false }
            waiter.entry.store(nil, ordering: .relaxed)
            w.pointee.remove(raw.assumingMemoryBound(to: TimerEntry.self))
            s.next.store(w.pointee.nextDeadline(origin: origin), ordering: .releasing)
            return true
        }
    }

    /// Unlink the timer `handle` names, if it hasn't fired. True if it was
    /// still linked: the caller then owns what its action holds.
    func remove(_ handle: TimerHandle) -> Bool {
        shards[handle.shard]._withUnsafeGuaranteedRef { s in
            let w = s.wheel.pointer
            s.lock.lock()
            defer { s.lock.unlock() }
            guard w.pointee.isLinked(handle.entry, gen: handle.gen) else { return false }
            w.pointee.remove(handle.entry)
            s.next.store(w.pointee.nextDeadline(origin: origin), ordering: .releasing)
            return true
        }
    }

    /// Fire every timer due by `now` in shard `i`, in deadline order: `body`
    /// runs for each, outside the lock. Returns how many fired.
    @inline(__always)
    func fireDue(shard i: Int, now: UInt64, _ body: (TimerAction) -> Void) -> Int {
        shards[i]._withUnsafeGuaranteedRef { s in
            if s.next.load(ordering: .acquiring) > now { return 0 }
            let w = s.wheel.pointer
            s.lock.lock()
            let due = w.pointee.poll(tick(floor: now))
            s.next.store(w.pointee.nextDeadline(origin: origin), ordering: .releasing)
            if let due {
                // Detached now: nobody can cancel these any more.
                var e: UnsafeMutablePointer<TimerEntry>? = due.head
                while let cur = e {
                    if case .waiter(let u) = cur.pointee.action {
                        u._withUnsafeGuaranteedRef { $0.entry.store(nil, ordering: .relaxed) }
                    }
                    e = cur.pointee.next
                }
            }
            s.lock.unlock()
            guard let due else { return 0 }
            var e: UnsafeMutablePointer<TimerEntry>? = due.head
            while let cur = e {
                e = cur.pointee.next
                body(cur.pointee.action)
            }
            s.lock.withLock { w.pointee.recycle(due.head, due.tail) }
            return due.count
        }
    }

    /// The earliest deadline over all shards, or `.max`. Sequentially
    /// consistent: the timer owner's half of the wake protocol (a plain load
    /// on x86 and arm64).
    @inline(__always) func earliest() -> UInt64 {
        var m = UInt64.max
        for i in 0..<shardCount {
            let n = shards[i]._withUnsafeGuaranteedRef { $0.next.load(ordering: .sequentiallyConsistent) }
            if n < m { m = n }
        }
        return m
    }

    /// Nanoseconds until the earliest deadline (0 if overdue), or -1 if none.
    func timeout(now: UInt64) -> Int64 {
        let n = earliest()
        if n == .max { return -1 }
        return n <= now ? 0 : Int64(n - now)
    }

    /// Whether shard `i`'s `next` is no later than any other shard's.
    func isEarliest(_ i: Int) -> Bool {
        let mine = shards[i]._withUnsafeGuaranteedRef { $0.next.load(ordering: .sequentiallyConsistent) }
        for j in 0..<shardCount where j != i {
            if shards[j]._withUnsafeGuaranteedRef({ $0.next.load(ordering: .sequentiallyConsistent) }) < mine {
                return false
            }
        }
        return true
    }

    /// Timers linked in, over all shards (takes every lock: tests only).
    var count: Int {
        var n = 0
        for i in 0..<shardCount {
            n += shards[i]._withUnsafeGuaranteedRef { s in s.lock.withLock { s.wheel.pointer.pointee.count } }
        }
        return n
    }
}

/// One `Runtime.sleep`: resumed by whichever comes first, the timer or
/// cancellation. The state is lock-free: the continuation is written before
/// the armed state is published and read only by whoever wins the exchange
/// to `done`. The wheel entry is guarded by the shard's lock, so a
/// cancelled sleep unlinks its entry at once.
final class SleepWaiter: @unchecked Sendable {
    private static let idle: UInt8 = 0, armed: UInt8 = 1, done: UInt8 = 2

    /// The timer shard this sleep goes into, fixed up front so cancel knows
    /// where to look.
    let shard: Int
    /// The linked wheel entry, or nil. Only touched under the shard's lock;
    /// atomic only to keep exclusivity checks out.
    let entry = Atomic<UnsafeMutableRawPointer?>(nil)
    private let state = Atomic<UInt8>(0)
    private var continuation: UnsafeContinuation<Void, any Error>?

    init(shard: Int) { self.shard = shard }

    var isDone: Bool { state.load(ordering: .acquiring) == Self.done }

    /// Store the continuation; false if it was cancelled before we got here.
    func arm(_ c: UnsafeContinuation<Void, any Error>) -> Bool {
        continuation = c
        return state.compareExchange(expected: Self.idle, desired: Self.armed,
                                     ordering: .acquiringAndReleasing).exchanged
    }

    func fire() {
        if state.exchange(Self.done, ordering: .acquiringAndReleasing) == Self.armed {
            continuation.take()!.resume()
        }
    }

    /// Resume with `CancellationError`. True if the sleep was armed, so its
    /// timer may be linked.
    func cancel() -> Bool {
        if state.exchange(Self.done, ordering: .acquiringAndReleasing) == Self.armed {
            continuation.take()!.resume(throwing: CancellationError())
            return true
        }
        return false
    }
}
