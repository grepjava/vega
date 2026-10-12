import Synchronization

/// What a timer does when it fires. Trivially copyable: no ARC in the heap.
enum TimerAction: @unchecked Sendable {
    /// A job handed over by Swift (`Task.sleep` via `SchedulingExecutor`).
    case job(UnownedJob)
    /// A task parked in `Runtime.sleep`. The heap holds one retain, which
    /// `fire` consumes.
    case waiter(Unmanaged<SleepWaiter>)
}

/// Jobs and sleepers waiting for a deadline. A binary min-heap behind a lock,
/// with the earliest deadline mirrored in an atomic so the common "nothing
/// due" check is one load. Phase 2 replaces this with a per-worker timing wheel.
final class TimerQueue: @unchecked Sendable {
    struct Entry {
        var deadline: UInt64
        var seq: UInt64 // FIFO among equal deadlines
        var action: TimerAction
        @inline(__always) func before(_ o: Entry) -> Bool {
            deadline != o.deadline ? deadline < o.deadline : seq < o.seq
        }
    }

    /// A min-heap in raw memory.
    struct Heap {
        var items: UnsafeMutablePointer<Entry>
        var capacity: Int
        var count = 0
        var seq: UInt64 = 0

        init() {
            capacity = 256
            items = .allocate(capacity: capacity)
        }

        mutating func push(_ e: Entry) {
            if count == capacity {
                let bigger = UnsafeMutablePointer<Entry>.allocate(capacity: capacity * 2)
                bigger.moveInitialize(from: items, count: count)
                items.deallocate()
                items = bigger
                capacity *= 2
            }
            var i = count
            count += 1
            while i > 0 {
                let p = (i - 1) / 2
                if !e.before(items[p]) { break }
                (items + i).initialize(to: items[p])
                i = p
            }
            (items + i).initialize(to: e)
        }

        mutating func pop() -> Entry {
            let top = items[0]
            count -= 1
            if count > 0 {
                let last = items[count]
                var i = 0
                while true {
                    let l = 2 * i + 1, r = l + 1
                    var m = l
                    if l >= count { break }
                    if r < count && items[r].before(items[l]) { m = r }
                    if !items[m].before(last) { break }
                    items[i] = items[m]
                    i = m
                }
                items[i] = last
            }
            return top
        }
    }

    private let lock = RawLock()
    private let heap = Guarded(Heap())
    /// Earliest deadline, or `.max` when empty.
    let next = Atomic<UInt64>(.max)

    deinit {
        heap.pointer.pointee.items.deallocate()
        heap.destroy()
        lock.destroy()
    }

    /// Returns true if this is now the earliest deadline.
    func add(_ action: TimerAction, deadline: UInt64) -> Bool {
        let h = heap.pointer
        return lock.withLock {
            h.pointee.seq &+= 1
            h.pointee.push(Entry(deadline: deadline, seq: h.pointee.seq, action: action))
            let earliest = h.pointee.items[0].deadline
            next.store(earliest, ordering: .sequentiallyConsistent)
            return earliest == deadline
        }
    }

    func popDue(now: UInt64) -> TimerAction? {
        if next.load(ordering: .acquiring) > now { return nil }
        let h = heap.pointer
        return lock.withLock {
            guard h.pointee.count > 0, h.pointee.items[0].deadline <= now else { return nil }
            let e = h.pointee.pop()
            next.store(h.pointee.count > 0 ? h.pointee.items[0].deadline : .max, ordering: .releasing)
            return e.action
        }
    }

    /// Nanoseconds until the earliest deadline (0 if overdue), or -1 if none.
    func timeout(now: UInt64) -> Int64 {
        let n = next.load(ordering: .sequentiallyConsistent)
        if n == .max { return -1 }
        return n <= now ? 0 : Int64(n - now)
    }
}

/// One `Runtime.sleep`: resumed by whichever comes first, the timer or
/// cancellation. Lock-free: the continuation is written before the armed state
/// is published and read only by whoever wins the exchange to `done`.
/// A cancelled sleeper's heap entry stays until its deadline and then does
/// nothing (the timing wheel will unlink it in O(1) instead).
final class SleepWaiter: @unchecked Sendable {
    private static let idle: UInt8 = 0, armed: UInt8 = 1, done: UInt8 = 2

    private let state = Atomic<UInt8>(0)
    private var continuation: UnsafeContinuation<Void, any Error>?

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

    func cancel() {
        if state.exchange(Self.done, ordering: .acquiringAndReleasing) == Self.armed {
            continuation.take()!.resume(throwing: CancellationError())
        }
    }
}
