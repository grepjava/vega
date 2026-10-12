import Synchronization

/// The shared queue for jobs enqueued from outside a worker thread, and for a
/// local queue's overflow. A growable ring behind a lock; `count` lets workers
/// skip the lock when it is empty.
final class InjectQueue: @unchecked Sendable {
    struct Ring {
        var buffer: UnsafeMutablePointer<UnownedJob>
        var capacity: Int
        var head = 0
        var count = 0

        init(capacity: Int) {
            self.capacity = capacity
            buffer = .allocate(capacity: capacity)
        }

        @inline(__always) mutating func push(_ job: UnownedJob) {
            if count == capacity { grow() }
            (buffer + ((head + count) & (capacity - 1))).initialize(to: job)
            count += 1
        }

        @inline(__always) mutating func pop() -> UnownedJob? {
            guard count > 0 else { return nil }
            let job = buffer[head]
            head = (head + 1) & (capacity - 1)
            count -= 1
            return job
        }

        private mutating func grow() {
            let bigger = UnsafeMutablePointer<UnownedJob>.allocate(capacity: capacity * 2)
            for i in 0..<count {
                (bigger + i).initialize(to: buffer[(head + i) & (capacity - 1)])
            }
            buffer.deallocate()
            buffer = bigger
            capacity *= 2
            head = 0
        }
    }

    private let lock = RawLock()
    private let ring = Guarded(Ring(capacity: 1024))
    let count = Atomic<Int>(0)

    deinit {
        ring.pointer.pointee.buffer.deallocate()
        ring.destroy()
        lock.destroy()
    }

    var isEmpty: Bool { count.load(ordering: .sequentiallyConsistent) == 0 }

    func push(_ job: UnownedJob) {
        let r = ring.pointer
        lock.withLock {
            r.pointee.push(job)
            count.add(1, ordering: .sequentiallyConsistent)
        }
    }

    /// Push `n + 1` jobs produced by `job(0...n)` under one lock.
    func pushBatch(_ n: UInt32, _ job: (UInt32) -> UnownedJob) {
        let r = ring.pointer
        lock.withLock {
            for i in 0...n { r.pointee.push(job(i)) }
            count.add(Int(n) + 1, ordering: .sequentiallyConsistent)
        }
    }

    func pop() -> UnownedJob? {
        if isEmpty { return nil }
        let r = ring.pointer
        return lock.withLock {
            let job = r.pointee.pop()
            if job != nil { count.subtract(1, ordering: .sequentiallyConsistent) }
            return job
        }
    }

    /// Take a fair share for one of `workers` workers: return one job and move
    /// the rest into `local`, which must be empty and owned by the caller.
    func popBatch(into local: LocalQueue, workers: Int) -> UnownedJob? {
        if isEmpty { return nil }
        let r = ring.pointer
        return lock.withLock {
            guard let first = r.pointee.pop() else { return nil }
            let share = min(r.pointee.count / workers + 1, Int(LocalQueue.capacity / 2))
            var moved = 1
            while moved < share, let job = r.pointee.pop() {
                local.pushUnchecked(job)
                moved += 1
            }
            count.subtract(moved, ordering: .sequentiallyConsistent)
            return first
        }
    }
}
