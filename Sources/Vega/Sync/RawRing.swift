/// A growable FIFO ring for use under a lock. Not thread-safe by itself, no
/// class, no ARC of its own: elements are moved in and out, so it works for
/// closures as well as trivial values. The owner calls `destroy()`.
struct RawRing<Element> {
    private(set) var buffer: UnsafeMutablePointer<Element>
    private(set) var capacity: Int
    private(set) var head = 0
    private(set) var count = 0

    init(capacity: Int = 16) {
        precondition(capacity > 0 && capacity & (capacity - 1) == 0, "capacity must be a power of two")
        self.capacity = capacity
        buffer = .allocate(capacity: capacity)
    }

    var isEmpty: Bool { count == 0 }

    @inline(__always) private func slot(_ i: Int) -> UnsafeMutablePointer<Element> {
        buffer + ((head + i) & (capacity - 1))
    }

    mutating func pushBack(_ x: consuming Element) {
        if count == capacity { grow() }
        slot(count).initialize(to: x)
        count += 1
    }

    mutating func popFront() -> Element? {
        guard count > 0 else { return nil }
        let x = (buffer + head).move()
        head = (head + 1) & (capacity - 1)
        count -= 1
        return x
    }

    /// Remove and return the first element matching `predicate`, keeping order.
    mutating func remove(where predicate: (borrowing Element) -> Bool) -> Element? {
        for i in 0..<count where predicate(slot(i).pointee) {
            let x = slot(i).move()
            for j in i..<(count - 1) { slot(j).initialize(to: slot(j + 1).move()) }
            count -= 1
            return x
        }
        return nil
    }

    private mutating func grow() {
        let bigger = UnsafeMutablePointer<Element>.allocate(capacity: capacity * 2)
        for i in 0..<count { (bigger + i).initialize(to: slot(i).move()) }
        buffer.deallocate()
        buffer = bigger
        capacity *= 2
        head = 0
    }

    mutating func destroy() {
        while popFront() != nil {}
        buffer.deallocate()
    }
}
