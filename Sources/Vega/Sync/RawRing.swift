/// A growable FIFO ring for use under a lock. Not thread-safe by itself, no
/// class, no ARC of its own: elements are moved in and out, so it works for
/// closures, trivial values and `~Copyable` values. The owner calls `destroy()`.
///
/// Inlinable so that generic users (`Channel`) specialize in client modules.
@usableFromInline
struct RawRing<Element: ~Copyable> {
    @usableFromInline var buffer: UnsafeMutablePointer<Element>
    @usableFromInline var capacity: Int
    @usableFromInline var head = 0
    @usableFromInline var count = 0

    @inlinable
    init(capacity: Int = 16) {
        precondition(capacity > 0 && capacity & (capacity - 1) == 0, "capacity must be a power of two")
        self.capacity = capacity
        buffer = .allocate(capacity: capacity)
    }

    @inlinable var isEmpty: Bool { count == 0 }

    /// The oldest element, in place.
    @inlinable var front: UnsafeMutablePointer<Element>? { count > 0 ? buffer + head : nil }

    @inlinable @inline(__always)
    func slot(_ i: Int) -> UnsafeMutablePointer<Element> {
        buffer + ((head + i) & (capacity - 1))
    }

    @inlinable
    mutating func pushBack(_ x: consuming Element) {
        if count == capacity { grow() }
        slot(count).initialize(to: x)
        count += 1
    }

    @inlinable
    mutating func popFront() -> Element? {
        guard count > 0 else { return nil }
        let x = (buffer + head).move()
        head = (head + 1) & (capacity - 1)
        count -= 1
        return x
    }

    /// Remove and return the first element matching `predicate`, keeping order.
    @inlinable
    mutating func remove(where predicate: (borrowing Element) -> Bool) -> Element? {
        for i in 0..<count where predicate(slot(i).pointee) {
            let x = slot(i).move()
            for j in i..<(count - 1) { slot(j).initialize(to: slot(j + 1).move()) }
            count -= 1
            return x
        }
        return nil
    }

    @inlinable
    mutating func grow() {
        let bigger = UnsafeMutablePointer<Element>.allocate(capacity: capacity * 2)
        for i in 0..<count { (bigger + i).initialize(to: slot(i).move()) }
        buffer.deallocate()
        buffer = bigger
        capacity *= 2
        head = 0
    }

    @inlinable
    mutating func destroy() {
        while popFront() != nil {}
        buffer.deallocate()
    }
}
