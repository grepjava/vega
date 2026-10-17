import CVega

/// A handle to a C mutex. Trivial to copy (no ARC); whoever creates it calls
/// `destroy()`. ThreadSanitizer sees it, as it doesn't `Synchronization`'s
/// `Mutex` on Linux: the package's other modules use it where TSan runs.
@usableFromInline
package struct RawLock: @unchecked Sendable {
    @usableFromInline let handle: UnsafeMutablePointer<cv_lock>

    @inlinable package init() { handle = cv_lock_new() }

    @inlinable package func destroy() { cv_lock_free(handle) }

    @inlinable @inline(__always) package func lock() { cv_lock_lock(handle) }
    @inlinable @inline(__always) package func unlock() { cv_lock_unlock(handle) }

    @inlinable @inline(__always)
    package func withLock<R: ~Copyable, E: Error>(_ body: () throws(E) -> R) throws(E) -> R {
        cv_lock_lock(handle)
        defer { cv_lock_unlock(handle) }
        return try body()
    }
}

/// Raw storage for one value that a `RawLock` guards: accessed through a
/// pointer, so no class exclusivity checks and no retain/release.
struct Guarded<Value>: @unchecked Sendable {
    let pointer: UnsafeMutablePointer<Value>

    init(_ value: Value) {
        pointer = .allocate(capacity: 1)
        pointer.initialize(to: value)
    }

    func destroy() {
        pointer.deinitialize(count: 1)
        pointer.deallocate()
    }
}

/// A value behind a `RawLock`, with `Mutex`'s `withLock`: for the package's
/// other modules, where ThreadSanitizer must see the lock (it doesn't see
/// `Synchronization.Mutex` on Linux, and reports what it guards as racing).
package final class Locked<Value>: @unchecked Sendable {
    private let lock = RawLock()
    private var value: Value

    package init(_ value: Value) {
        self.value = value
    }

    deinit { lock.destroy() }

    package func withLock<R, E: Error>(_ body: (inout Value) throws(E) -> R) throws(E) -> R {
        lock.lock()
        defer { lock.unlock() }
        return try body(&value)
    }
}
