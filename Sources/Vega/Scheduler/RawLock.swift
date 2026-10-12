import CVega

/// A handle to a C mutex. Trivial to copy (no ARC); whoever creates it calls
/// `destroy()`.
@usableFromInline
struct RawLock: @unchecked Sendable {
    @usableFromInline let handle: UnsafeMutablePointer<cv_lock>

    @inlinable init() { handle = cv_lock_new() }

    @inlinable func destroy() { cv_lock_free(handle) }

    @inlinable @inline(__always) func lock() { cv_lock_lock(handle) }
    @inlinable @inline(__always) func unlock() { cv_lock_unlock(handle) }

    @inlinable @inline(__always)
    func withLock<R: ~Copyable, E: Error>(_ body: () throws(E) -> R) throws(E) -> R {
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
