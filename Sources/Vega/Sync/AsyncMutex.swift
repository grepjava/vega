/// A lock held across `await`: Tokio's `Mutex`. Tasks waiting for it
/// suspend instead of blocking their thread, and get it in arrival order.
///
/// ```swift
/// let counts = AsyncMutex([String: Int]())
/// try await counts.withLock { $0[key, default: 0] += 1 }
/// ```
///
/// Use it only when the critical section awaits. For short sections that
/// don't, `Synchronization.Mutex` is cheaper: nothing suspends.
///
/// Built on a one-permit `Semaphore`, so uncontended locking is one CAS.
public final class AsyncMutex<Value: ~Copyable>: @unchecked Sendable {
    private let permit = Semaphore(permits: 1)
    private let value: UnsafeMutablePointer<Value>

    public init(_ value: consuming sending Value) {
        self.value = .allocate(capacity: 1)
        self.value.initialize(to: value)
    }

    deinit {
        value.deinitialize(count: 1)
        value.deallocate()
    }

    /// Run `body` with the lock held, waiting for it first. Throws
    /// `AcquireError.cancelled` if the task is cancelled while waiting (the
    /// lock is not taken), or whatever `body` throws (the lock is released).
    public func withLock<R: ~Copyable>(_ body: (inout Value) async throws -> R) async throws -> R {
        try await permit.acquire()
        defer { permit.release() }
        return try await body(&value.pointee)
    }

    /// Run `body` with the lock held if it is free now; nil if it isn't.
    public func tryWithLock<R, E: Error>(_ body: (inout Value) throws(E) -> R) throws(E) -> R? {
        guard permit.tryAcquire() else { return nil }
        defer { permit.release() }
        return try body(&value.pointee)
    }
}

/// A reader-writer lock held across `await`: Tokio's `RwLock`. Any number
/// of readers, or one writer. Fair: a writer waits only for the readers
/// ahead of it, and readers that arrive after it wait for it.
///
/// ```swift
/// let config = AsyncRWLock(Config.defaults)
/// let port = try await config.withReadLock { $0.port }
/// try await config.withWriteLock { $0.port = 8080 }
/// ```
///
/// Built on a `Semaphore`: a reader takes one permit, a writer all of them.
public final class AsyncRWLock<Value: ~Copyable>: @unchecked Sendable {
    /// Most readers at once (Tokio's `MAX_READS`).
    public static var maxReaders: Int { Int(UInt32.max >> 3) }

    private let permits = Semaphore(permits: AsyncRWLock.maxReaders)
    private let value: UnsafeMutablePointer<Value>

    public init(_ value: consuming sending Value) {
        self.value = .allocate(capacity: 1)
        self.value.initialize(to: value)
    }

    deinit {
        value.deinitialize(count: 1)
        value.deallocate()
    }

    /// Run `body` with shared access. Throws `AcquireError.cancelled` if
    /// cancelled while waiting, or whatever `body` throws.
    public func withReadLock<R: ~Copyable>(_ body: (borrowing Value) async throws -> R) async throws -> R {
        try await permits.acquire(1)
        defer { permits.release(1) }
        return try await body(value.pointee)
    }

    /// Run `body` with exclusive access. Throws `AcquireError.cancelled` if
    /// cancelled while waiting, or whatever `body` throws.
    public func withWriteLock<R: ~Copyable>(_ body: (inout Value) async throws -> R) async throws -> R {
        try await permits.acquire(AsyncRWLock.maxReaders)
        defer { permits.release(AsyncRWLock.maxReaders) }
        return try await body(&value.pointee)
    }

    /// `withReadLock` if no writer holds or waits for the lock; else nil.
    public func tryWithReadLock<R, E: Error>(_ body: (borrowing Value) throws(E) -> R) throws(E) -> R? {
        guard permits.tryAcquire(1) else { return nil }
        defer { permits.release(1) }
        return try body(value.pointee)
    }

    /// `withWriteLock` if the lock is free now; else nil.
    public func tryWithWriteLock<R, E: Error>(_ body: (inout Value) throws(E) -> R) throws(E) -> R? {
        guard permits.tryAcquire(AsyncRWLock.maxReaders) else { return nil }
        defer { permits.release(AsyncRWLock.maxReaders) }
        return try body(&value.pointee)
    }
}
