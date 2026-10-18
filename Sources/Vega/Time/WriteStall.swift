import CVega

extension Runtime {
    /// Run `body` with a bound on how long its socket writes may stall: a
    /// write that waits `limit` for room without the peer taking any of
    /// what it sends gives up and throws `IOError.timedOut`. A peer that
    /// reads, however slowly, keeps the write going.
    ///
    /// ```swift
    /// try await Runtime.withWriteStallTimeout(for: .seconds(30)) {
    ///     try await stream.write(response)
    /// }
    /// ```
    ///
    /// Where `withIOTimeout` bounds the whole of an operation and costs a
    /// timer for every scope, this costs nothing until a write finds the
    /// socket full: only then does that one wait get a deadline. So it can
    /// go around every write, where nearly all of them go out at once. A
    /// wait inside a `withIOTimeout` scope keeps that deadline instead.
    /// Only the calling task's writes are bounded, as with `withIOTimeout`.
    @inlinable
    public static func withWriteStallTimeout<T: ~Copyable, E: Error>(
        for limit: Duration,
        _ body: () async throws(E) -> T
    ) async throws(E) -> T {
        // Inlined, so the body is specialized at the call; a task Vega runs
        // sets the limit on its hook, and needs nothing more.
        let scope = WriteStallScope(limit)
        defer { scope.end() }
        if scope.onHook { return try await body() }
        return try await scope.bind(body)
    }
}

/// One `withWriteStallTimeout` scope: the limit set on the task's I/O hook,
/// and the one it replaced.
@usableFromInline
struct WriteStallScope {
    /// The task's I/O hook, unretained: its task-local holds it.
    private let hook: Unmanaged<IOTaskHook>?
    private let previous: UInt64
    private let nanos: UInt64
    /// The limit is on the task's hook: `bind` is not needed.
    @usableFromInline let onHook: Bool

    @usableFromInline init(_ limit: Duration) {
        let nanos = UInt64(clamping: max(1, Scheduler.nanoseconds(limit)))
        self.nanos = nanos
        let hook = IOTaskHook.activeUnmanaged
        self.hook = hook
        previous = hook?._withUnsafeGuaranteedRef { h in
            defer { h.writeStall = nanos }
            return h.writeStall
        } ?? 0
        onHook = hook != nil
    }

    @usableFromInline func end() {
        hook?._withUnsafeGuaranteedRef { $0.writeStall = previous }
    }

    /// `body` with the limit bound as a task-local, for a task without a
    /// hook. Marked with the task, so that its child tasks, which inherit
    /// task-locals, do not take it for theirs.
    @usableFromInline
    func bind<T: ~Copyable, E: Error>(_ body: () async throws(E) -> T) async throws(E) -> T {
        // TaskLocal.withValue neither takes typed throws nor ~Copyable
        // results.
        var result: Result<T, E>? = nil
        let binding = WriteStall(nanos: nanos, owner: UInt(bitPattern: cv_task_current()))
        await WriteStall.current.withValue(binding, operation: { () async -> Void in
            do throws(E) {
                result = .success(try await body())
            } catch {
                result = .failure(error)
            }
        })
        switch result.take()! {
        case .success(let value): return value
        case .failure(let error): throw error
        }
    }
}

/// A `withWriteStallTimeout` limit bound as a task-local, for a task
/// without an `IOTaskHook`.
struct WriteStall: Sendable {
    let nanos: UInt64
    /// The task that set it.
    let owner: UInt

    static let current = TaskLocal<WriteStall?>(wrappedValue: nil)

    /// The running task's stall limit in nanoseconds, if it set one.
    @inline(__always) static var active: UInt64? {
        if let hook = IOTaskHook.active {
            let nanos = hook.writeStall
            return nanos == 0 ? nil : nanos
        }
        guard let bound = current.get(), bound.owner == UInt(bitPattern: cv_task_current()) else { return nil }
        return bound.nanos
    }
}
