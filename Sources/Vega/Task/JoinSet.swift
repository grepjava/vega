import CVega

/// A set of spawned tasks whose results come back in the order they finish,
/// as Tokio's `JoinSet`.
///
/// Unlike a `TaskGroup` it isn't tied to a scope: it can be stored, passed
/// along and added to from anywhere. Dropping it cancels the tasks still in
/// it.
///
/// ```swift
/// let set = JoinSet<Int, IOError>()
/// for host in hosts { set.spawn { try await probe(host) } }
/// while let result = await set.next() { ... }
/// ```
///
/// - `next()` serves one waiter at a time.
/// - Cancelling a task is cooperative, as for any Swift task: it still ends
///   with whatever its closure returns or throws, which `next()` gives.
public final class JoinSet<Success: Sendable, Failure: Error>: @unchecked Sendable {
    private struct State {
        /// The tasks still running, by id, for cancelling them.
        var running: [Int: Task<Void, Never>] = [:]
        /// Tasks that finished before `spawn` had stored their handle.
        var finishedEarly: Set<Int> = []
        var live = 0
        var nextID = 0
        var results = RawRing<Result<Success, Failure>>(capacity: 8)
        var waiter: UnsafeContinuation<Result<Success, Failure>?, Never>?
        var cancelled = false
    }

    private let runtime: Runtime?
    private let lock = RawLock()
    private let state = Guarded(State())

    /// - Parameter runtime: where the tasks run; by default the runtime
    ///   running the caller of `spawn`, as `Runtime.spawn` picks.
    public init(runtime: Runtime? = nil) {
        self.runtime = runtime
    }

    deinit {
        for task in state.pointer.pointee.running.values { task.cancel() }
        state.pointer.pointee.results.destroy()
        state.destroy()
        lock.destroy()
    }

    /// Tasks spawned whose results haven't been taken with `next()` yet.
    public var count: Int {
        lock.withLock { state.pointer.pointee.live + state.pointer.pointee.results.count }
    }

    public var isEmpty: Bool { count == 0 }

    /// Spawn `operation` into the set. After `cancelAll()`, it starts
    /// cancelled.
    public func spawn(priority: TaskPriority? = nil,
                      _ operation: sending @escaping () async throws(Failure) -> Success) {
        let s = state.pointer
        let (id, cancelled) = lock.withLock { () -> (Int, Bool) in
            s.pointee.nextID += 1
            s.pointee.live += 1
            return (s.pointee.nextID, s.pointee.cancelled)
        }
        // Weakly: a task must not keep a dropped set alive, or dropping it
        // wouldn't cancel.
        let body = { [weak self] () async -> Void in
            let result: Result<Success, Failure>
            do throws(Failure) {
                result = .success(try await operation())
            } catch {
                result = .failure(error)
            }
            self?.finish(id, result)
        }
        let task = if let runtime {
            runtime.spawn(priority: priority, body)
        } else {
            Runtime.spawn(priority: priority, body)
        }
        let early = lock.withLock { () -> Bool in
            if s.pointee.finishedEarly.remove(id) != nil { return true }
            s.pointee.running[id] = task
            return false
        }
        if cancelled && !early { task.cancel() }
    }

    /// The next result, in the order the tasks finish; nil when the set is
    /// empty, or when the task waiting is cancelled (results not yet taken
    /// stay in the set).
    public func next() async -> Result<Success, Failure>? {
        let s = state.pointer
        let result = await withTaskCancellationHandler {
            await withUnsafeContinuation { (c: UnsafeContinuation<Result<Success, Failure>?, Never>) in
                let now = lock.withLock { () -> (ready: Bool, result: Result<Success, Failure>?) in
                    if let r = s.pointee.results.popFront() { return (true, r) }
                    if s.pointee.live == 0 || Task.isCancelled { return (true, nil) }
                    precondition(s.pointee.waiter == nil, "JoinSet.next() called while another call waits")
                    s.pointee.waiter = c
                    return (false, nil)
                }
                if now.ready { c.resume(returning: now.result) }
            }
        } onCancel: {
            let waiter = lock.withLock { () -> UnsafeContinuation<Result<Success, Failure>?, Never>? in
                let s = state.pointer
                defer { s.pointee.waiter = nil }
                return s.pointee.waiter
            }
            waiter?.resume(returning: nil)
        }
        // finish can resume us before we suspend; see cv_tsan_acquire.
        cv_tsan_acquire(cv_task_current())
        return result
    }

    /// The next result's value, rethrowing its error; nil as for `next()`.
    public func nextValue() async throws(Failure) -> Success? {
        try await next()?.get()
    }

    /// Cancel every task in the set, and any spawned into it from now on.
    public func cancelAll() {
        let tasks = lock.withLock { () -> [Task<Void, Never>] in
            state.pointer.pointee.cancelled = true
            return Array(state.pointer.pointee.running.values)
        }
        for task in tasks { task.cancel() }
    }

    /// Cancel every task and wait for them all to end, dropping their
    /// results. The set is empty afterwards, and takes new tasks uncancelled.
    public func shutdown() async {
        cancelAll()
        while await next() != nil {}
        lock.withLock { state.pointer.pointee.cancelled = false }
    }

    private func finish(_ id: Int, _ result: Result<Success, Failure>) {
        let s = state.pointer
        let waiter = lock.withLock { () -> UnsafeContinuation<Result<Success, Failure>?, Never>? in
            if s.pointee.running.removeValue(forKey: id) == nil { s.pointee.finishedEarly.insert(id) }
            s.pointee.live -= 1
            if let w = s.pointee.waiter {
                s.pointee.waiter = nil
                return w
            }
            s.pointee.results.pushBack(result)
            return nil
        }
        waiter?.resume(returning: result)
    }
}
