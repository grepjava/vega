import CVega
import Synchronization

/// Runs short closures on a pool of long-lived Swift tasks, so starting one is
/// a queue push instead of creating and destroying a Swift `Task`.
///
/// Creating a task is the most expensive thing Swift concurrency does: a
/// large allocation that the worker finishing it frees again, a preference
/// record, status-record locking. For work that is started very often (a
/// handler per request, a closure per message) the pool keeps that off the
/// hot path: the closure runs inside a pooled task that then picks up the
/// next one.
///
/// Differences from `spawn`:
/// - Fire and forget: there is no handle. Use `Notify`, a channel or a
///   counter to learn about completion.
/// - The closure runs in a pooled task, so it does not see the spawner's
///   task-locals or priority, and cancelling the spawner doesn't cancel it.
/// - A closure that suspends holds its pooled task meanwhile; the pool grows
///   (up to `maxTasks`) when work arrives and no pooled task is idle. Past
///   that bound work queues, so closures that wait on *other pooled
///   closures* must not outnumber `maxTasks`.
public final class TaskPool: @unchecked Sendable {
    public typealias Work = @Sendable () async -> Void

    private struct State {
        var pending = RawRing<Work>(capacity: 64)
        var idle = RawRing<UnsafeContinuation<Work?, Never>>(capacity: 64)
        var live = 0
        var closed = false
    }

    private let runtime: Runtime
    private let maxTasks: Int
    private let lock = RawLock()
    private let state = Guarded(State())

    /// - Parameter maxTasks: upper bound on pooled tasks; defaults to 64 per worker.
    public init(runtime: Runtime, maxTasks: Int? = nil) {
        self.runtime = runtime
        self.maxTasks = max(1, maxTasks ?? runtime.workerCount * 64)
    }

    deinit {
        state.pointer.pointee.pending.destroy()
        state.pointer.pointee.idle.destroy()
        state.destroy()
        lock.destroy()
    }

    /// Pooled tasks alive now.
    public var taskCount: Int { lock.withLock { state.pointer.pointee.live } }

    /// Run `work` on a pooled task.
    public func spawn(_ work: @escaping Work) {
        let s = state.pointer
        var idle: UnsafeContinuation<Work?, Never>? = nil
        var grow = false
        lock.withLock {
            precondition(!s.pointee.closed, "TaskPool.spawn after close()")
            if let c = s.pointee.idle.popFront() {
                idle = c
                return
            }
            s.pointee.pending.pushBack(work)
            // No pooled task is idle: every one is running or suspended in a
            // closure. Grow, or queued work could wait on a closure that is
            // itself waiting for it. Bounded by maxTasks, so a burst creates
            // at most that many tasks; after that they are reused.
            if s.pointee.live < maxTasks {
                s.pointee.live += 1
                grow = true
            }
        }
        if let idle {
            idle.resume(returning: work)
        } else if grow {
            Task(executorPreference: runtime.scheduler) { await IOTaskHook.run { await self.loop() } }
        }
    }

    /// Let idle pooled tasks finish. Work already queued still runs; `spawn`
    /// afterwards is an error.
    public func close() {
        let s = state.pointer
        var idle = lock.withLock { () -> RawRing<UnsafeContinuation<Work?, Never>> in
            s.pointee.closed = true
            let all = s.pointee.idle
            s.pointee.idle = RawRing(capacity: 1)
            return all
        }
        while let c = idle.popFront() { c.resume(returning: nil) }
        idle.destroy()
    }

    private func loop() async {
        let s = state.pointer
        while true {
            // Drain queued work without suspending.
            while let work = lock.withLock({ s.pointee.pending.popFront() }) {
                await work()
            }
            let next = await withUnsafeContinuation { (c: UnsafeContinuation<Work?, Never>) in
                let resume = lock.withLock { () -> (hand: Bool, work: Work?) in
                    if let work = s.pointee.pending.popFront() { return (true, work) }
                    if s.pointee.closed { return (true, nil) }
                    s.pointee.idle.pushBack(c)
                    return (false, nil)
                }
                if resume.hand { c.resume(returning: resume.work) }
            }
            // spawn can resume us before we suspend; see cv_tsan_acquire.
            cv_tsan_acquire(cv_task_current())
            guard let next else { break }
            await next()
        }
        lock.withLock { s.pointee.live -= 1 }
    }
}
