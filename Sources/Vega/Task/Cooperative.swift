/// Something to do once the job running now has returned: see
/// `Runtime.afterJob(_:)`.
public protocol JobEndAction: AnyObject, Sendable {
    /// The job that asked has returned. Runs on the worker that ran it,
    /// outside any task: start a task for anything that waits.
    func jobEnded()
}

extension Runtime {
    /// Call `action.jobEnded()` once the job running now has returned: when
    /// the calling task next suspends or finishes, on this worker, before
    /// it runs anything else. For work that is only needed if the task stops
    /// part-way -- bytes a handler queued and then went off to wait on
    /// something else -- and costs a task to do: asked for here, it costs
    /// nothing when the task carries on and does it itself. The action is
    /// held until it has run. False off a Vega worker, and when the worker
    /// is holding as many actions as it has room for: then do the work
    /// another way.
    public static func afterJob(_ action: some JobEndAction) -> Bool {
        guard let w = Worker.current else { return false }
        return w._withUnsafeGuaranteedRef { $0.afterJob(action) }
    }

    /// Let other tasks run: the caller goes to the back of its worker's queue.
    ///
    /// Cheaper than `Task.yield()`, which asks Swift for the current executor
    /// (a retain of a shared object on every call) and in global mode wraps
    /// the task in an extra job. This parks the continuation on the worker
    /// and resumes it as soon as the task's job has returned. Off a Vega
    /// worker it falls back to `Task.yield()`.
    public static func yield() async {
        guard let w = Worker.current else {
            await Task.yield()
            return
        }
        await withUnsafeContinuation { (c: UnsafeContinuation<Void, Never>) in
            w._withUnsafeGuaranteedRef { $0.deferYield(c) }
        }
    }

    /// Let other tasks run, then carry on on whichever of the runtime's
    /// workers takes the caller first: it goes to the runtime's shared queue
    /// rather than to the back of its own worker's, as `yield` sends it.
    ///
    /// For a task that should not stay where it is: one about to compute for
    /// long on a core where another such task already runs
    /// (`Runtime.currentCore`), say. It can come back to the same worker,
    /// so a caller that must move checks again and repeats. Off a Vega
    /// worker it falls back to `Task.yield()`.
    public static func yieldToAnyWorker() async {
        guard let w = Worker.current else {
            await Task.yield()
            return
        }
        await withUnsafeContinuation { (c: UnsafeContinuation<Void, Never>) in
            w._withUnsafeGuaranteedRef { $0.deferYield(c, toAnyWorker: true) }
        }
    }

    /// Spend one unit of the running task's cooperative budget, yielding when
    /// it runs out (Tokio's coop budget: 128 per poll).
    ///
    /// Swift can't preempt a task, so a loop that always finds work ready
    /// (a socket with data waiting, a full channel) would keep its worker
    /// forever. Vega's own primitives call this on their ready paths; call
    /// it from your own tight loops.
    @inline(__always)
    public static func consumeBudget() async {
        if spendBudget() { await yieldSpent() }
    }

    /// `consumeBudget`'s synchronous part: spend a unit, and say whether
    /// the budget ran out, so the caller must call `yieldSpent`.
    @inline(__always)
    static func spendBudget() -> Bool {
        guard let w = Worker.current else { return false }
        return w._withUnsafeGuaranteedRef { worker -> Bool in
            worker.budget -= 1
            return worker.budget <= 0
        }
    }

    /// The yield of a task whose budget ran out.
    @usableFromInline
    static func yieldSpent() async {
        if let w = Worker.current {
            w._withUnsafeGuaranteedRef { $0.forcedYields.store($0.forcedYields.load(ordering: .relaxed) &+ 1,
                                                               ordering: .relaxed) }
        }
        await yield()
    }
}
