extension Runtime {
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

    /// Spend one unit of the running task's cooperative budget, yielding when
    /// it runs out (Tokio's coop budget: 128 per poll).
    ///
    /// Swift can't preempt a task, so a loop that always finds work ready
    /// (a socket with data waiting, a full channel) would keep its worker
    /// forever. Vega's own primitives call this on their ready paths; call
    /// it from your own tight loops.
    @inline(__always)
    public static func consumeBudget() async {
        guard let w = Worker.current else { return }
        let exhausted = w._withUnsafeGuaranteedRef { worker -> Bool in
            worker.budget -= 1
            return worker.budget <= 0
        }
        if exhausted {
            w._withUnsafeGuaranteedRef { $0.forcedYields.store($0.forcedYields.load(ordering: .relaxed) &+ 1,
                                                               ordering: .relaxed) }
            await yield()
        }
    }
}
