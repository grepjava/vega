import Vega

extension Runtime {
    /// A current-thread runtime that runs its tasks in an order drawn from
    /// `seed`, for tests: each time it picks the next job, it picks at
    /// random among all those ready, not the oldest. Its clock is paused
    /// and moves on by itself when everything waits on a timer, as
    /// `MockClock` does.
    ///
    /// The same seed gives the same interleaving of the tasks, as long as
    /// what wakes them is in the runtime: its timers, its sync primitives,
    /// VegaTest's in-memory streams. Real I/O, `blocking` threads and other
    /// threads wake them when they happen to. ``Simulation`` runs a test
    /// under many seeds, and names the one that fails.
    public static func seeded(_ seed: UInt64, name: String = "vega-seeded") -> Runtime {
        makeSeeded(seed, name: name)
    }

    /// The seed of a ``seeded(_:name:)`` runtime; nil for any other.
    public var seed: UInt64? { schedulerSeed }
}
