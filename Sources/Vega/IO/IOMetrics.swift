/// What the I/O driver has done since the runtime started.
public struct IOMetrics: Sendable, Equatable {
    /// Polls by a parked worker, blocking until an event or a wake.
    public var parkedPolls: UInt64 = 0
    /// Zero-timeout polls by busy workers (every 61 scheduler ticks).
    public var busyPolls: UInt64 = 0
    /// Readiness events the kernel returned.
    public var events: UInt64 = 0
    /// Waiting tasks resumed by those events.
    public var wakes: UInt64 = 0
    /// Polls that filled the whole event batch, leaving events for the next.
    public var fullBatches: UInt64 = 0

    public init() {}

    init(parkedPolls: UInt64, busyPolls: UInt64, events: UInt64, wakes: UInt64, fullBatches: UInt64) {
        self.parkedPolls = parkedPolls
        self.busyPolls = busyPolls
        self.events = events
        self.wakes = wakes
        self.fullBatches = fullBatches
    }
}
