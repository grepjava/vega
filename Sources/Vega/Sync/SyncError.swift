/// Why a channel operation that waits gave up.
public enum ChannelError: Error, Sendable, Hashable {
    /// The other side is gone: every sender dropped (and the buffer is
    /// drained), or the receiver dropped or closed the channel.
    case closed
    /// The waiting task was cancelled. The channel is still usable.
    case cancelled
}

/// Why `trySend` failed.
public enum TrySendError: Error, Sendable, Hashable {
    /// No room in a bounded channel.
    case full
    /// The receiver is gone or closed the channel.
    case closed
}

/// Why `tryReceive` failed.
public enum TryReceiveError: Error, Sendable, Hashable {
    /// Nothing buffered right now.
    case empty
    /// Nothing buffered, and nothing ever will be: every sender dropped.
    case closed
}

/// Why `Semaphore.acquire` failed.
public enum AcquireError: Error, Sendable, Hashable {
    /// The semaphore was closed.
    case closed
    /// The waiting task was cancelled. Permits it had been handed while
    /// queued went back to the semaphore.
    case cancelled
}
