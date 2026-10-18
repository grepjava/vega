/// Why a channel operation that waits gave up.
///
/// A struct rather than an enum, so that kinds of failure can be added
/// without breaking anyone's exhaustive `switch`: switch over `code`, or
/// compare the error itself where its kind carries nothing more
/// (`catch ChannelError.closed`, `error == .closed`).
public struct ChannelError: Error, Hashable, Sendable, CustomStringConvertible {
    /// What kind of failure this is.
    public let code: Code

    /// The kinds of `ChannelError`.
    public struct Code: Hashable, Sendable, CustomStringConvertible {
        let rawValue: UInt8

        /// The other side is gone: every sender dropped (and the buffer is
        /// drained), or the receiver dropped or closed the channel.
        public static let closed = Code(rawValue: 0)
        /// The waiting task was cancelled. The channel is still usable.
        public static let cancelled = Code(rawValue: 1)

        public var description: String {
            let names = ["closed", "cancelled"]
            return Int(rawValue) < names.count ? names[Int(rawValue)] : "code \(rawValue)"
        }
    }

    init(_ code: Code) {
        self.code = code
    }

    /// The other side is gone: every sender dropped (and the buffer is
    /// drained), or the receiver dropped or closed the channel.
    public static let closed = ChannelError(.closed)
    /// The waiting task was cancelled. The channel is still usable.
    public static let cancelled = ChannelError(.cancelled)

    public var description: String {
        switch code {
        case .closed: "closed"
        case .cancelled: "cancelled"
        default: "\(code)"
        }
    }
}

/// Why `trySend` failed.
///
/// A struct rather than an enum, so that kinds of failure can be added
/// without breaking anyone's exhaustive `switch`: switch over `code`, or
/// compare the error itself where its kind carries nothing more
/// (`catch TrySendError.full`, `error == .full`).
public struct TrySendError: Error, Hashable, Sendable, CustomStringConvertible {
    /// What kind of failure this is.
    public let code: Code

    /// The kinds of `TrySendError`.
    public struct Code: Hashable, Sendable, CustomStringConvertible {
        let rawValue: UInt8

        /// No room in a bounded channel.
        public static let full = Code(rawValue: 0)
        /// The receiver is gone or closed the channel.
        public static let closed = Code(rawValue: 1)

        public var description: String {
            let names = ["full", "closed"]
            return Int(rawValue) < names.count ? names[Int(rawValue)] : "code \(rawValue)"
        }
    }

    init(_ code: Code) {
        self.code = code
    }

    /// No room in a bounded channel.
    public static let full = TrySendError(.full)
    /// The receiver is gone or closed the channel.
    public static let closed = TrySendError(.closed)

    public var description: String {
        switch code {
        case .full: "full"
        case .closed: "closed"
        default: "\(code)"
        }
    }
}

/// Why `tryReceive` failed.
///
/// A struct rather than an enum, so that kinds of failure can be added
/// without breaking anyone's exhaustive `switch`: switch over `code`, or
/// compare the error itself where its kind carries nothing more
/// (`catch TryReceiveError.empty`, `error == .empty`).
public struct TryReceiveError: Error, Hashable, Sendable, CustomStringConvertible {
    /// What kind of failure this is.
    public let code: Code

    /// The kinds of `TryReceiveError`.
    public struct Code: Hashable, Sendable, CustomStringConvertible {
        let rawValue: UInt8

        /// Nothing buffered right now.
        public static let empty = Code(rawValue: 0)
        /// Nothing buffered, and nothing ever will be: every sender dropped.
        public static let closed = Code(rawValue: 1)

        public var description: String {
            let names = ["empty", "closed"]
            return Int(rawValue) < names.count ? names[Int(rawValue)] : "code \(rawValue)"
        }
    }

    init(_ code: Code) {
        self.code = code
    }

    /// Nothing buffered right now.
    public static let empty = TryReceiveError(.empty)
    /// Nothing buffered, and nothing ever will be: every sender dropped.
    public static let closed = TryReceiveError(.closed)

    public var description: String {
        switch code {
        case .empty: "empty"
        case .closed: "closed"
        default: "\(code)"
        }
    }
}

/// Why `Semaphore.acquire` failed.
///
/// A struct rather than an enum, so that kinds of failure can be added
/// without breaking anyone's exhaustive `switch`: switch over `code`, or
/// compare the error itself where its kind carries nothing more
/// (`catch AcquireError.closed`, `error == .closed`).
public struct AcquireError: Error, Hashable, Sendable, CustomStringConvertible {
    /// What kind of failure this is.
    public let code: Code

    /// The kinds of `AcquireError`.
    public struct Code: Hashable, Sendable, CustomStringConvertible {
        let rawValue: UInt8

        /// The semaphore was closed.
        public static let closed = Code(rawValue: 0)
        /// The waiting task was cancelled. Permits it had been handed while
        /// queued went back to the semaphore.
        public static let cancelled = Code(rawValue: 1)
        /// `acquire(_:timeout:)` waited its whole timeout. Permits it had been
        /// handed while queued went back to the semaphore.
        public static let timedOut = Code(rawValue: 2)

        public var description: String {
            let names = ["closed", "cancelled", "timedOut"]
            return Int(rawValue) < names.count ? names[Int(rawValue)] : "code \(rawValue)"
        }
    }

    init(_ code: Code) {
        self.code = code
    }

    /// The semaphore was closed.
    public static let closed = AcquireError(.closed)
    /// The waiting task was cancelled. Permits it had been handed while
    /// queued went back to the semaphore.
    public static let cancelled = AcquireError(.cancelled)
    /// `acquire(_:timeout:)` waited its whole timeout. Permits it had been
    /// handed while queued went back to the semaphore.
    public static let timedOut = AcquireError(.timedOut)

    public var description: String {
        switch code {
        case .closed: "closed"
        case .cancelled: "cancelled"
        case .timedOut: "timed out"
        default: "\(code)"
        }
    }
}
