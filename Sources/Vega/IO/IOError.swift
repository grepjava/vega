#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// An I/O failure: an `errno` value, or one of Vega's own conditions,
/// optionally with a message saying more (a TLS failure's reason).
///
/// Two plain integers, so throwing one costs no reference counting: a
/// message is interned once and carried as its index. Equality and hashing
/// look at `code` only.
public struct IOError: Error, Hashable, CustomStringConvertible {
    /// A positive `errno` value, or a negative Vega code.
    public let code: Int32
    /// 0, or 1 + the index of the message in `Messages`.
    private let detail: UInt32

    public init(code: Int32) {
        self.code = code
        detail = 0
    }

    /// With a message, such as the TLS library's reason. Messages are kept
    /// for the life of the process, so they should come from a bounded set
    /// (no peer-supplied text).
    public init(code: Int32, message: String) {
        self.code = code
        detail = Messages.intern(message)
    }

    /// The message given when this error was made, if any.
    public var message: String? { detail == 0 ? nil : Messages.lookup(detail) }

    /// The task was cancelled while waiting. Only that operation was
    /// abandoned; the socket is still usable.
    public static let cancelled = IOError(code: -1)
    /// The call needs a Vega runtime: make it from a task running on one.
    public static let notOnRuntime = IOError(code: -2)
    /// No I/O driver on this platform yet.
    public static let unsupported = IOError(code: -3)
    /// A TLS handshake or record failed: `message` says why.
    public static let tls = IOError(code: -4)
    /// The peer closed the connection without a TLS close_notify, so the
    /// data may have been cut short.
    public static let tlsTruncated = IOError(code: -5)

    /// A `Runtime.withIODeadline` deadline passed while waiting (or a
    /// connect timed out). As with `cancelled`, that operation was abandoned.
    public static let timedOut = IOError(code: ETIMEDOUT)
    public static let connectionReset = IOError(code: ECONNRESET)
    public static let brokenPipe = IOError(code: EPIPE)
    public static let connectionRefused = IOError(code: ECONNREFUSED)

    public static func == (a: IOError, b: IOError) -> Bool { a.code == b.code }

    public func hash(into hasher: inout Hasher) { hasher.combine(code) }

    public var description: String {
        let base: String
        switch code {
        case -1: base = "cancelled"
        case -2: base = "not on a Vega runtime"
        case -3: base = "no I/O driver on this platform"
        case -4: base = "TLS failure"
        case -5: base = "connection closed without TLS close_notify"
        default: base = "\(String(cString: strerror(code))) (errno \(code))"
        }
        guard let message else { return base }
        return "\(base): \(message)"
    }
}

/// Interned error messages.
private enum Messages {
    static let lock = RawLock()
    nonisolated(unsafe) static var list: [String] = []
    nonisolated(unsafe) static var index: [String: UInt32] = [:]

    static func intern(_ message: String) -> UInt32 {
        lock.withLock {
            if let i = index[message] { return i }
            list.append(message)
            let i = UInt32(list.count)
            index[message] = i
            return i
        }
    }

    static func lookup(_ detail: UInt32) -> String {
        lock.withLock { list[Int(detail) - 1] }
    }
}
