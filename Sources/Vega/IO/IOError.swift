#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// An I/O failure: an `errno` value, or one of Vega's own conditions.
public struct IOError: Error, Hashable, CustomStringConvertible {
    /// A positive `errno` value, or a negative Vega code.
    public let code: Int32

    public init(code: Int32) { self.code = code }

    /// The task was cancelled while waiting. Only that operation was
    /// abandoned; the socket is still usable.
    public static let cancelled = IOError(code: -1)
    /// The call needs a Vega runtime: make it from a task running on one.
    public static let notOnRuntime = IOError(code: -2)
    /// No I/O driver on this platform yet.
    public static let unsupported = IOError(code: -3)

    public static let connectionReset = IOError(code: ECONNRESET)
    public static let brokenPipe = IOError(code: EPIPE)
    public static let connectionRefused = IOError(code: ECONNREFUSED)

    public var description: String {
        switch code {
        case -1: return "cancelled"
        case -2: return "not on a Vega runtime"
        case -3: return "no I/O driver on this platform"
        default: return "\(String(cString: strerror(code))) (errno \(code))"
        }
    }
}
