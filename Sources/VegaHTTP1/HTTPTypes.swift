import Vega
import VegaIO

/// An HTTP method: a token such as `GET`.
public struct HTTPMethod: RawRepresentable, Hashable, Sendable, CustomStringConvertible, ExpressibleByStringLiteral {
    public let rawValue: String

    public init(rawValue: String) { self.rawValue = rawValue }
    public init(stringLiteral value: String) { rawValue = value }

    public static let get: HTTPMethod = "GET"
    public static let head: HTTPMethod = "HEAD"
    public static let post: HTTPMethod = "POST"
    public static let put: HTTPMethod = "PUT"
    public static let delete: HTTPMethod = "DELETE"
    public static let patch: HTTPMethod = "PATCH"
    public static let options: HTTPMethod = "OPTIONS"
    public static let connect: HTTPMethod = "CONNECT"
    public static let trace: HTTPMethod = "TRACE"

    public var description: String { rawValue }
}

/// An HTTP version. VegaHTTP1 speaks 1.0 and 1.1; VegaHTTP2 marks its
/// messages 2.0.
public struct HTTPVersion: Hashable, Sendable, CustomStringConvertible {
    public var major: Int
    public var minor: Int

    public init(major: Int, minor: Int) {
        self.major = major
        self.minor = minor
    }

    public static let http1_0 = HTTPVersion(major: 1, minor: 0)
    public static let http1_1 = HTTPVersion(major: 1, minor: 1)
    public static let http2 = HTTPVersion(major: 2, minor: 0)

    public var description: String { "HTTP/\(major).\(minor)" }
}

/// A request line and its fields.
public struct HTTPRequestHead: Sendable, Equatable {
    public var method: HTTPMethod
    /// The request target as sent: usually a path and query.
    public var target: String
    public var version: HTTPVersion
    public var fields: HTTPFields

    public init(method: HTTPMethod = .get, target: String, version: HTTPVersion = .http1_1, fields: HTTPFields = [:]) {
        self.method = method
        self.target = target
        self.version = version
        self.fields = fields
    }

    /// The target up to any `?`, still percent-encoded.
    public var path: Substring {
        target.firstIndex(of: "?").map { target[..<$0] } ?? target[...]
    }

    /// The target after the `?`, if there is one.
    public var query: Substring? {
        target.firstIndex(of: "?").map { target[target.index(after: $0)...] }
    }

    /// Whether the connection may carry another request after this one.
    public var keepAlive: Bool { HTTPFields.keepAlive(fields, version) }
}

/// A status line and its fields.
public struct HTTPResponseHead: Sendable, Equatable {
    public var status: Int
    public var reason: String
    public var version: HTTPVersion
    public var fields: HTTPFields

    /// `reason` defaults to the standard phrase for `status`.
    public init(status: Int, reason: String? = nil, version: HTTPVersion = .http1_1, fields: HTTPFields = [:]) {
        self.status = status
        self.reason = reason ?? HTTPResponseHead.reason(status)
        self.version = version
        self.fields = fields
    }

    /// Whether the connection may carry another exchange after this one.
    public var keepAlive: Bool { HTTPFields.keepAlive(fields, version) }

    /// The standard reason phrase for `status`, or "" for one not listed.
    public static func reason(_ status: Int) -> String {
        switch status {
        case 100: "Continue"
        case 101: "Switching Protocols"
        case 103: "Early Hints"
        case 200: "OK"
        case 201: "Created"
        case 202: "Accepted"
        case 203: "Non-Authoritative Information"
        case 204: "No Content"
        case 205: "Reset Content"
        case 206: "Partial Content"
        case 300: "Multiple Choices"
        case 301: "Moved Permanently"
        case 302: "Found"
        case 303: "See Other"
        case 304: "Not Modified"
        case 307: "Temporary Redirect"
        case 308: "Permanent Redirect"
        case 400: "Bad Request"
        case 401: "Unauthorized"
        case 403: "Forbidden"
        case 404: "Not Found"
        case 405: "Method Not Allowed"
        case 406: "Not Acceptable"
        case 408: "Request Timeout"
        case 409: "Conflict"
        case 410: "Gone"
        case 411: "Length Required"
        case 412: "Precondition Failed"
        case 413: "Content Too Large"
        case 414: "URI Too Long"
        case 415: "Unsupported Media Type"
        case 416: "Range Not Satisfiable"
        case 417: "Expectation Failed"
        case 421: "Misdirected Request"
        case 422: "Unprocessable Content"
        case 425: "Too Early"
        case 426: "Upgrade Required"
        case 428: "Precondition Required"
        case 429: "Too Many Requests"
        case 431: "Request Header Fields Too Large"
        case 500: "Internal Server Error"
        case 501: "Not Implemented"
        case 502: "Bad Gateway"
        case 503: "Service Unavailable"
        case 504: "Gateway Timeout"
        case 505: "HTTP Version Not Supported"
        default: ""
        }
    }
}

/// One piece of a message as it streams: the head, body bytes (any number
/// of times), then the end with any trailer fields. NIO's `HTTPPart`.
public enum HTTPPart<Head: Sendable & Equatable>: Sendable, Equatable {
    case head(Head)
    case body([UInt8])
    case end(HTTPFields?)
}

public typealias HTTPRequestPart = HTTPPart<HTTPRequestHead>
public typealias HTTPResponsePart = HTTPPart<HTTPResponseHead>

/// Why a message couldn't be read or written.
public enum HTTP1Error: Error, Sendable, Hashable, CustomStringConvertible {
    case badRequestLine
    case badStatusLine
    /// Not HTTP/1.0 or 1.1.
    case badVersion
    /// A malformed field line, including whitespace before the colon, a
    /// folded line, or a control character in a value.
    case badHeader
    case uriTooLong
    case headTooLarge
    case tooManyFields
    /// Content-Length with Transfer-Encoding, Content-Lengths that disagree,
    /// or a Transfer-Encoding that doesn't end in chunked: how requests are
    /// smuggled past a proxy, so always refused.
    case conflictingFraming
    /// A transfer coding other than chunked.
    case unsupportedTransferEncoding
    /// An HTTP/1.1 request without a Host field.
    case missingHost
    /// More than one Host field.
    case duplicateHost
    case badChunk
    case bodyTooLarge
    /// The stream ended inside a message.
    case truncated
    /// A field name or value that can't be sent: a character that would
    /// end the field early, or a name that isn't a token.
    case invalidField
    /// Body bytes for a message that can't have any (a HEAD response, 204,
    /// 304, or a request sent without framing).
    case bodyNotAllowed
    /// More or fewer body bytes than the Content-Length said.
    case contentLengthMismatch
    /// An HTTP/1.0 request with a body but no Content-Length.
    case lengthRequired
    /// The connection failed.
    case io(IOError)

    /// The status to answer a request that failed this way with.
    public var status: Int {
        switch self {
        case .uriTooLong: 414
        case .headTooLarge, .tooManyFields: 431
        case .badVersion: 505
        case .unsupportedTransferEncoding: 501
        case .bodyTooLarge: 413
        case .lengthRequired: 411
        case .io, .invalidField, .bodyNotAllowed, .contentLengthMismatch: 500
        default: 400
        }
    }

    public var description: String {
        switch self {
        case .badRequestLine: "bad request line"
        case .badStatusLine: "bad status line"
        case .badVersion: "unsupported HTTP version"
        case .badHeader: "bad field line"
        case .uriTooLong: "request target too long"
        case .headTooLarge: "head too large"
        case .tooManyFields: "too many fields"
        case .conflictingFraming: "conflicting message framing"
        case .unsupportedTransferEncoding: "unsupported transfer coding"
        case .missingHost: "no Host field"
        case .duplicateHost: "more than one Host field"
        case .badChunk: "bad chunk"
        case .bodyTooLarge: "body too large"
        case .truncated: "stream ended inside a message"
        case .invalidField: "field can't be sent"
        case .bodyNotAllowed: "body not allowed"
        case .contentLengthMismatch: "body length differs from Content-Length"
        case .lengthRequired: "body needs a Content-Length"
        case .io(let e): "\(e)"
        }
    }

    var codecError: CodecError {
        self == .truncated ? .truncated(0) : .malformed(description)
    }
}
