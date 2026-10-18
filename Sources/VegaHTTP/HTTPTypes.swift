import VegaWire

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
    public static let http3 = HTTPVersion(major: 3, minor: 0)

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

/// A request with its whole body.
public struct HTTPRequest: Sendable, Equatable {
    public var head: HTTPRequestHead
    public var body: [UInt8]

    public init(head: HTTPRequestHead, body: [UInt8] = []) {
        self.head = head
        self.body = body
    }

    public init(method: HTTPMethod = .get, target: String, fields: HTTPFields = [:], body: [UInt8] = []) {
        self.init(head: HTTPRequestHead(method: method, target: target, fields: fields), body: body)
    }
}

/// A response with its whole body.
public struct HTTPResponse: Sendable, Equatable {
    public var head: HTTPResponseHead
    public var body: [UInt8]

    public init(head: HTTPResponseHead, body: [UInt8] = []) {
        self.head = head
        self.body = body
    }

    public init(status: Int = 200, fields: HTTPFields = [:], body: [UInt8] = []) {
        self.init(head: HTTPResponseHead(status: status, fields: fields), body: body)
    }

    public init(status: Int = 200, fields: HTTPFields = [:], body: String) {
        self.init(status: status, fields: fields, body: Array(body.utf8))
    }

    public var status: Int { head.status }
    /// The body as UTF-8 text.
    public var text: String { String(decoding: body, as: UTF8.self) }
}
