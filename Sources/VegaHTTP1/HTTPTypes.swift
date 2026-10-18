import Vega
import VegaIO
@_spi(Garuda) import VegaHTTP1Core
@_exported import VegaHTTP

/// One piece of a message as it streams: the head, body bytes (any number
/// of times), then the end with any trailer fields. NIO's `HTTPPart`.
public enum HTTPPart<Head: Sendable & Equatable>: Sendable, Equatable {
    case head(Head)
    case body([UInt8])
    case end(HTTPFields?)
}

public typealias HTTPRequestPart = HTTPPart<HTTPRequestHead>
public typealias HTTPResponsePart = HTTPPart<HTTPResponseHead>

/// Why an HTTP/1 message couldn't be read or written.
///
/// A struct rather than an enum, so that kinds of failure can be added
/// without breaking anyone's exhaustive `switch`: switch over `code`, or
/// compare the error itself where its kind carries nothing more
/// (`catch HTTP1Error.badRequestLine`, `error == .badRequestLine`).
public struct HTTP1Error: Error, Hashable, Sendable, CustomStringConvertible {
    /// What kind of failure this is.
    public let code: Code
    public let ioError: IOError?

    /// The kinds of `HTTP1Error`.
    public struct Code: Hashable, Sendable, CustomStringConvertible {
        let rawValue: UInt8

        public static let badRequestLine = Code(rawValue: 0)
        public static let badStatusLine = Code(rawValue: 1)
        /// Not HTTP/1.0 or 1.1.
        public static let badVersion = Code(rawValue: 2)
        /// A malformed field line, including whitespace before the colon, a
        /// folded line, or a control character in a value.
        public static let badHeader = Code(rawValue: 3)
        public static let uriTooLong = Code(rawValue: 4)
        public static let headTooLarge = Code(rawValue: 5)
        public static let tooManyFields = Code(rawValue: 6)
        /// Content-Length with Transfer-Encoding, Content-Lengths that disagree,
        /// or a Transfer-Encoding that doesn't end in chunked: how requests are
        /// smuggled past a proxy, so always refused.
        public static let conflictingFraming = Code(rawValue: 7)
        /// A transfer coding other than chunked.
        public static let unsupportedTransferEncoding = Code(rawValue: 8)
        /// An HTTP/1.1 request without a Host field.
        public static let missingHost = Code(rawValue: 9)
        /// More than one Host field.
        public static let duplicateHost = Code(rawValue: 10)
        public static let badChunk = Code(rawValue: 11)
        public static let bodyTooLarge = Code(rawValue: 12)
        /// The stream ended inside a message.
        public static let truncated = Code(rawValue: 13)
        /// A field name or value that can't be sent: a character that would
        /// end the field early, or a name that isn't a token.
        public static let invalidField = Code(rawValue: 14)
        /// Body bytes for a message that can't have any (a HEAD response, 204,
        /// 304, or a request sent without framing).
        public static let bodyNotAllowed = Code(rawValue: 15)
        /// More or fewer body bytes than the Content-Length said.
        public static let contentLengthMismatch = Code(rawValue: 16)
        /// An HTTP/1.0 request with a body but no Content-Length.
        public static let lengthRequired = Code(rawValue: 17)
        /// The connection failed.
        public static let io = Code(rawValue: 18)

        public var description: String {
            let names = ["badRequestLine", "badStatusLine", "badVersion", "badHeader", "uriTooLong", "headTooLarge", "tooManyFields", "conflictingFraming", "unsupportedTransferEncoding", "missingHost", "duplicateHost", "badChunk", "bodyTooLarge", "truncated", "invalidField", "bodyNotAllowed", "contentLengthMismatch", "lengthRequired", "io"]
            return Int(rawValue) < names.count ? names[Int(rawValue)] : "code \(rawValue)"
        }
    }

    init(_ code: Code, ioError: IOError? = nil) {
        self.code = code
        self.ioError = ioError
    }

    public static let badRequestLine = HTTP1Error(.badRequestLine)
    public static let badStatusLine = HTTP1Error(.badStatusLine)
    /// Not HTTP/1.0 or 1.1.
    public static let badVersion = HTTP1Error(.badVersion)
    /// A malformed field line, including whitespace before the colon, a
    /// folded line, or a control character in a value.
    public static let badHeader = HTTP1Error(.badHeader)
    public static let uriTooLong = HTTP1Error(.uriTooLong)
    public static let headTooLarge = HTTP1Error(.headTooLarge)
    public static let tooManyFields = HTTP1Error(.tooManyFields)
    /// Content-Length with Transfer-Encoding, Content-Lengths that disagree,
    /// or a Transfer-Encoding that doesn't end in chunked: how requests are
    /// smuggled past a proxy, so always refused.
    public static let conflictingFraming = HTTP1Error(.conflictingFraming)
    /// A transfer coding other than chunked.
    public static let unsupportedTransferEncoding = HTTP1Error(.unsupportedTransferEncoding)
    /// An HTTP/1.1 request without a Host field.
    public static let missingHost = HTTP1Error(.missingHost)
    /// More than one Host field.
    public static let duplicateHost = HTTP1Error(.duplicateHost)
    public static let badChunk = HTTP1Error(.badChunk)
    public static let bodyTooLarge = HTTP1Error(.bodyTooLarge)
    /// The stream ended inside a message.
    public static let truncated = HTTP1Error(.truncated)
    /// A field name or value that can't be sent: a character that would
    /// end the field early, or a name that isn't a token.
    public static let invalidField = HTTP1Error(.invalidField)
    /// Body bytes for a message that can't have any (a HEAD response, 204,
    /// 304, or a request sent without framing).
    public static let bodyNotAllowed = HTTP1Error(.bodyNotAllowed)
    /// More or fewer body bytes than the Content-Length said.
    public static let contentLengthMismatch = HTTP1Error(.contentLengthMismatch)
    /// An HTTP/1.0 request with a body but no Content-Length.
    public static let lengthRequired = HTTP1Error(.lengthRequired)
    /// The connection failed.
    public static func io(_ ioError: IOError) -> HTTP1Error { HTTP1Error(.io, ioError: ioError) }

    public var description: String {
        switch code {
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
        case .io: "\(ioError!)"
        default: "\(code)"
        }
    }

    /// The status to answer a request that failed this way with.
    public var status: Int {
        switch code {
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

    init(_ error: HTTP1ParseError) {
        let code: Code = switch error {
        case .badRequestLine: .badRequestLine
        case .badStatusLine: .badStatusLine
        case .badVersion: .badVersion
        case .badHeader: .badHeader
        case .headTooLarge: .headTooLarge
        case .tooManyFields: .tooManyFields
        case .conflictingFraming: .conflictingFraming
        case .unsupportedTransferEncoding: .unsupportedTransferEncoding
        case .missingHost: .missingHost
        case .duplicateHost: .duplicateHost
        case .badChunk: .badChunk
        }
        self.init(code)
    }

    var codecError: CodecError {
        code == .truncated ? .truncated(0) : .malformed(description)
    }
}
