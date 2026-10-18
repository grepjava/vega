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

    init(_ error: HTTP1ParseError) {
        self = switch error {
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
    }

    var codecError: CodecError {
        self == .truncated ? .truncated(0) : .malformed(description)
    }
}
