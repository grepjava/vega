@_spi(Garuda) import VegaWire
//===----------------------------------------------------------------------===//
// HTTP/2 framing (RFC 9113).
//
// Frames are a nine-octet header and a payload. Nothing here owns memory or
// interprets a payload; it is the wire format and the constants, so that the
// connection layer can stay about state rather than byte offsets.
//===----------------------------------------------------------------------===//


@_spi(Garuda) public enum HTTP2FrameType: UInt8 {
    case data = 0x0
    case headers = 0x1
    case priority = 0x2
    case rstStream = 0x3
    case settings = 0x4
    case pushPromise = 0x5
    case ping = 0x6
    case goaway = 0x7
    case windowUpdate = 0x8
    case continuation = 0x9
}

@_spi(Garuda) public struct HTTP2Flags: OptionSet, Sendable {
    public let rawValue: UInt8
    @inlinable public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// DATA, HEADERS.
    public static let endStream  = HTTP2Flags(rawValue: 0x1)
    /// SETTINGS, PING.
    public static let ack        = HTTP2Flags(rawValue: 0x1)
    /// HEADERS, PUSH_PROMISE, CONTINUATION.
    public static let endHeaders = HTTP2Flags(rawValue: 0x4)
    /// DATA, HEADERS, PUSH_PROMISE.
    public static let padded     = HTTP2Flags(rawValue: 0x8)
    /// HEADERS.
    public static let priority   = HTTP2Flags(rawValue: 0x20)
}

/// An HTTP/2 error code (RFC 9113 section 7).
public struct HTTP2ErrorCode: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let noError = HTTP2ErrorCode(rawValue: 0x0)
    public static let protocolError = HTTP2ErrorCode(rawValue: 0x1)
    public static let internalError = HTTP2ErrorCode(rawValue: 0x2)
    public static let flowControlError = HTTP2ErrorCode(rawValue: 0x3)
    public static let settingsTimeout = HTTP2ErrorCode(rawValue: 0x4)
    public static let streamClosed = HTTP2ErrorCode(rawValue: 0x5)
    public static let frameSizeError = HTTP2ErrorCode(rawValue: 0x6)
    public static let refusedStream = HTTP2ErrorCode(rawValue: 0x7)
    public static let cancel = HTTP2ErrorCode(rawValue: 0x8)
    public static let compressionError = HTTP2ErrorCode(rawValue: 0x9)
    public static let connectError = HTTP2ErrorCode(rawValue: 0xa)
    public static let enhanceYourCalm = HTTP2ErrorCode(rawValue: 0xb)
    public static let inadequateSecurity = HTTP2ErrorCode(rawValue: 0xc)
    public static let http11Required = HTTP2ErrorCode(rawValue: 0xd)

    public var description: String {
        let names = ["NO_ERROR", "PROTOCOL_ERROR", "INTERNAL_ERROR", "FLOW_CONTROL_ERROR", "SETTINGS_TIMEOUT",
                     "STREAM_CLOSED", "FRAME_SIZE_ERROR", "REFUSED_STREAM", "CANCEL", "COMPRESSION_ERROR",
                     "CONNECT_ERROR", "ENHANCE_YOUR_CALM", "INADEQUATE_SECURITY", "HTTP_1_1_REQUIRED"]
        return rawValue < names.count ? names[Int(rawValue)] : "error 0x\(String(rawValue, radix: 16))"
    }
}

/// A SETTINGS parameter (RFC 9113 section 6.5.2).
public struct HTTP2Setting: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let headerTableSize = HTTP2Setting(rawValue: 0x1)
    public static let enablePush = HTTP2Setting(rawValue: 0x2)
    public static let maxConcurrentStreams = HTTP2Setting(rawValue: 0x3)
    public static let initialWindowSize = HTTP2Setting(rawValue: 0x4)
    public static let maxFrameSize = HTTP2Setting(rawValue: 0x5)
    public static let maxHeaderListSize = HTTP2Setting(rawValue: 0x6)
    /// RFC 8441: extended CONNECT, which carries WebSockets over HTTP/2.
    /// RFC 8441, the extended CONNECT protocol that carries WebSockets -- and,
    /// with RFC 9220, WebTransport -- over HTTP/2.
    public static let enableConnectProtocol = HTTP2Setting(rawValue: 0x8)
}

@_spi(Garuda) public struct HTTP2FrameHeader {
    public var length: Int
    public var type: UInt8
    public var flags: HTTP2Flags
    public var streamID: UInt32

    public static let size = 9
    /// Every implementation must accept at least this much; it is also the
    /// default until SETTINGS says otherwise.
    public static let defaultMaxFrameSize = 16384
    public static let defaultInitialWindowSize = 65535
    public static let maxWindowSize = 0x7FFF_FFFF

    public init(length: Int, type: HTTP2FrameType, flags: HTTP2Flags, streamID: UInt32) {
        self.length = length
        self.type = type.rawValue
        self.flags = flags
        self.streamID = streamID
    }

    public init(length: Int, rawType: UInt8, flags: HTTP2Flags, streamID: UInt32) {
        self.length = length
        self.type = rawType
        self.flags = flags
        self.streamID = streamID
    }

    /// Reads a header from at least nine readable bytes.
    @inlinable
    public static func parse(_ p: UnsafePointer<UInt8>) -> HTTP2FrameHeader {
        let length = (Int(p[0]) << 16) | (Int(p[1]) << 8) | Int(p[2])
        // The reserved high bit of the stream identifier is ignored, not
        // rejected: RFC 9113 section 5.1.1.
        let id = (UInt32(p[5] & 0x7F) << 24) | (UInt32(p[6]) << 16)
               | (UInt32(p[7]) << 8) | UInt32(p[8])
        return HTTP2FrameHeader(length: length, rawType: p[3],
                             flags: HTTP2Flags(rawValue: p[4]), streamID: id)
    }

    @inlinable
    public func write(into out: inout ByteBuffer) {
        out.reserve(HTTP2FrameHeader.size)
        let p = out.writePointer
        p[0] = UInt8(truncatingIfNeeded: length >> 16)
        p[1] = UInt8(truncatingIfNeeded: length >> 8)
        p[2] = UInt8(truncatingIfNeeded: length)
        p[3] = type
        p[4] = flags.rawValue
        p[5] = UInt8(truncatingIfNeeded: streamID >> 24) & 0x7F
        p[6] = UInt8(truncatingIfNeeded: streamID >> 16)
        p[7] = UInt8(truncatingIfNeeded: streamID >> 8)
        p[8] = UInt8(truncatingIfNeeded: streamID)
        out.advanceWriter(HTTP2FrameHeader.size)
    }
}

@_spi(Garuda) public enum HTTP2 {
    /// The client connection preface, RFC 9113 section 3.4.
    public static let preface: [UInt8] = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    /// Whether `n` bytes at `p` could still become the preface.
    public static func prefaceMatches(_ p: UnsafePointer<UInt8>, _ n: Int) -> Bool {
        var i = 0
        while i < n && i < preface.count {
            if p[i] != preface[i] { return false }
            i += 1
        }
        return true
    }

    @inlinable
    public static func readUInt32(_ p: UnsafePointer<UInt8>) -> UInt32 {
        (UInt32(p[0]) << 24) | (UInt32(p[1]) << 16) | (UInt32(p[2]) << 8) | UInt32(p[3])
    }

    @inlinable
    public static func writeUInt32(_ v: UInt32, into out: inout ByteBuffer) {
        out.reserve(4)
        let p = out.writePointer
        p[0] = UInt8(truncatingIfNeeded: v >> 24)
        p[1] = UInt8(truncatingIfNeeded: v >> 16)
        p[2] = UInt8(truncatingIfNeeded: v >> 8)
        p[3] = UInt8(truncatingIfNeeded: v)
        out.advanceWriter(4)
    }

    /// A header name is valid in HTTP/2 only if it is lowercase and a token.
    /// RFC 9113 section 8.2.1 makes anything else malformed.
    public static func validFieldName(_ p: UnsafePointer<UInt8>, _ n: Int) -> Bool {
        if n == 0 { return false }
        var i = 0
        while i < n {
            let c = p[i]
            switch c {
            case 0x41...0x5A: return false            // uppercase
            case 0x30...0x39, 0x61...0x7A: break      // digits, lowercase
            case 0x21, 0x23...0x27, 0x2A, 0x2B, 0x2D, 0x2E,
                 0x5E, 0x5F, 0x60, 0x7C, 0x7E: break  // remaining tchar
            default: return false
            }
            i += 1
        }
        return true
    }

    /// Field values may not contain NUL, CR or LF, and may not be padded with
    /// spaces or tabs: those are the header-injection shapes.
    public static func validFieldValue(_ p: UnsafePointer<UInt8>, _ n: Int) -> Bool {
        if n == 0 { return true }
        if p[0] == 0x20 || p[0] == 0x09 { return false }
        if p[n - 1] == 0x20 || p[n - 1] == 0x09 { return false }
        var i = 0
        while i < n {
            let c = p[i]
            if c == 0x00 || c == 0x0A || c == 0x0D { return false }
            i += 1
        }
        return true
    }

    /// Headers that describe a connection rather than a message, and so have no
    /// meaning in HTTP/2. RFC 9113 section 8.2.2 makes their presence malformed.
    public static func isConnectionSpecific(_ p: UnsafePointer<UInt8>, _ n: Int) -> Bool {
        switch n {
        case 2: return equalsLowercased(p, n, "te")   // only "trailers" is legal
        case 7: return equalsLowercased(p, n, "upgrade")
        case 10: return equalsLowercased(p, n, "connection") || equalsLowercased(p, n, "keep-alive")
        case 16: return equalsLowercased(p, n, "proxy-connection")
        case 17: return equalsLowercased(p, n, "transfer-encoding")
        default: return false
        }
    }
}
