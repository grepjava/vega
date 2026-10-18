import CVegaCompress
import Vega
import VegaIO
@_spi(Garuda) import VegaWire
import VegaHTTP1
@_spi(Garuda) import VegaWebSocketCore

/// A whole message: fragments are joined before it's handed on.
public enum WebSocketMessage: Sendable, Equatable {
    case text(String)
    case binary([UInt8])
}

/// Why a WebSocket operation failed.
///
/// A struct rather than an enum, so that kinds of failure can be added
/// without breaking anyone's exhaustive `switch`: switch over `code`, or
/// compare the error itself where its kind carries nothing more
/// (`catch WebSocketError.connectionLost`, `error == .connectionLost`).
public struct WebSocketError: Error, Hashable, Sendable, CustomStringConvertible {
    /// What kind of failure this is.
    public let code: Code
    public let closeCode: WebSocketCloseCode?
    public let message: String?
    public let ioError: IOError?

    /// The kinds of `WebSocketError`.
    public struct Code: Hashable, Sendable, CustomStringConvertible {
        let rawValue: UInt8

        /// The peer broke the protocol; this end sent a close frame with
        /// `closeCode` (1002 protocol error, 1007 bad UTF-8, 1009 too big).
        public static let protocolViolation = Code(rawValue: 0)
        /// The opening handshake failed: `message` says why.
        public static let handshake = Code(rawValue: 1)
        /// The connection ended without a close frame.
        public static let connectionLost = Code(rawValue: 2)
        /// This end has already sent its close frame.
        public static let closed = Code(rawValue: 3)
        /// `close` was given `closeCode`, which may not be sent (1005, 1006,
        /// 1015 and the unassigned ones).
        public static let invalidCloseCode = Code(rawValue: 4)
        /// The connection failed.
        public static let io = Code(rawValue: 5)

        public var description: String {
            let names = ["protocolViolation", "handshake", "connectionLost", "closed", "invalidCloseCode", "io"]
            return Int(rawValue) < names.count ? names[Int(rawValue)] : "code \(rawValue)"
        }
    }

    init(_ code: Code, closeCode: WebSocketCloseCode? = nil, message: String? = nil, ioError: IOError? = nil) {
        self.code = code
        self.closeCode = closeCode
        self.message = message
        self.ioError = ioError
    }

    /// The peer broke the protocol; this end sent a close frame with
    /// `closeCode` (1002 protocol error, 1007 bad UTF-8, 1009 too big).
    public static func protocolViolation(_ closeCode: WebSocketCloseCode) -> WebSocketError { WebSocketError(.protocolViolation, closeCode: closeCode) }
    /// The opening handshake failed: `message` says why.
    public static func handshake(_ message: String) -> WebSocketError { WebSocketError(.handshake, message: message) }
    /// The connection ended without a close frame.
    public static let connectionLost = WebSocketError(.connectionLost)
    /// This end has already sent its close frame.
    public static let closed = WebSocketError(.closed)
    /// `close` was given `closeCode`, which may not be sent (1005, 1006,
    /// 1015 and the unassigned ones).
    public static func invalidCloseCode(_ closeCode: WebSocketCloseCode) -> WebSocketError { WebSocketError(.invalidCloseCode, closeCode: closeCode) }
    /// The connection failed.
    public static func io(_ ioError: IOError) -> WebSocketError { WebSocketError(.io, ioError: ioError) }

    public var description: String {
        switch code {
        case .protocolViolation: "protocol violation (closed with \(closeCode!))"
        case .handshake: "handshake failed: \(message ?? "")"
        case .connectionLost: "connection lost without a close frame"
        case .closed: "already closed"
        case .invalidCloseCode: "close code \(closeCode!) can't be sent"
        case .io: "\(ioError!)"
        default: "\(code)"
        }
    }
}

public struct WebSocketConfiguration: Sendable {
    /// A longer message is refused with 1009.
    public var maxMessageSize: Int
    /// A longer frame is refused with 1009 before it's buffered.
    public var maxFrameSize: Int
    /// Limits on the HTTP handshake.
    public var limits: HTTP1Limits
    /// Offer (client) or accept (server) permessage-deflate (RFC 7692), so
    /// messages of 64 bytes or more go compressed. On zlib, which every
    /// platform has (Windows a vendored copy).
    public var compression: Bool

    public init(maxMessageSize: Int = 16 << 20, maxFrameSize: Int = 16 << 20, limits: HTTP1Limits = .init(),
                compression: Bool = false) {
        self.maxMessageSize = maxMessageSize
        self.maxFrameSize = maxFrameSize
        self.limits = limits
        self.compression = compression && cv_ws_available() == 1
    }
}

/// A WebSocket over any byte stream (TCP, TLS, in memory): tokio-tungstenite's
/// `WebSocketStream`, NIO's `NIOWebSocket` with its handlers.
///
/// ```swift
/// // Server
/// var ws = try await WebSocket.accept(conn)
/// while let message = try await ws.receive() { try await ws.send(message) }
///
/// // Client
/// var ws = try await WebSocket.connect(tcp, host: "example.com", target: "/chat")
/// try await ws.send(.text("hello"))
/// ```
///
/// Pings are answered as they arrive, and the closing handshake is done
/// for you: `receive()` returns nil once the peer has closed, with its code
/// in `closeCode`. One task at a time uses a WebSocket.
public struct WebSocket<Stream: AsyncReader & AsyncWriter & ~Copyable>: ~Copyable {
    private let stream: Stream
    public let role: WebSocketRole
    public let configuration: WebSocketConfiguration
    /// The upgrade request (server) or the 101 response (client).
    public let request: HTTPRequestHead?
    public let response: HTTPResponseHead?
    /// What permessage-deflate was agreed as, if it was.
    public let deflate: PerMessageDeflate?

    private var codec: WebSocketFrameCodec
    private let compressor: DeflateContext?
    private var fragmentCompressed = false
    private var buffer: IOBuffer
    private var start = 0
    private var output = IOBuffer(capacity: 4096)
    private var fragments: [UInt8] = []
    private var fragmentOpcode: WebSocketOpcode?
    private var utf8 = UTF8Validator()
    private var sentClose = false
    private var receivedClose = false
    /// The code the connection closed with, once it has.
    public private(set) var closeCode: WebSocketCloseCode?
    public private(set) var closeReason: String?

    /// A WebSocket over a stream whose handshake is done; `leftover` is what
    /// was read past it.
    public init(_ stream: consuming Stream, role: WebSocketRole, leftover: [UInt8] = [],
                configuration: WebSocketConfiguration = .init()) {
        self.init(stream, role: role, leftover: leftover, configuration: configuration, request: nil, response: nil,
                  deflate: nil)
    }

    private init(_ stream: consuming Stream, role: WebSocketRole, leftover: [UInt8],
                 configuration: WebSocketConfiguration, request: HTTPRequestHead?, response: HTTPResponseHead?,
                 deflate: PerMessageDeflate?) {
        self.stream = stream
        self.role = role
        self.configuration = configuration
        self.request = request
        self.response = response
        let compressor = deflate.flatMap { DeflateContext($0, role: role) }
        self.compressor = compressor
        self.deflate = compressor == nil ? nil : deflate
        codec = WebSocketFrameCodec(role: role, maxFrameSize: configuration.maxFrameSize,
                                    acceptsCompressed: compressor != nil)
        buffer = IOBuffer(capacity: max(16 * 1024, leftover.count))
        leftover.withUnsafeBytes { buffer.write($0) }
    }

    // MARK: - Handshakes

    /// Read the client's upgrade request from `stream` and answer it: 101
    /// with whatever fields `accept` returns, or 403 if it returns nil. A
    /// request that isn't a WebSocket upgrade gets 400 (426 for the wrong
    /// version) and throws.
    public static func accept(
        _ stream: consuming Stream,
        configuration: WebSocketConfiguration = .init(),
        accept: (HTTPRequestHead) async -> HTTPFields? = { _ in [:] }
    ) async throws(WebSocketError) -> WebSocket {
        var decoder = HTTP1RequestDecoder(limits: configuration.limits)
        var input = IOBuffer(capacity: 4096)
        var used = 0
        var head: HTTPRequestHead?
        reading: while true {
            let at = used
            let part: (item: HTTPRequestPart, consumed: Int)?
            do throws(HTTP1Error) {
                part = try input.withUnsafeBytes { all throws(HTTP1Error) in
                    try decoder.decodePart(UnsafeRawBufferPointer(rebasing: all[at...]))
                }
            } catch {
                try await refuse(error.status, on: stream)
                throw .handshake("\(error)")
            }
            if let (item, n) = part {
                used += n
                switch item {
                case .head(let h): head = h
                case .body: break
                case .end: break reading
                }
                continue
            }
            if input.spareCapacity == 0 { input.reserveCapacity(input.capacity * 2) }
            let n: Int
            do throws(IOError) { n = try await stream.read(into: &input) } catch { throw .io(error) }
            if n == 0 { throw .handshake("the connection closed") }
        }
        guard let head else { throw .handshake("no request") }
        if let (status, reason) = WebSocketHandshake.check(head) {
            try await refuse(status, on: stream, fields: status == 426 ? ["sec-websocket-version": "13"] : [:])
            throw .handshake(reason)
        }
        guard var fields = await accept(head) else {
            try await refuse(403, on: stream)
            throw .handshake("refused")
        }
        var deflate: PerMessageDeflate?
        if configuration.compression {
            deflate = PerMessageDeflate.negotiate(head.fields.values(for: "sec-websocket-extensions"))
            if let deflate { fields["sec-websocket-extensions"] = deflate.headerValue }
        }
        var encoder = HTTP1ResponseEncoder()
        var out = IOBuffer(capacity: 512)
        do throws(HTTP1Error) {
            try encoder.encodePart(.head(WebSocketHandshake.response(to: head, fields: fields)), into: &out)
        } catch {
            try await refuse(500, on: stream)
            throw .handshake("\(error)")
        }
        try await write(out, to: stream)
        let start = used
        let leftover = input.withUnsafeBytes { Array($0[start...]) }
        return WebSocket(stream, role: .server, leftover: leftover, configuration: configuration,
                         request: head, response: nil, deflate: deflate)
    }

    /// Ask the server at the other end of `stream` to upgrade `target`.
    public static func connect(
        _ stream: consuming Stream,
        host: String,
        target: String = "/",
        fields: HTTPFields = [:],
        configuration: WebSocketConfiguration = .init()
    ) async throws(WebSocketError) -> WebSocket {
        let key = WebSocketHandshake.makeKey()
        var fields = fields
        if configuration.compression { fields["sec-websocket-extensions"] = PerMessageDeflate.clientOffer }
        let request = WebSocketHandshake.request(host: host, target: target, key: key, fields: fields)
        var encoder = HTTP1RequestEncoder()
        var out = IOBuffer(capacity: 512)
        do throws(HTTP1Error) {
            try encoder.encodePart(.head(request), into: &out)
            try encoder.encodePart(.end(nil), into: &out)
        } catch {
            throw .handshake("\(error)")
        }
        try await write(out, to: stream)

        var decoder = HTTP1ResponseDecoder(limits: configuration.limits)
        decoder.requestSent(.get)
        var input = IOBuffer(capacity: 4096)
        while true {
            let decoded: (item: HTTPResponsePart, consumed: Int)?
            do throws(HTTP1Error) {
                decoded = try input.withUnsafeBytes { all throws(HTTP1Error) in try decoder.decodePart(all) }
            } catch {
                throw .handshake("\(error)")
            }
            if let (part, n) = decoded {
                guard case .head(let head) = part else { continue }
                // Interim responses come before the real one.
                if head.status < 200 && head.status != 101 {
                    input.consume(n)
                    continue
                }
                guard WebSocketHandshake.accepts(head, key: key) else {
                    throw .handshake("the server answered \(head.status) \(head.reason)")
                }
                let extensions = head.fields.values(for: "sec-websocket-extensions")
                guard configuration.compression || extensions.isEmpty else {
                    throw .handshake("an extension that wasn't offered")
                }
                let deflate = try PerMessageDeflate.accepted(extensions)
                let leftover = input.withUnsafeBytes { Array($0[n...]) }
                return WebSocket(stream, role: .client, leftover: leftover, configuration: configuration,
                                 request: nil, response: head, deflate: deflate)
            }
            if input.spareCapacity == 0 { input.reserveCapacity(input.capacity * 2) }
            let n: Int
            do throws(IOError) { n = try await stream.read(into: &input) } catch { throw .io(error) }
            if n == 0 { throw .handshake("the connection closed") }
        }
    }

    private static func refuse(_ status: Int, on stream: borrowing Stream, fields: HTTPFields = [:]) async throws(WebSocketError) {
        var head = HTTPResponseHead(status: status, fields: fields)
        head.fields["content-length"] = "0"
        head.fields["connection"] = "close"
        var encoder = HTTP1ResponseEncoder()
        var out = IOBuffer(capacity: 256)
        try? encoder.encodePart(.head(head), into: &out)
        try? encoder.encodePart(.end(nil), into: &out)
        try await write(out, to: stream)
    }

    private static func write(_ out: borrowing IOBuffer, to stream: borrowing Stream) async throws(WebSocketError) {
        do throws(IOError) { try await stream.write(out) } catch { throw .io(error) }
    }

    // MARK: - Messages

    /// The next message, or nil once the peer has closed (its code is in
    /// `closeCode`). Throws after a protocol violation, which this end has
    /// already answered with a close frame.
    public mutating func receive() async throws(WebSocketError) -> WebSocketMessage? {
        while !receivedClose {
            guard let frame = try await nextFrame() else {
                closeCode = .abnormal
                receivedClose = true
                throw .connectionLost
            }
            switch frame.opcode {
            case .ping:
                if !sentClose { try await send(WebSocketFrame(opcode: .pong, payload: frame.payload)) }
            case .pong:
                break
            case .close:
                try await peerClosed(frame.payload)
                return nil
            case .text, .binary, .continuation:
                if let message = try await data(frame) { return message }
            }
        }
        return nil
    }

    /// A data frame: the message it completes, if it does.
    private mutating func data(_ frame: WebSocketFrame) async throws(WebSocketError) -> WebSocketMessage? {
        if frame.opcode == .continuation {
            guard fragmentOpcode != nil else { try await fail(.protocolError) }
        } else {
            // A new message while another is unfinished.
            guard fragmentOpcode == nil else { try await fail(.protocolError) }
            fragmentOpcode = frame.opcode
            fragmentCompressed = frame.compressed
            utf8 = UTF8Validator()
        }
        guard fragments.count + frame.payload.count <= configuration.maxMessageSize else {
            try await fail(.messageTooBig)
        }
        // Compressed text is checked once it's inflated.
        if fragmentOpcode == .text && !fragmentCompressed && !utf8.feed(frame.payload) { try await fail(.invalidPayload) }
        fragments += frame.payload
        guard frame.fin else { return nil }
        let opcode = fragmentOpcode
        var payload = fragments
        fragmentOpcode = nil
        fragments = []
        if fragmentCompressed, let compressor {
            let inflated: [UInt8]?
            do throws(WebSocketError) {
                inflated = try compressor.decompress(payload, limit: configuration.maxMessageSize)
            } catch {
                try await fail(.invalidPayload)
            }
            guard let inflated else { try await fail(.messageTooBig) }
            payload = inflated
            if opcode == .text && !utf8.feed(payload) { try await fail(.invalidPayload) }
        }
        if opcode == .text {
            guard utf8.isComplete else { try await fail(.invalidPayload) }
            return .text(String(decoding: payload, as: UTF8.self))
        }
        return .binary(payload)
    }

    /// The peer's close frame: note its code, and answer it.
    private mutating func peerClosed(_ payload: [UInt8]) async throws(WebSocketError) {
        guard payload.count != 1 else { try await fail(.protocolError) }
        var code = WebSocketCloseCode.noStatus
        var reason = ""
        if payload.count >= 2 {
            code = WebSocketCloseCode(rawValue: UInt16(payload[0]) << 8 | UInt16(payload[1]))
            guard code.isSendable else { try await fail(.protocolError) }
            let text = Array(payload[2...])
            var check = UTF8Validator()
            guard check.feed(text), check.isComplete else { try await fail(.invalidPayload) }
            reason = String(decoding: text, as: UTF8.self)
        }
        receivedClose = true
        closeCode = code
        closeReason = reason
        if !sentClose {
            sentClose = true
            // Echo the code (RFC 6455 section 5.5.1), or send none if none came.
            let echo = payload.count >= 2 ? Array(payload[0..<2]) : []
            try? await send(WebSocketFrame(opcode: .close, payload: echo))
        }
    }

    /// Close with `code` after a violation, then throw.
    private mutating func fail(_ code: WebSocketCloseCode) async throws(WebSocketError) -> Never {
        if !sentClose {
            sentClose = true
            try? await send(WebSocketFrame(opcode: .close, payload: [UInt8(code.rawValue >> 8), UInt8(truncatingIfNeeded: code.rawValue)]))
        }
        closeCode = code
        receivedClose = true
        throw .protocolViolation(code)
    }

    public mutating func send(_ message: WebSocketMessage) async throws(WebSocketError) {
        guard !sentClose else { throw .closed }
        let (opcode, payload): (WebSocketOpcode, [UInt8]) = switch message {
        case .text(let text): (.text, Array(text.utf8))
        case .binary(let bytes): (.binary, bytes)
        }
        if let compressed = compressor?.compress(payload) {
            try await send(WebSocketFrame(opcode: opcode, payload: compressed, compressed: true))
        } else {
            try await send(WebSocketFrame(opcode: opcode, payload: payload))
        }
    }

    /// Send a ping; its pong is absorbed by `receive()`.
    public mutating func ping(_ payload: [UInt8] = []) async throws(WebSocketError) {
        guard !sentClose else { throw .closed }
        guard payload.count <= 125 else { throw .protocolViolation(.protocolError) }
        try await send(WebSocketFrame(opcode: .ping, payload: payload))
    }

    /// Start or finish the closing handshake: send a close frame, then read
    /// (and drop) messages until the peer's close frame, the end, or
    /// `timeout` (a peer that never answers doesn't hold this up). `reason`
    /// is cut to the 123 bytes a close frame has room for, between
    /// characters.
    public mutating func close(_ code: WebSocketCloseCode = .normal, reason: String = "",
                               timeout: Duration = .seconds(5)) async throws(WebSocketError) {
        if !sentClose {
            guard code.isSendable else { throw .invalidCloseCode(code) }
            sentClose = true
            var text: [UInt8] = []
            for scalar in reason.unicodeScalars {
                let utf8 = Array(String(scalar).utf8)
                guard text.count + utf8.count <= 123 else { break }
                text += utf8
            }
            let payload = [UInt8(code.rawValue >> 8), UInt8(truncatingIfNeeded: code.rawValue)] + text
            try await send(WebSocketFrame(opcode: .close, payload: payload))
        }
        _ = try? await Runtime.withIODeadline(timeout) { () async throws(IOError) in
            while !receivedClose {
                guard let frame = try? await nextFrame() else { return }
                if frame.opcode == .close {
                    receivedClose = true
                    if frame.payload.count >= 2 {
                        closeCode = WebSocketCloseCode(rawValue: UInt16(frame.payload[0]) << 8 | UInt16(frame.payload[1]))
                    } else {
                        closeCode = .noStatus
                    }
                }
            }
        }
    }

    /// Give back the stream, to close or reuse.
    public consuming func intoStream() -> Stream {
        stream
    }

    // MARK: - Frames

    private mutating func send(_ frame: WebSocketFrame) async throws(WebSocketError) {
        output.clear()
        codec.write(frame, into: &output)
        do throws(IOError) { try await stream.write(output) } catch { throw .io(error) }
    }

    /// The next frame; nil at the end of the stream.
    private mutating func nextFrame() async throws(WebSocketError) -> WebSocketFrame? {
        while true {
            let s = start
            let decoded: (item: WebSocketFrame, consumed: Int)?
            do throws(WebSocketError) {
                decoded = try buffer.withUnsafeBytes { all throws(WebSocketError) in
                    try codec.decodeFrame(UnsafeRawBufferPointer(rebasing: all[s...]))
                }
            } catch {
                if error.code == .protocolViolation, let code = error.closeCode { try await fail(code) }
                throw error
            }
            if let (frame, used) = decoded {
                start += used
                return frame
            }
            if start > 0 {
                buffer.consume(start)
                start = 0
            }
            if buffer.spareCapacity == 0 { buffer.reserveCapacity(buffer.capacity * 2) }
            do throws(IOError) {
                if try await stream.read(into: &buffer) == 0 { return nil }
            } catch {
                throw .io(error)
            }
        }
    }
}
