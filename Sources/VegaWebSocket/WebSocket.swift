import Vega
import VegaIO
import VegaHTTP1

/// A whole message: fragments are joined before it's handed on.
public enum WebSocketMessage: Sendable, Equatable {
    case text(String)
    case binary([UInt8])
}

/// Why a WebSocket operation failed.
public enum WebSocketError: Error, Hashable, Sendable, CustomStringConvertible {
    /// The peer broke the protocol; this end sent a close frame with this
    /// code (1002 protocol error, 1007 bad UTF-8, 1009 too big).
    case protocolViolation(WebSocketCloseCode)
    /// The opening handshake failed.
    case handshake(String)
    /// The connection ended without a close frame.
    case connectionLost
    /// This end has already sent its close frame.
    case closed
    case io(IOError)

    public var description: String {
        switch self {
        case .protocolViolation(let code): "protocol violation (closed with \(code))"
        case .handshake(let why): "handshake failed: \(why)"
        case .connectionLost: "connection lost without a close frame"
        case .closed: "already closed"
        case .io(let e): "\(e)"
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

    public init(maxMessageSize: Int = 16 << 20, maxFrameSize: Int = 16 << 20, limits: HTTP1Limits = .init()) {
        self.maxMessageSize = maxMessageSize
        self.maxFrameSize = maxFrameSize
        self.limits = limits
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

    private var codec: WebSocketFrameCodec
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
        self.init(stream, role: role, leftover: leftover, configuration: configuration, request: nil, response: nil)
    }

    private init(_ stream: consuming Stream, role: WebSocketRole, leftover: [UInt8],
                 configuration: WebSocketConfiguration, request: HTTPRequestHead?, response: HTTPResponseHead?) {
        self.stream = stream
        self.role = role
        self.configuration = configuration
        self.request = request
        self.response = response
        codec = WebSocketFrameCodec(role: role, maxFrameSize: configuration.maxFrameSize)
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
        guard let fields = await accept(head) else {
            try await refuse(403, on: stream)
            throw .handshake("refused")
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
                         request: head, response: nil)
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
                let leftover = input.withUnsafeBytes { Array($0[n...]) }
                return WebSocket(stream, role: .client, leftover: leftover, configuration: configuration,
                                 request: nil, response: head)
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
            utf8 = UTF8Validator()
        }
        guard fragments.count + frame.payload.count <= configuration.maxMessageSize else {
            try await fail(.messageTooBig)
        }
        if fragmentOpcode == .text && !utf8.feed(frame.payload) { try await fail(.invalidPayload) }
        fragments += frame.payload
        guard frame.fin else { return nil }
        let opcode = fragmentOpcode
        let payload = fragments
        fragmentOpcode = nil
        fragments = []
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
        switch message {
        case .text(let text): try await send(WebSocketFrame(opcode: .text, payload: Array(text.utf8)))
        case .binary(let bytes): try await send(WebSocketFrame(opcode: .binary, payload: bytes))
        }
    }

    /// Send a ping; its pong is absorbed by `receive()`.
    public mutating func ping(_ payload: [UInt8] = []) async throws(WebSocketError) {
        guard !sentClose else { throw .closed }
        guard payload.count <= 125 else { throw .protocolViolation(.protocolError) }
        try await send(WebSocketFrame(opcode: .ping, payload: payload))
    }

    /// Start or finish the closing handshake: send a close frame, then read
    /// (and drop) messages until the peer's close frame or the end.
    public mutating func close(_ code: WebSocketCloseCode = .normal, reason: String = "") async throws(WebSocketError) {
        if !sentClose {
            precondition(code.isSendable, "close code \(code) can't be sent")
            sentClose = true
            let payload = [UInt8(code.rawValue >> 8), UInt8(truncatingIfNeeded: code.rawValue)] + Array(reason.utf8.prefix(123))
            try await send(WebSocketFrame(opcode: .close, payload: payload))
        }
        while !receivedClose {
            guard let frame = try? await nextFrame() else { break }
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
                if case .protocolViolation(let code) = error { try await fail(code) }
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
