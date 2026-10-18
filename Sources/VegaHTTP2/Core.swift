import Vega
import VegaIO
import VegaHTTP1
import VegaWire
import VegaHTTP2Core

/// Limits and windows for one HTTP/2 connection.
public struct HTTP2Configuration: Sendable {
    /// Streams the peer may have open at once.
    public var maxConcurrentStreams: Int
    /// Each stream's receive window: how much body the peer may send
    /// before this end has taken it in.
    public var initialWindowSize: Int
    /// The receive window for all streams together.
    public var connectionWindowSize: Int
    public var maxFrameSize: Int
    /// The largest header block, decoded, this end accepts.
    public var maxHeaderListSize: Int
    /// A bigger body is refused: a request with 413, a response with an error.
    public var maxBodySize: Int

    public init(maxConcurrentStreams: Int = 100, initialWindowSize: Int = 1 << 20,
                connectionWindowSize: Int = 4 << 20, maxFrameSize: Int = HTTP2Frame.defaultMaxFrameSize,
                maxHeaderListSize: Int = 64 * 1024, maxBodySize: Int = 8 << 20) {
        self.maxConcurrentStreams = maxConcurrentStreams
        self.initialWindowSize = initialWindowSize
        self.connectionWindowSize = connectionWindowSize
        self.maxFrameSize = maxFrameSize
        self.maxHeaderListSize = maxHeaderListSize
        self.maxBodySize = maxBodySize
    }
}

/// Why an HTTP/2 exchange failed.
public enum HTTP2Error: Error, Hashable, Sendable, CustomStringConvertible {
    /// The peer broke the protocol; this end closed the connection with
    /// this code.
    case connection(HTTP2ErrorCode)
    /// The peer closed the connection (GOAWAY) without answering.
    case goaway(HTTP2ErrorCode)
    /// The peer reset the stream.
    case stream(HTTP2ErrorCode)
    /// The connection ended without answering.
    case closed
    /// A request that can't be sent, such as one with a field that would
    /// end early.
    case invalidMessage
    case io(IOError)

    public var description: String {
        switch self {
        case .connection(let c): "connection error \(c)"
        case .goaway(let c): "connection closed by peer (\(c))"
        case .stream(let c): "stream reset by peer (\(c))"
        case .closed: "connection closed"
        case .invalidMessage: "message can't be sent"
        case .io(let e): "\(e)"
        }
    }
}

/// A connection error: send GOAWAY with this code and close.
struct ConnectionError: Error {
    var code: HTTP2ErrorCode
}

/// What a frame (or a send) brought about.
enum CoreEvent {
    /// A whole request (server) or response (client) on a stream.
    case request(UInt32, HTTPRequest)
    case response(UInt32, HTTPResponse)
    /// The stream ended without a message: reset by the peer or by this
    /// end, or refused.
    case reset(UInt32, HTTP2ErrorCode)
    /// A request body over the limit (server): answer 413.
    case bodyTooLarge(UInt32)
    case goaway(lastStreamID: UInt32, HTTP2ErrorCode)
}

/// The HTTP/2 protocol for one connection, without I/O: frames in, events
/// and frames to send out. Streams are whole messages: a body is gathered
/// before its message is handed on, and a message to send goes out as its
/// windows allow.
struct H2Core {
    let isServer: Bool
    let config: HTTP2Configuration

    /// What the peer's SETTINGS say.
    private var peerInitialWindow = HTTP2Frame.defaultWindowSize
    private(set) var peerMaxFrameSize = HTTP2Frame.defaultMaxFrameSize
    private(set) var peerMaxConcurrentStreams = Int.max

    /// VegaWire's, which owns its memory: `destroy()` frees it.
    private var hpack = HPACKDecoder()
    private var streams: [UInt32: Stream] = [:]
    /// Streams in the order their sends began, for fair flushing.
    private var sendOrder: [UInt32] = []
    /// The highest stream the peer opened.
    private(set) var highestPeerStream: UInt32 = 0
    /// The peer's recent streams, and those of them this end reset: what a
    /// HEADERS frame on a stream below `highestPeerStream` was (RFC 9113
    /// section 5.1). Bounded: the oldest are forgotten.
    private var recentPeerStreams = RecentStreams()
    private var resetPeerStreams = RecentStreams()
    private var nextLocalStream: UInt32
    private var sendWindow = HTTP2Frame.defaultWindowSize
    private var recvWindow = HTTP2Frame.defaultWindowSize
    /// Bytes taken in but not yet given back with WINDOW_UPDATE.
    private var recvUnacked = 0
    /// A header block waiting for CONTINUATION frames.
    private var pendingBlock: (stream: UInt32, block: [UInt8], endStream: Bool)?
    private(set) var goawayReceived: UInt32?
    /// This end sent GOAWAY to shut down: new streams from the peer are
    /// refused.
    var goawaySent = false

    private struct Stream {
        var recvWindow: Int
        var sendWindow: Int
        var recvUnacked = 0
        var remoteClosed = false
        var localClosed = false
        /// The request (server) or response (client) head, once read.
        var request: HTTPRequestHead?
        var response: HTTPResponseHead?
        var body: [UInt8] = []
        var trailers: HTTPFields?
        /// A body over the limit, being thrown away.
        var discarding = false
        /// A response to HEAD: its Content-Length describes a body not sent.
        var headRequest = false
        /// What's left to send: body bytes from `sent`, then trailers.
        var outgoing: [UInt8] = []
        var sent = 0
        var outgoingTrailers: HTTPFields?
        var sending = false
    }

    init(isServer: Bool, configuration: HTTP2Configuration) {
        self.isServer = isServer
        config = configuration
        nextLocalStream = isServer ? 2 : 1
    }

    /// The opening frames: the client's preface, then this end's SETTINGS
    /// and the connection window raised to the configured size.
    mutating func start(into out: inout IOBuffer) {
        if !isServer { HTTP2Frame.preface.withUnsafeBytes { out.write($0) } }
        var settings: [(HTTP2Setting, UInt32)] = [
            (.initialWindowSize, UInt32(config.initialWindowSize)),
            (.maxFrameSize, UInt32(config.maxFrameSize)),
            (.maxHeaderListSize, UInt32(config.maxHeaderListSize)),
        ]
        if isServer {
            settings.append((.maxConcurrentStreams, UInt32(config.maxConcurrentStreams)))
        } else {
            settings.append((.enablePush, 0))
        }
        HTTP2Frame(streamID: 0, payload: .settings(settings)).write(into: &out)
        let raise = config.connectionWindowSize - recvWindow
        if raise > 0 {
            HTTP2Frame(streamID: 0, payload: .windowUpdate(UInt32(raise))).write(into: &out)
            recvWindow += raise
        }
    }

    // MARK: - Receiving

    mutating func receive(_ frame: HTTP2Frame, into out: inout IOBuffer) throws(ConnectionError) -> [CoreEvent] {
        let id = frame.streamID
        if let pending = pendingBlock {
            // Nothing may come between a header block's frames.
            guard case .continuation(let fragment, let endHeaders) = frame.payload, id == pending.stream
            else { throw ConnectionError(code: .protocolError) }
            pendingBlock!.block += fragment
            guard pendingBlock!.block.count <= config.maxHeaderListSize * 2 else {
                throw ConnectionError(code: .enhanceYourCalm)
            }
            guard endHeaders else { return [] }
            let whole = pendingBlock!
            pendingBlock = nil
            return try headerBlock(id, whole.block, endStream: whole.endStream, into: &out)
        }
        switch frame.payload {
        case .data(let bytes, let endStream, let flowLength):
            return try data(id, bytes, endStream: endStream, flowLength: flowLength, into: &out)
        case .headers(let block, let endStream, let endHeaders):
            guard endHeaders else {
                pendingBlock = (id, block, endStream)
                return []
            }
            return try headerBlock(id, block, endStream: endStream, into: &out)
        case .continuation:
            throw ConnectionError(code: .protocolError)
        case .priority:
            return []
        case .rstStream(let code):
            if isIdle(id) { throw ConnectionError(code: .protocolError) }
            guard streams.removeValue(forKey: id) != nil else { return [] }
            return [.reset(id, code)]
        case .settings(let settings):
            try apply(settings)
            HTTP2Frame(streamID: 0, payload: .settingsAck).write(into: &out)
            flush(into: &out)
            return []
        case .settingsAck, .unknown:
            return []
        case .pushPromise:
            // Push is off: the client says so, and clients never get to push.
            throw ConnectionError(code: .protocolError)
        case .ping(let data, let ack):
            if !ack { HTTP2Frame(streamID: 0, payload: .ping(data, ack: true)).write(into: &out) }
            return []
        case .goaway(let last, let code, _):
            goawayReceived = last
            return [.goaway(lastStreamID: last, code)]
        case .windowUpdate(let increment):
            try windowUpdate(id, Int(increment), into: &out)
            return []
        }
    }

    /// Whether `id` names a stream that was never opened.
    private func isIdle(_ id: UInt32) -> Bool {
        let peerOpens = (id % 2 == 1) == isServer
        return peerOpens ? id > highestPeerStream : id >= nextLocalStream
    }

    private mutating func data(_ id: UInt32, _ bytes: [UInt8], endStream: Bool, flowLength: Int,
                               into out: inout IOBuffer) throws(ConnectionError) -> [CoreEvent] {
        guard flowLength <= recvWindow else { throw ConnectionError(code: .flowControlError) }
        recvWindow -= flowLength
        // Whatever happens to the stream, the connection window comes back.
        giveBack(connection: flowLength, into: &out)
        guard var s = streams[id] else {
            if isIdle(id) { throw ConnectionError(code: .protocolError) }
            reset(id, .streamClosed, into: &out)
            return []
        }
        guard !s.remoteClosed, s.request != nil || s.response != nil else {
            // After END_STREAM, or before any HEADERS.
            streams[id] = nil
            reset(id, s.remoteClosed ? .streamClosed : .protocolError, into: &out)
            return [.reset(id, s.remoteClosed ? .streamClosed : .protocolError)]
        }
        guard flowLength <= s.recvWindow else {
            streams[id] = nil
            reset(id, .flowControlError, into: &out)
            return [.reset(id, .flowControlError)]
        }
        s.recvWindow -= flowLength
        var events: [CoreEvent] = []
        if !s.discarding {
            if s.body.count + bytes.count > config.maxBodySize {
                s.discarding = true
                s.body = []
                events.append(isServer ? .bodyTooLarge(id) : .reset(id, .cancel))
                if !isServer {
                    streams[id] = nil
                    reset(id, .cancel, into: &out)
                    return events
                }
            } else {
                s.body += bytes
            }
        }
        if endStream {
            s.remoteClosed = true
            streams[id] = s
            if !s.discarding { events += finish(id, into: &out) }
            return events
        }
        // Give the stream's window back as it's taken in.
        s.recvUnacked += flowLength
        if s.recvUnacked >= config.initialWindowSize / 2 {
            HTTP2Frame(streamID: id, payload: .windowUpdate(UInt32(s.recvUnacked))).write(into: &out)
            s.recvWindow += s.recvUnacked
            s.recvUnacked = 0
        }
        streams[id] = s
        return events
    }

    private mutating func giveBack(connection n: Int, into out: inout IOBuffer) {
        recvUnacked += n
        if recvUnacked >= config.connectionWindowSize / 2 {
            HTTP2Frame(streamID: 0, payload: .windowUpdate(UInt32(recvUnacked))).write(into: &out)
            recvWindow += recvUnacked
            recvUnacked = 0
        }
    }

    private mutating func headerBlock(_ id: UInt32, _ block: [UInt8], endStream: Bool,
                                      into out: inout IOBuffer) throws(ConnectionError) -> [CoreEvent] {
        // Decoded whatever becomes of the stream: HPACK state is shared.
        var fields = DecodedFields()
        do {
            try hpack.decode(block, sizeLimit: config.maxHeaderListSize, into: &fields)
        } catch {
            throw ConnectionError(code: error as? HPACKError == .tooLarge ? .enhanceYourCalm : .compressionError)
        }

        if var s = streams[id] {
            if s.remoteClosed {
                streams[id] = nil
                reset(id, .streamClosed, into: &out)
                return [.reset(id, .streamClosed)]
            }
            if !isServer && s.response == nil {
                // The response head, or an interim one before it.
                guard let head = fields.responseHead(version: .http2) else { return streamError(id, into: &out) }
                if head.status < 200 {
                    if endStream { return streamError(id, into: &out) }
                    return []
                }
                s.response = head
            } else {
                // Trailers: they end the stream, and have no pseudo-fields.
                guard endStream, let trailers = fields.trailers() else { return streamError(id, into: &out) }
                s.trailers = trailers
            }
            guard endStream else {
                streams[id] = s
                return []
            }
            s.remoteClosed = true
            streams[id] = s
            return s.discarding ? [] : finish(id, into: &out)
        }

        // A new stream, which only a client opens.
        guard isServer, id % 2 == 1 else {
            if isIdle(id) { throw ConnectionError(code: .protocolError) }
            reset(id, .streamClosed, into: &out)
            return []
        }
        guard id > highestPeerStream else {
            // One this end reset may still have frames in flight: reset it
            // again. One that closed normally is a connection error
            // (section 5.1), and so is one never opened, which a higher
            // stream implicitly closed (section 5.1.1).
            if resetPeerStreams.contains(id) {
                reset(id, .streamClosed, into: &out)
                return []
            }
            throw ConnectionError(code: recentPeerStreams.contains(id) ? .streamClosed : .protocolError)
        }
        highestPeerStream = id
        recentPeerStreams.insert(id)
        if goawaySent || streams.count >= config.maxConcurrentStreams {
            reset(id, .refusedStream, into: &out)
            return []
        }
        guard let head = fields.requestHead(version: .http2) else {
            reset(id, .protocolError, into: &out)
            return []
        }
        var s = Stream(recvWindow: config.initialWindowSize, sendWindow: peerInitialWindow)
        s.request = head
        s.remoteClosed = endStream
        streams[id] = s
        return endStream ? finish(id, into: &out) : []
    }

    private mutating func streamError(_ id: UInt32, into out: inout IOBuffer) -> [CoreEvent] {
        streams[id] = nil
        reset(id, .protocolError, into: &out)
        return [.reset(id, .protocolError)]
    }

    /// The peer has sent its whole message on `id`.
    private mutating func finish(_ id: UInt32, into out: inout IOBuffer) -> [CoreEvent] {
        guard let s = streams[id] else { return [] }
        let fields = s.request?.fields ?? s.response?.fields ?? HTTPFields()
        let unsent = s.headRequest || s.response?.status == 304
        if !unsent, let length = fields["content-length"], Int(length) != s.body.count {
            return streamError(id, into: &out)
        }
        // Trailers join the fields: whole messages have nowhere else to put them.
        var trailing = HTTPFields()
        for (name, value) in s.trailers ?? [:] { trailing.append(name: name, value: value) }
        if var request = s.request {
            for (name, value) in trailing { request.fields.append(name: name, value: value) }
            return [.request(id, HTTPRequest(head: request, body: s.body))]
        }
        if var response = s.response {
            closeIfDone(id)
            for (name, value) in trailing { response.fields.append(name: name, value: value) }
            return [.response(id, HTTPResponse(head: response, body: s.body))]
        }
        return []
    }

    private mutating func apply(_ settings: [(HTTP2Setting, UInt32)]) throws(ConnectionError) {
        for (id, value) in settings {
            switch id {
            case .enablePush:
                // Only a client may turn push on, and this end never pushes.
                guard value <= 1, isServer || value == 0 else { throw ConnectionError(code: .protocolError) }
            case .initialWindowSize:
                guard value <= UInt32(HTTP2Frame.maxWindowSize) else { throw ConnectionError(code: .flowControlError) }
                let delta = Int(value) - peerInitialWindow
                peerInitialWindow = Int(value)
                for key in streams.keys {
                    streams[key]!.sendWindow += delta
                    guard streams[key]!.sendWindow <= HTTP2Frame.maxWindowSize else {
                        throw ConnectionError(code: .flowControlError)
                    }
                }
            case .maxFrameSize:
                guard value >= 16_384 && value <= 16_777_215 else { throw ConnectionError(code: .protocolError) }
                peerMaxFrameSize = Int(value)
            case .maxConcurrentStreams:
                peerMaxConcurrentStreams = Int(value)
            default:
                break // the encoder never indexes, so the table size doesn't matter
            }
        }
    }

    private mutating func windowUpdate(_ id: UInt32, _ increment: Int, into out: inout IOBuffer) throws(ConnectionError) {
        if id == 0 {
            guard increment > 0 else { throw ConnectionError(code: .protocolError) }
            sendWindow += increment
            guard sendWindow <= HTTP2Frame.maxWindowSize else { throw ConnectionError(code: .flowControlError) }
        } else if var s = streams[id] {
            guard increment > 0 else {
                streams[id] = nil
                reset(id, .protocolError, into: &out)
                return
            }
            s.sendWindow += increment
            guard s.sendWindow <= HTTP2Frame.maxWindowSize else {
                streams[id] = nil
                reset(id, .flowControlError, into: &out)
                return
            }
            streams[id] = s
        } else if isIdle(id) {
            throw ConnectionError(code: .protocolError)
        }
        flush(into: &out)
    }

    // MARK: - Sending

    /// Streams open, in either direction.
    var openStreamCount: Int { streams.count }

    /// Streams this end has open.
    var localStreamCount: Int { streams.keys.count { ($0 % 2 == 1) != isServer } }

    /// Whether a new request may be sent now.
    var canOpenStream: Bool {
        goawayReceived == nil && localStreamCount < peerMaxConcurrentStreams && nextLocalStream < 0x7FFF_FFFF
    }

    /// Send `request` on a new stream (client). Returns its stream.
    mutating func open(_ request: HTTPRequest, scheme: String, authority: String?,
                       into out: inout IOBuffer) throws(HTTP2Error) -> UInt32 {
        let head = request.head
        guard let authority = authority ?? head.fields["host"] else { throw .invalidMessage }
        var pseudo: [(String, String)] = [(":method", head.method.rawValue)]
        if head.method == .connect {
            pseudo.append((":authority", authority))
        } else {
            pseudo += [(":scheme", scheme), (":authority", authority), (":path", head.target)]
        }
        let id = nextLocalStream
        var fields = head.fields
        fields.remove("host")
        let block = try encodeBlock(pseudo, fields)
        nextLocalStream += 2
        streams[id] = Stream(recvWindow: config.initialWindowSize, sendWindow: peerInitialWindow)
        streams[id]!.headRequest = head.method == .head
        send(id, block: block, body: request.body, trailers: nil, into: &out)
        return id
    }

    /// Answer the request on `id` (server).
    mutating func respond(_ id: UInt32, _ response: HTTPResponse, into out: inout IOBuffer) {
        guard let s = streams[id], let request = s.request, !s.sending else { return }
        var fields = response.head.fields
        let status = response.head.status
        var body = response.body
        if status >= 200, status != 204, status != 304, !fields.contains("content-length") {
            fields["content-length"] = String(body.count)
        }
        if request.method == .head || status == 204 || status == 304 { body = [] }
        let block: [UInt8]
        do throws(HTTP2Error) {
            block = try encodeBlock([(":status", String(status))], fields)
        } catch {
            block = (try? encodeBlock([(":status", "500")], ["content-length": "0"])) ?? []
            body = []
        }
        send(id, block: block, body: body, trailers: nil, into: &out)
        // A request still arriving (refused for its size) is cut off.
        if let after = streams[id], !after.remoteClosed, after.localClosed {
            streams[id] = nil
            reset(id, .noError, into: &out)
        }
    }

    private mutating func send(_ id: UInt32, block: [UInt8], body: [UInt8], trailers: HTTPFields?,
                               into out: inout IOBuffer) {
        let endStream = body.isEmpty && trailers == nil
        writeBlock(id, block, endStream: endStream, into: &out)
        streams[id]!.sending = true
        if endStream {
            streams[id]!.localClosed = true
            closeIfDone(id)
            return
        }
        streams[id]!.outgoing = body
        streams[id]!.outgoingTrailers = trailers
        sendOrder.append(id)
        flush(into: &out)
    }

    /// HEADERS, then CONTINUATION frames as needed.
    private func writeBlock(_ id: UInt32, _ block: [UInt8], endStream: Bool, into out: inout IOBuffer) {
        var offset = 0
        var first = true
        repeat {
            let n = min(peerMaxFrameSize, block.count - offset)
            let fragment = Array(block[offset..<offset + n])
            offset += n
            let last = offset == block.count
            let payload: HTTP2Frame.Payload = first
                ? .headers(fragment, endStream: endStream, endHeaders: last)
                : .continuation(fragment, endHeaders: last)
            HTTP2Frame(streamID: id, payload: payload).write(into: &out)
            first = false
        } while offset < block.count
    }

    /// Send what the windows allow of every stream's body.
    mutating func flush(into out: inout IOBuffer) {
        var i = 0
        while i < sendOrder.count {
            let id = sendOrder[i]
            guard var s = streams[id], !s.localClosed else {
                sendOrder.remove(at: i)
                continue
            }
            while s.sent < s.outgoing.count && sendWindow > 0 && s.sendWindow > 0 {
                let n = min(s.outgoing.count - s.sent, sendWindow, s.sendWindow, peerMaxFrameSize)
                let last = s.sent + n == s.outgoing.count && s.outgoingTrailers == nil
                HTTP2Frame(streamID: id, payload: .data(Array(s.outgoing[s.sent..<s.sent + n]),
                                                       endStream: last, flowLength: n)).write(into: &out)
                s.sent += n
                sendWindow -= n
                s.sendWindow -= n
            }
            if s.sent == s.outgoing.count {
                if let trailers = s.outgoingTrailers, let block = try? encodeBlock([], trailers) {
                    writeBlock(id, block, endStream: true, into: &out)
                }
                s.localClosed = true
                s.outgoing = []
                streams[id] = s
                closeIfDone(id)
                sendOrder.remove(at: i)
                continue
            }
            streams[id] = s
            i += 1
        }
    }

    private mutating func closeIfDone(_ id: UInt32) {
        if let s = streams[id], s.localClosed && s.remoteClosed { streams[id] = nil }
    }

    /// Frees what the HPACK decoder holds. The connection's loop calls it
    /// once, when it is done with the connection.
    mutating func destroy() { hpack.destroy() }

    /// Reset a stream: RST_STREAM, and forget it.
    mutating func reset(_ id: UInt32, _ code: HTTP2ErrorCode, into out: inout IOBuffer) {
        streams[id] = nil
        if (id % 2 == 1) == isServer { resetPeerStreams.insert(id) }
        HTTP2Frame(streamID: id, payload: .rstStream(code)).write(into: &out)
    }

    /// The fields of a message as a header block, names lowercased and
    /// connection-specific fields left out.
    private func encodeBlock(_ pseudo: [(String, String)], _ fields: HTTPFields) throws(HTTP2Error) -> [UInt8] {
        var block = HeaderBlockEncoder()
        for (name, value) in pseudo { block.add(name: name, value: value) }
        for (name, value) in fields {
            let lower = name.lowercased()
            if connectionSpecific.contains(lower) || (lower == "te" && value.lowercased() != "trailers") { continue }
            guard isValidName(Array(lower.utf8)), isValidValue(Array(value.utf8)) else { throw .invalidMessage }
            block.add(name: lower, value: value)
        }
        return block.bytes
    }
}

/// The last few hundred stream IDs, for telling apart what a late frame on
/// a stream refers to.
struct RecentStreams {
    private var ring = [UInt32](repeating: 0, count: 256)
    private var set: Set<UInt32> = []
    private var next = 0

    mutating func insert(_ id: UInt32) {
        guard set.insert(id).inserted else { return }
        let old = ring[next]
        if old != 0 { set.remove(old) }
        ring[next] = id
        next = (next + 1) % ring.count
    }

    func contains(_ id: UInt32) -> Bool { set.contains(id) }
}
