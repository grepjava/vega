import Synchronization
import Vega
import VegaIO
import VegaHTTP1

/// HTTP/2 serving with whole bodies: each request runs its handler in a
/// task of its own, so slow requests don't hold up the others.
///
/// ```swift
/// let conn = try await listener.accept()
/// runtime.spawn(with: conn) { conn in
///     try? await HTTP2Server.serve(conn) { request in HTTPResponse(body: "hello") }
/// }
/// ```
///
/// Over TLS, offer "h2" with ALPN and serve `tls.halves()`.
public enum HTTP2Server {
    /// Serve the connection until the client closes it or breaks the
    /// protocol (answered with GOAWAY, then thrown). A handler that throws
    /// is answered with 500.
    ///
    /// Once `shutdown` triggers, the server sends GOAWAY, refuses new
    /// streams, and returns when the open ones are done.
    ///
    /// At most `maxConcurrentStreams` handlers run at once, counting those
    /// whose stream the client has reset (each is cancelled): a stream past
    /// that is refused. A client that keeps resetting streams, or opening
    /// them past the limit it was given, faster than handlers finish (the
    /// "rapid reset" attack, CVE-2023-44487) gets GOAWAY with
    /// ENHANCE_YOUR_CALM.
    public static func serve<Reader: AsyncReader & ~Copyable & Sendable, Writer: AsyncWriter & ~Copyable>(
        reader: consuming Reader,
        writer: consuming Writer,
        configuration: HTTP2Configuration = .init(),
        shutdown: ShutdownSignal? = nil,
        _ handler: @escaping @Sendable (HTTPRequest) async throws -> HTTPResponse
    ) async throws(HTTP2Error) {
        let readerBox = Handoff(reader)
        let writerBox = Handoff(writer)
        let failure = await withTaskGroup(of: Void.self) { group -> HTTP2Error? in
            let channel = Channel<LoopEvent>(capacity: 1024)
            let mailbox = Mailbox(channel.sender)
            var inbox = channel.receiver
            group.addTask {
                await readFrames(readerBox.take(), preface: true, maxFrameSize: configuration.maxFrameSize, to: mailbox)
            }
            if let shutdown {
                group.addTask {
                    await shutdown.wait() // returns early when the group is cancelled
                    if shutdown.isTriggered { _ = await mailbox.post(.shutdown) }
                }
            }
            let writer = writerBox.take()
            var core = H2Core(isServer: true, configuration: configuration)
            defer { core.destroy() }
            var out = IOBuffer(capacity: 64 * 1024)
            core.start(into: &out)
            var inFlight = 0
            // Each handler's task, to cancel it when its stream is reset.
            var handlers: [UInt32: Task<Void, Never>] = [:]
            // Streams reset while their handler ran or refused for the limit,
            // less responses sent.
            var resetDebt = 0
            func overLimit() -> Bool {
                resetDebt += 1
                return resetDebt > configuration.maxConcurrentStreams
            }
            var readerDone = false
            var failure: HTTP2Error?

            loop: while true {
                if !out.isEmpty {
                    do throws(IOError) { try await writer.write(out) } catch {
                        failure = .io(error)
                        break loop
                    }
                    out.clear()
                }
                if inFlight == 0 && (readerDone || core.goawaySent && core.openStreamCount == 0) { break }
                var event: LoopEvent
                do throws(ChannelError) { event = try await inbox.receive() } catch { break }
                while true {
                    switch event {
                    case .frame(let frame):
                        let events: [CoreEvent]
                        do throws(ConnectionError) {
                            events = try core.receive(frame, into: &out)
                        } catch {
                            goaway(core.highestPeerStream, error.code, into: &out)
                            failure = .connection(error.code)
                            readerDone = true
                            inFlight = 0
                            break
                        }
                        for e in events {
                            switch e {
                            case .request(let id, let request):
                                guard inFlight < configuration.maxConcurrentStreams else {
                                    core.reset(id, .refusedStream, into: &out)
                                    if overLimit() {
                                        goaway(core.highestPeerStream, .enhanceYourCalm, into: &out)
                                        failure = .connection(.enhanceYourCalm)
                                        readerDone = true
                                        inFlight = 0
                                    }
                                    continue
                                }
                                inFlight += 1
                                handlers[id] = Runtime.spawn {
                                    let response = (try? await handler(request)) ?? HTTPResponse(status: 500)
                                    _ = await mailbox.post(.response(id, response))
                                }
                            case .bodyTooLarge(let id):
                                core.respond(id, HTTPResponse(status: 413), into: &out)
                            case .reset(let id, _):
                                guard let task = handlers[id] else { break }
                                task.cancel()
                                if overLimit() {
                                    goaway(core.highestPeerStream, .enhanceYourCalm, into: &out)
                                    failure = .connection(.enhanceYourCalm)
                                    readerDone = true
                                    inFlight = 0
                                }
                            case .response, .goaway:
                                break
                            }
                        }
                    case .response(let id, let response):
                        inFlight -= 1
                        if handlers.removeValue(forKey: id)?.isCancelled == false { resetDebt = max(resetDebt - 1, 0) }
                        core.respond(id, response, into: &out)
                    case .readEnded:
                        readerDone = true
                    case .readFailed(let error):
                        if case .connection(let code) = error { goaway(core.highestPeerStream, code, into: &out) }
                        failure = error
                        readerDone = true
                        inFlight = 0
                    case .shutdown:
                        if !core.goawaySent {
                            core.goawaySent = true
                            goaway(core.highestPeerStream, .noError, into: &out)
                        }
                    case .request, .bodyDone:
                        break
                    }
                    // Take whatever else is queued before writing.
                    guard failure == nil, let next = try? inbox.tryReceive() else { break }
                    event = next
                }
            }
            if failure != nil, !out.isEmpty { try? await writer.write(out) }
            inbox.close()
            for task in handlers.values { task.cancel() }
            group.cancelAll()
            return failure
        }
        if let failure { throw failure }
    }

    /// Serve the halves of a split stream (`stream.halves()`).
    public static func serve<Reader: AsyncReader & ~Copyable & Sendable, Writer: AsyncWriter & ~Copyable>(
        _ halves: consuming StreamHalves<Reader, Writer>, configuration: HTTP2Configuration = .init(),
        shutdown: ShutdownSignal? = nil,
        _ handler: @escaping @Sendable (HTTPRequest) async throws -> HTTPResponse
    ) async throws(HTTP2Error) {
        try await serve(reader: halves.reader, writer: halves.writer, configuration: configuration,
                        shutdown: shutdown, handler)
    }

    /// Serve a TCP connection.
    public static func serve(_ stream: consuming TCPStream, configuration: HTTP2Configuration = .init(),
                             shutdown: ShutdownSignal? = nil,
                             _ handler: @escaping @Sendable (HTTPRequest) async throws -> HTTPResponse) async throws(HTTP2Error) {
        try await serve(stream.halves(), configuration: configuration, shutdown: shutdown, handler)
    }
}

/// An HTTP/2 client connection, for use inside
/// `HTTP2Client.withConnection`. Requests may be sent from many tasks at
/// once; each gets a stream of its own.
public final class HTTP2Client: Sendable {
    private let mailbox: Mailbox

    fileprivate init(_ mailbox: Mailbox) {
        self.mailbox = mailbox
    }

    /// Send `request` and wait for its response. The request's Host field
    /// (or the connection's authority) becomes `:authority`.
    public func send(_ request: HTTPRequest) async throws(HTTP2Error) -> HTTPResponse {
        let slot = ResponseSlot()
        guard await mailbox.post(.request(request, slot)) else { throw .closed }
        return try await slot.value()
    }

    /// Run `body` with a client over the connection, then close it with
    /// GOAWAY. Requests still waiting then fail with `.closed`.
    ///
    /// ```swift
    /// let tcp = try await TCPStream.connect(host: "127.0.0.1", port: 8080)
    /// let response = try await HTTP2Client.withConnection(tcp.halves(), scheme: "http") { client in
    ///     try await client.send(HTTPRequest(target: "/", fields: ["host": "localhost"]))
    /// }
    /// ```
    public static func withConnection<Reader: AsyncReader & ~Copyable & Sendable,
                                      Writer: AsyncWriter & ~Copyable & Sendable, T>(
        reader: consuming Reader,
        writer: consuming Writer,
        scheme: String = "https",
        authority: String? = nil,
        configuration: HTTP2Configuration = .init(),
        _ body: (HTTP2Client) async throws -> T
    ) async throws -> T {
        let readerBox = Handoff(reader)
        let writerBox = Handoff(writer)
        let result: Result<T, any Error> = await withTaskGroup(of: Bool.self) { group in
            let channel = Channel<LoopEvent>(capacity: 1024)
            let mailbox = Mailbox(channel.sender)
            let inboxBox = Handoff(channel.receiver)
            group.addTask {
                await readFrames(readerBox.take(), preface: false, maxFrameSize: configuration.maxFrameSize, to: mailbox)
                return false
            }
            group.addTask {
                await clientLoop(writerBox.take(), inboxBox.take(), scheme: scheme, authority: authority,
                                 configuration: configuration)
                return true
            }
            let result: Result<T, any Error>
            do {
                result = .success(try await body(HTTP2Client(mailbox)))
            } catch {
                result = .failure(error)
            }
            // Let the loop say goodbye before the reader is stopped.
            _ = await mailbox.post(.bodyDone)
            while let loopEnded = await group.next(), !loopEnded {}
            group.cancelAll()
            return result
        }
        return try result.get()
    }

    /// `withConnection` over the halves of a split stream
    /// (`stream.halves()`): scheme "https" for TLS.
    public static func withConnection<Reader: AsyncReader & ~Copyable & Sendable,
                                      Writer: AsyncWriter & ~Copyable & Sendable, T>(
        _ halves: consuming StreamHalves<Reader, Writer>,
        scheme: String = "https",
        authority: String? = nil,
        configuration: HTTP2Configuration = .init(),
        _ body: (HTTP2Client) async throws -> T
    ) async throws -> T {
        try await withConnection(reader: halves.reader, writer: halves.writer, scheme: scheme,
                                        authority: authority, configuration: configuration, body)
    }

    private static func clientLoop<Writer: AsyncWriter & ~Copyable>(
        _ writer: consuming Writer, _ inbox: consuming Channel<LoopEvent>.Receiver,
        scheme: String, authority: String?, configuration: HTTP2Configuration
    ) async {
        var core = H2Core(isServer: false, configuration: configuration)
        defer { core.destroy() }
        var out = IOBuffer(capacity: 64 * 1024)
        core.start(into: &out)
        var waiting: [UInt32: ResponseSlot] = [:]
        var queued: [(HTTPRequest, ResponseSlot)] = []
        // Once set, the connection is done for: every request fails with it.
        var failure: HTTP2Error?

        func failAll(_ error: HTTP2Error) {
            for slot in waiting.values { slot.resolve(.failure(error)) }
            for (_, slot) in queued { slot.resolve(.failure(error)) }
            waiting = [:]
            queued = []
        }

        while true {
            if !out.isEmpty {
                if failure == nil {
                    do throws(IOError) { try await writer.write(out) } catch {
                        failure = .io(error)
                        failAll(.io(error))
                    }
                }
                out.clear()
            }
            guard let event = try? await inbox.receive() else { return }
            switch event {
            case .request(let request, let slot):
                if let failure {
                    slot.resolve(.failure(failure))
                } else {
                    queued.append((request, slot))
                }
            case .frame(let frame):
                guard failure == nil else { break }
                do throws(ConnectionError) {
                    for e in try core.receive(frame, into: &out) {
                        switch e {
                        case .response(let id, let response):
                            waiting.removeValue(forKey: id)?.resolve(.success(response))
                        case .reset(let id, let code):
                            waiting.removeValue(forKey: id)?.resolve(.failure(.stream(code)))
                        case .goaway(let last, let code):
                            // Streams above `last` were never seen: they fail.
                            for (id, slot) in waiting where id > last {
                                slot.resolve(.failure(.goaway(code)))
                                waiting[id] = nil
                            }
                            for (_, slot) in queued { slot.resolve(.failure(.goaway(code))) }
                            queued = []
                        case .request, .bodyTooLarge:
                            break
                        }
                    }
                } catch {
                    goaway(0, error.code, into: &out)
                    try? await writer.write(out)
                    out.clear()
                    failure = .connection(error.code)
                    failAll(.connection(error.code))
                }
            case .readEnded:
                if failure == nil { failure = .closed }
                failAll(failure!)
            case .readFailed(let error):
                if failure == nil {
                    if case .connection(let code) = error { goaway(0, code, into: &out) }
                    failure = error
                }
                failAll(failure!)
            case .bodyDone:
                if failure == nil {
                    goaway(0, .noError, into: &out)
                    try? await writer.write(out)
                }
                failAll(.closed)
                inbox.close()
                return
            case .response, .shutdown:
                break
            }
            if failure == nil {
                if core.goawayReceived != nil {
                    for (_, slot) in queued { slot.resolve(.failure(.goaway(.noError))) }
                    queued = []
                }
                while !queued.isEmpty && core.canOpenStream {
                    let (request, slot) = queued.removeFirst()
                    do throws(HTTP2Error) {
                        let id = try core.open(request, scheme: scheme, authority: authority, into: &out)
                        waiting[id] = slot
                    } catch {
                        slot.resolve(.failure(error))
                    }
                }
            }
        }
    }
}

private func goaway(_ lastStreamID: UInt32, _ code: HTTP2ErrorCode, into out: inout IOBuffer) {
    HTTP2Frame(streamID: 0, payload: .goaway(lastStreamID: lastStreamID, code, debug: [])).write(into: &out)
}

/// What a connection loop hears about.
enum LoopEvent: Sendable {
    case frame(HTTP2Frame)
    /// The peer closed its side.
    case readEnded
    case readFailed(HTTP2Error)
    /// A handler's answer (server).
    case response(UInt32, HTTPResponse)
    /// A request to send (client).
    case request(HTTPRequest, ResponseSlot)
    /// The client's scope ended.
    case bodyDone
    /// The server's shutdown signal triggered.
    case shutdown
}

/// The sending side of a loop's channel, shared by the tasks that feed it.
final class Mailbox: Sendable {
    private let sender: Channel<LoopEvent>.Sender

    init(_ sender: consuming Channel<LoopEvent>.Sender) {
        self.sender = sender
    }

    /// False once the loop has gone.
    func post(_ event: LoopEvent) async -> Bool {
        do throws(ChannelError) {
            try await sender.sendIgnoringCancellation(event)
            return true
        } catch {
            return false
        }
    }
}

/// A response to come, resolved by the connection loop.
final class ResponseSlot: Sendable {
    private struct State {
        var result: Result<HTTPResponse, HTTP2Error>?
        var waiter: CheckedContinuation<Result<HTTPResponse, HTTP2Error>, Never>?
    }

    private let state = Mutex(State())

    func resolve(_ result: Result<HTTPResponse, HTTP2Error>) {
        let waiter = state.withLock { s -> CheckedContinuation<Result<HTTPResponse, HTTP2Error>, Never>? in
            guard s.result == nil else { return nil }
            s.result = result
            defer { s.waiter = nil }
            return s.waiter
        }
        waiter?.resume(returning: result)
    }

    func value() async throws(HTTP2Error) -> HTTPResponse {
        let result = await withCheckedContinuation { (c: CheckedContinuation<Result<HTTPResponse, HTTP2Error>, Never>) in
            let ready = state.withLock { s -> Result<HTTPResponse, HTTP2Error>? in
                if s.result == nil { s.waiter = c }
                return s.result
            }
            if let ready { c.resume(returning: ready) }
        }
        return try result.get()
    }
}

/// Moves a `~Copyable` value into a task.
final class Handoff<Value: ~Copyable>: @unchecked Sendable {
    private var value: Value?

    init(_ value: consuming Value) { self.value = consume value }

    func take() -> Value { value.take()! }
}

/// Read frames from `reader` and post them, until the stream ends or fails.
private func readFrames<Reader: AsyncReader & ~Copyable>(
    _ reader: consuming Reader, preface: Bool, maxFrameSize: Int, to mailbox: Mailbox
) async {
    var buffer = IOBuffer(capacity: max(64 * 1024, maxFrameSize + HTTP2Frame.headerSize))
    var start = 0
    var needPreface = preface
    let codec = HTTP2FrameCodec(maxFrameSize: maxFrameSize)
    while true {
        while true {
            let s = start
            if needPreface {
                guard buffer.count - s >= HTTP2Frame.preface.count else { break }
                let matches = buffer.withUnsafeBytes { b in
                    HTTP2Frame.preface.withUnsafeBytes { $0.elementsEqual(b[s..<s + HTTP2Frame.preface.count]) }
                }
                guard matches else {
                    _ = await mailbox.post(.readFailed(.connection(.protocolError)))
                    return
                }
                start += HTTP2Frame.preface.count
                needPreface = false
                continue
            }
            let decoded: (item: HTTP2Frame, consumed: Int)?
            do throws(FrameError) {
                decoded = try buffer.withUnsafeBytes { b throws(FrameError) in
                    try codec.decodeFrame(UnsafeRawBufferPointer(rebasing: b[s...]))
                }
            } catch {
                _ = await mailbox.post(.readFailed(.connection(error.code)))
                return
            }
            guard let (frame, used) = decoded else { break }
            start += used
            guard await mailbox.post(.frame(frame)) else { return }
        }
        if start > 0 {
            buffer.consume(start)
            start = 0
        }
        do throws(IOError) {
            if try await reader.read(into: &buffer) == 0 {
                _ = await mailbox.post(.readEnded)
                return
            }
        } catch {
            _ = await mailbox.post(.readFailed(.io(error)))
            return
        }
    }
}
