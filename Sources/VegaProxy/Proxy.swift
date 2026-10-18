import Vega
import VegaIO
import VegaHTTP1

/// Why a proxy handshake failed.
public enum ProxyError: Error, Hashable, Sendable, CustomStringConvertible {
    case io(IOError)
    /// The other end isn't speaking the protocol.
    case malformed(String)
    /// The SOCKS server took no method offered, or refused the credentials.
    case authenticationFailed
    /// The SOCKS server couldn't make the connection.
    case socksRefused(SOCKS5.Reply)
    /// The HTTP proxy answered CONNECT with this status.
    case httpRefused(status: Int)

    public var description: String {
        switch self {
        case .io(let e): "\(e)"
        case .malformed(let why): "malformed proxy exchange: \(why)"
        case .authenticationFailed: "proxy authentication failed"
        case .socksRefused(let reply): "SOCKS server refused: \(reply)"
        case .httpRefused(let status): "HTTP proxy answered \(status)"
        }
    }
}

/// SOCKS version 5 (RFC 1928), with username/password authentication
/// (RFC 1929). The client side tunnels a stream through a SOCKS proxy;
/// the server side is the proxy.
///
/// ```swift
/// let tcp = try await TCPStream.connect(host: "proxy.local", port: 1080)
/// try await SOCKS5.connect(through: tcp, to: "example.com", port: 443)
/// // tcp now reaches example.com:443
/// ```
public enum SOCKS5 {
    public struct Credentials: Sendable, Hashable {
        public var username: String
        public var password: String

        public init(username: String, password: String) {
            self.username = username
            self.password = password
        }
    }

    public enum Command: UInt8, Sendable {
        case connect = 1, bind = 2, udpAssociate = 3
    }

    /// The server's answer to a request.
    public enum Reply: UInt8, Sendable, CustomStringConvertible {
        case succeeded = 0, generalFailure, notAllowed, networkUnreachable, hostUnreachable,
             connectionRefused, ttlExpired, commandNotSupported, addressTypeNotSupported

        public var description: String {
            switch self {
            case .succeeded: "succeeded"
            case .generalFailure: "general failure"
            case .notAllowed: "not allowed by ruleset"
            case .networkUnreachable: "network unreachable"
            case .hostUnreachable: "host unreachable"
            case .connectionRefused: "connection refused"
            case .ttlExpired: "TTL expired"
            case .commandNotSupported: "command not supported"
            case .addressTypeNotSupported: "address type not supported"
            }
        }
    }

    /// What a client asked the proxy for.
    public struct Request: Sendable, Hashable {
        public var command: Command
        /// A name, or an address as text.
        public var host: String
        public var port: Int
    }

    // MARK: Client

    /// Ask the SOCKS server at the other end of `stream` to connect to
    /// `host`:`port`. Afterwards the stream is the tunnel. A name is sent
    /// for the proxy to resolve; an address is sent as one.
    public static func connect<Stream: AsyncReader & AsyncWriter & ~Copyable>(
        through stream: borrowing Stream, to host: String, port: Int, credentials: Credentials? = nil
    ) async throws(ProxyError) {
        // Checked before anything is sent: SOCKS carries a name of at most
        // 255 bytes, and a shortened one would be another host.
        guard (0...65535).contains(port) else { throw .malformed("port \(port)") }
        let address = try encode(host)
        // Offer no authentication, or username/password if we have them.
        try await send(credentials == nil ? [5, 1, 0] : [5, 2, 0, 2], on: stream)
        let choice = try await readExactly(2, from: stream)
        guard choice[0] == 5 else { throw .malformed("version \(choice[0])") }
        switch choice[1] {
        case 0:
            break
        case 2:
            guard let credentials else { throw .authenticationFailed }
            let user = Array(credentials.username.utf8), pass = Array(credentials.password.utf8)
            guard user.count <= 255, pass.count <= 255 else { throw .authenticationFailed }
            try await send([1, UInt8(user.count)] + user + [UInt8(pass.count)] + pass, on: stream)
            let status = try await readExactly(2, from: stream)
            guard status[1] == 0 else { throw .authenticationFailed }
        default:
            throw .authenticationFailed
        }
        try await send([5, Command.connect.rawValue, 0] + address + [UInt8(port >> 8), UInt8(port & 0xFF)], on: stream)
        let head = try await readExactly(4, from: stream)
        guard head[0] == 5 else { throw .malformed("version \(head[0])") }
        guard let reply = Reply(rawValue: head[1]) else { throw .malformed("reply \(head[1])") }
        // The bound address and port, read so nothing of them is left for the tunnel.
        _ = try await readAddress(type: head[3], from: stream)
        _ = try await readExactly(2, from: stream)
        guard reply == .succeeded else { throw .socksRefused(reply) }
    }

    // MARK: Server

    /// Read a client's greeting and request. With `authenticate`, the
    /// client must log in with username/password; without, it must accept
    /// no authentication. Answer with `reply(_:on:)`.
    public static func accept<Stream: AsyncReader & AsyncWriter & ~Copyable>(
        _ stream: borrowing Stream, authenticate: ((Credentials) async -> Bool)? = nil
    ) async throws(ProxyError) -> Request {
        let greeting = try await readExactly(2, from: stream)
        guard greeting[0] == 5 else { throw .malformed("version \(greeting[0])") }
        let methods = try await readExactly(Int(greeting[1]), from: stream)
        let wanted: UInt8 = authenticate == nil ? 0 : 2
        guard methods.contains(wanted) else {
            try await send([5, 0xFF], on: stream)
            throw .authenticationFailed
        }
        try await send([5, wanted], on: stream)
        if let authenticate {
            let version = try await readExactly(2, from: stream)
            guard version[0] == 1 else { throw .malformed("auth version \(version[0])") }
            let user = try await readExactly(Int(version[1]), from: stream)
            let passLength = try await readExactly(1, from: stream)
            let pass = try await readExactly(Int(passLength[0]), from: stream)
            let ok = await authenticate(Credentials(username: String(decoding: user, as: UTF8.self),
                                                    password: String(decoding: pass, as: UTF8.self)))
            try await send([1, ok ? 0 : 1], on: stream)
            guard ok else { throw .authenticationFailed }
        }
        let head = try await readExactly(4, from: stream)
        guard head[0] == 5 else { throw .malformed("version \(head[0])") }
        let host = try await readAddress(type: head[3], from: stream)
        let portBytes = try await readExactly(2, from: stream)
        guard let command = Command(rawValue: head[1]) else {
            try await reply(.commandNotSupported, on: stream)
            throw .malformed("command \(head[1])")
        }
        return Request(command: command, host: host, port: Int(portBytes[0]) << 8 | Int(portBytes[1]))
    }

    /// Answer a request, with the address the proxy connected from.
    public static func reply<Stream: AsyncWriter & ~Copyable>(
        _ reply: Reply, bound: SocketAddress? = nil, on stream: borrowing Stream
    ) async throws(ProxyError) {
        let ip = bound?.ipBytes ?? [0, 0, 0, 0]
        let port = bound?.port ?? 0
        try await send([5, reply.rawValue, 0, ip.count == 16 ? 4 : 1] + ip + [UInt8(port >> 8), UInt8(port & 0xFF)], on: stream)
    }

    /// Be a SOCKS proxy for one client: CONNECT requests only, to wherever
    /// `allow` permits (everywhere by default), until both sides close.
    public static func serve(
        _ client: consuming TCPStream,
        authenticate: ((Credentials) async -> Bool)? = nil,
        allow: (Request) async -> Bool = { _ in true }
    ) async throws(ProxyError) {
        let request = try await accept(client, authenticate: authenticate)
        guard request.command == .connect else {
            try await reply(.commandNotSupported, on: client)
            return
        }
        guard await allow(request) else {
            try await reply(.notAllowed, on: client)
            return
        }
        let upstream: TCPStream
        do throws(IOError) {
            upstream = try await TCPStream.connect(host: request.host, port: request.port)
        } catch {
            let code: Reply = switch error {
            case .connectionRefused: .connectionRefused
            default: .hostUnreachable
            }
            try await reply(code, on: client)
            return
        }
        try await reply(.succeeded, bound: try? upstream.localAddress, on: client)
        do throws(IOError) {
            try await copyBidirectional(client.halves(), upstream.halves())
        } catch {
            throw .io(error)
        }
    }

    // MARK: Addresses

    /// ATYP and DST.ADDR for `host`.
    private static func encode(_ host: String) throws(ProxyError) -> [UInt8] {
        if let address = SocketAddress(numericHost: host, port: 0), let ip = address.ipBytes {
            return [ip.count == 16 ? 4 : 1] + ip
        }
        let name = Array(host.utf8)
        guard (1...255).contains(name.count) else { throw .malformed("host name of \(name.count) bytes") }
        return [3, UInt8(name.count)] + name
    }

    /// An address of `type`, as text, then the port is still to read.
    private static func readAddress<Stream: AsyncReader & ~Copyable>(type: UInt8, from stream: borrowing Stream) async throws(ProxyError) -> String {
        switch type {
        case 1, 4:
            let ip = try await readExactly(type == 1 ? 4 : 16, from: stream)
            return SocketAddress(ip: ip, port: 0)?.host ?? ""
        case 3:
            let length = try await readExactly(1, from: stream)
            return String(decoding: try await readExactly(Int(length[0]), from: stream), as: UTF8.self)
        default:
            throw .malformed("address type \(type)")
        }
    }
}

/// Tunnelling through an HTTP proxy with CONNECT (RFC 9110 section 9.3.6).
public enum HTTPProxy {
    /// Ask the proxy at the other end of `stream` for a tunnel to
    /// `authority` ("host:port"). Returns any bytes that came after the
    /// proxy's answer, which belong to the tunnel: read them first, or wrap
    /// the stream in a `PrefixedStream`.
    public static func connect<Stream: AsyncReader & AsyncWriter & ~Copyable>(
        through stream: borrowing Stream, to authority: String, fields: HTTPFields = [:]
    ) async throws(ProxyError) -> [UInt8] {
        var head = HTTPRequestHead(method: .connect, target: authority, fields: fields)
        if !head.fields.contains("host") { head.fields["host"] = authority }
        var encoder = HTTP1RequestEncoder()
        var out = IOBuffer(capacity: 256)
        do throws(HTTP1Error) {
            try encoder.encodePart(.head(head), into: &out)
        } catch {
            throw .malformed("\(error)")
        }
        do throws(IOError) { try await stream.write(out) } catch { throw .io(error) }

        var decoder = HTTP1ResponseDecoder()
        decoder.requestSent(.connect)
        var input = IOBuffer(capacity: 1024)
        var used = 0
        while true {
            let at = used
            let decoded: (item: HTTPResponsePart, consumed: Int)?
            do throws(HTTP1Error) {
                decoded = try input.withUnsafeBytes { all throws(HTTP1Error) in
                    try decoder.decodePart(UnsafeRawBufferPointer(rebasing: all[at...]))
                }
            } catch {
                throw .malformed("\(error)")
            }
            if let (part, n) = decoded {
                used += n
                guard case .head(let response) = part else { continue }
                // Interim responses come before the real one.
                if response.status < 200 { continue }
                guard response.status / 100 == 2 else { throw .httpRefused(status: response.status) }
                let start = used
                return input.withUnsafeBytes { Array($0[start...]) }
            }
            if input.spareCapacity == 0 { input.reserveCapacity(input.capacity * 2) }
            let n: Int
            do throws(IOError) { n = try await stream.read(into: &input) } catch { throw .io(error) }
            if n == 0 { throw .malformed("the proxy closed the connection") }
        }
    }
}

// MARK: - Exact reads and writes

/// Exactly `n` bytes, reading no further: what follows belongs to the tunnel.
private func readExactly<Stream: AsyncReader & ~Copyable>(_ n: Int, from stream: borrowing Stream) async throws(ProxyError) -> [UInt8] {
    guard n > 0 else { return [] }
    var buffer = IOBuffer(capacity: n)
    while buffer.count < n {
        let got: Int
        do throws(IOError) { got = try await stream.read(into: &buffer) } catch { throw .io(error) }
        if got == 0 { throw .malformed("the connection closed") }
    }
    return buffer.withUnsafeBytes { Array($0) }
}

private func send<Stream: AsyncWriter & ~Copyable>(_ bytes: [UInt8], on stream: borrowing Stream) async throws(ProxyError) {
    var buffer = IOBuffer(capacity: max(bytes.count, 1))
    bytes.withUnsafeBytes { buffer.write($0) }
    do throws(IOError) { try await stream.write(buffer) } catch { throw .io(error) }
}
