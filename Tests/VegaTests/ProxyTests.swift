import Synchronization
import Testing
import Vega
import VegaIO
import VegaHTTP1
import VegaProxy

/// An echo server on a fresh port; returns the port.
private func echoServer(_ rt: Runtime) throws -> Int {
    let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
    let port = listener.localPort
    rt.spawn(with: listener) { l async in
        while let conn = try? await l.accept() {
            rt.spawn(with: conn) { conn async in _ = try? await copy(from: conn, to: conn) }
        }
    }
    return port
}

/// A SOCKS proxy on a fresh port; returns the port.
private func socksProxy(_ rt: Runtime, authenticate: (@Sendable (SOCKS5.Credentials) async -> Bool)? = nil) throws -> Int {
    let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
    let port = listener.localPort
    rt.spawn(with: listener) { l async in
        while let conn = try? await l.accept() {
            rt.spawn(with: conn) { conn async in
                if let authenticate {
                    try? await SOCKS5.serve(conn, authenticate: { await authenticate($0) })
                } else {
                    try? await SOCKS5.serve(conn)
                }
            }
        }
    }
    return port
}

private func roundTrip(_ stream: borrowing TCPStream, _ text: String) async throws -> String {
    var out = IOBuffer(capacity: 256)
    out.append(text)
    try await stream.write(out)
    var back = IOBuffer(capacity: 256)
    _ = try await readAtLeast(text.utf8.count, from: stream, into: &back)
    return back.string
}

@Suite struct ProxyTests {
    @Test func socksTunnel() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let echoed = try rt.block { () async throws -> [String] in
            let echo = try echoServer(rt)
            let proxy = try socksProxy(rt)
            var out: [String] = []
            // By address, and by name for the proxy to resolve.
            for host in ["127.0.0.1", "localhost"] {
                let tcp = try await TCPStream.connect(host: "127.0.0.1", port: proxy)
                try await SOCKS5.connect(through: tcp, to: host, port: echo)
                out.append(try await roundTrip(tcp, "via \(host)"))
            }
            return out
        }
        #expect(echoed == ["via 127.0.0.1", "via localhost"])
    }

    @Test func socksAuthentication() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let (good, bad, none) = try rt.block { () async throws -> (String, ProxyError?, ProxyError?) in
            let echo = try echoServer(rt)
            let proxy = try socksProxy(rt) { $0 == SOCKS5.Credentials(username: "vega", password: "s3cret") }
            let tcp = try await TCPStream.connect(host: "127.0.0.1", port: proxy)
            try await SOCKS5.connect(through: tcp, to: "127.0.0.1", port: echo,
                                     credentials: .init(username: "vega", password: "s3cret"))
            let good = try await roundTrip(tcp, "authed")
            func failure(_ credentials: SOCKS5.Credentials?) async throws -> ProxyError? {
                let tcp = try await TCPStream.connect(host: "127.0.0.1", port: proxy)
                do throws(ProxyError) {
                    try await SOCKS5.connect(through: tcp, to: "127.0.0.1", port: echo, credentials: credentials)
                    return nil
                } catch {
                    return error
                }
            }
            return (good, try await failure(.init(username: "vega", password: "wrong")), try await failure(nil))
        }
        #expect(good == "authed")
        #expect(bad == .authenticationFailed)
        #expect(none == .authenticationFailed)
    }

    @Test func socksRefusal() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let error = try rt.block { () async throws -> ProxyError? in
            let proxy = try socksProxy(rt)
            // A port nothing listens on.
            let closed = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = closed.localPort
            _ = consume closed
            let tcp = try await TCPStream.connect(host: "127.0.0.1", port: proxy)
            do throws(ProxyError) {
                try await SOCKS5.connect(through: tcp, to: "127.0.0.1", port: port)
                return nil
            } catch {
                return error
            }
        }
        #expect(error == .socksRefused(.connectionRefused))
    }

    /// A proxy whose 200 arrives in the same packet as the tunnel's first
    /// bytes: they come back as leftover, and a PrefixedStream reads them first.
    @Test func httpConnect() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let (target, banner, refused) = try rt.block { () async throws -> (String, String, ProxyError?) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            let seen = Box()
            rt.spawn(with: listener) { l async in
                while let conn = try? await l.accept() {
                    rt.spawn(with: conn) { conn async in
                        var buf = IOBuffer(capacity: 1024)
                        _ = try? await conn.read(into: &buf)
                        let line = buf.string.split(separator: "\r\n").first.map(String.init) ?? ""
                        let blocked = line.contains("blocked")
                        if !blocked { seen.value = line }
                        var reply = IOBuffer(capacity: 256)
                        reply.append(blocked ? "HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n"
                                             : "HTTP/1.1 200 Connection established\r\n\r\nSSH-2.0-banner\r\n")
                        try? await conn.write(reply)
                        _ = try? await copy(from: conn, to: conn)
                    }
                }
            }
            let tcp = try await TCPStream.connect(host: "127.0.0.1", port: port)
            let leftover = try await HTTPProxy.connect(through: tcp, to: "example.com:22")
            let tunnel = PrefixedStream(tcp, prefix: leftover)
            var buf = IOBuffer(capacity: 64)
            _ = try await readAtLeast(16, from: tunnel, into: &buf)
            let other = try await TCPStream.connect(host: "127.0.0.1", port: port)
            let refused: ProxyError?
            do throws(ProxyError) {
                _ = try await HTTPProxy.connect(through: other, to: "blocked.example:443")
                refused = nil
            } catch {
                refused = error
            }
            return (seen.value, buf.string, refused)
        }
        #expect(target.hasPrefix("CONNECT "))
        #expect(banner == "SSH-2.0-banner\r\n")
        #expect(refused == .httpRefused(status: 403))
    }

    /// Bytes both ways, and an end on one side passes through.
    @Test func bidirectionalCopy() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let (reply, counts) = try rt.block { () async throws -> (String, (Int, Int)) in
            let echo = try echoServer(rt)
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            let relay = rt.spawn(with: listener) { l async -> (Int, Int) in
                guard let conn = try? await l.accept(),
                      let upstream = try? await TCPStream.connect(host: "127.0.0.1", port: echo),
                      let counts = try? await copyBidirectional(conn.split(), upstream.split())
                else { return (-1, -1) }
                return (counts.aToB, counts.bToA)
            }
            let tcp = try await TCPStream.connect(host: "127.0.0.1", port: port)
            var out = IOBuffer(capacity: 64)
            out.append("through the relay")
            try await tcp.write(out)
            try tcp.shutdownWrite()
            var back = IOBuffer(capacity: 64)
            while try await tcp.read(into: &back) > 0 {}
            return (back.string, await relay.value)
        }
        #expect(reply == "through the relay")
        #expect(counts == (17, 17))
    }
}

private final class Box: Sendable {
    private let stored = Mutex("")
    var value: String {
        get { stored.withLock { $0 } }
        set { stored.withLock { $0 = newValue } }
    }
}
