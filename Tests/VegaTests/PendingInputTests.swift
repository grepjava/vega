import Testing
import Vega
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import VegaTLS
#endif

// `hasPendingInput`: whether a read would return at once, asked without
// reading or waiting -- what a pool asks of an idle connection.

private func byte(_ value: UInt8) -> IOBuffer {
    var buffer = IOBuffer(capacity: 1)
    buffer.withUnsafeSpareCapacity { room in
        room.storeBytes(of: value, as: UInt8.self)
        return 1
    }
    return buffer
}

/// Polls `probe` until it says `want`, for up to a second: the bytes cross
/// loopback, not instantly.
private func eventually(_ want: Bool, _ probe: () -> Bool) async -> Bool {
    for _ in 0..<200 {
        if probe() == want { return true }
        try? await Runtime.sleep(for: .milliseconds(5))
    }
    return probe() == want
}

@Suite("hasPendingInput")
struct PendingInputTests {
    /// Quiet, then a byte, then read empty, then the peer's close.
    @Test func overTCP() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let seen = try rt.block { () async throws(IOError) -> [Bool] in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let server = try await listener.accept()
            var seen = [client.hasPendingInput]
            try await server.write(byte(1))
            seen.append(await eventually(true) { client.hasPendingInput })
            var buffer = IOBuffer(capacity: 8)
            _ = try await client.read(into: &buffer)
            seen.append(client.hasPendingInput)
            _ = consume server // closes it
            seen.append(await eventually(true) { client.hasPendingInput })
            return seen
        }
        #expect(seen == [false, true, false, true])
    }

    #if !os(Windows)
    @Test func overAUnixSocket() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let seen = try rt.block { () async throws(IOError) -> [Bool] in
            let pair = try UnixStream.pair()
            let a = pair.first, b = pair.second
            var seen = [a.hasPendingInput]
            try await b.write(byte(7))
            seen.append(await eventually(true) { a.hasPendingInput })
            return seen
        }
        #expect(seen == [false, true])
    }
    #endif

    #if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
    /// Once a round trip has taken the handshake's leftovers, an idle TLS
    /// connection is quiet, and a record from the peer is input.
    @Test func overTLS() throws {
        let identity = try TLSIdentity.selfSigned(names: ["vega.test"])
        let server = try TLSContext(.server(identity: identity))
        let client = try TLSContext(.client(trustRoots: .certificates(identity.certificateChain)))
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let seen = try rt.block { () async throws(IOError) -> [Bool] in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            let peer = rt.spawn(with: listener) { listener async -> Bool in
                do throws(IOError) {
                    let tls = try await TLSStream.accept(try await listener.accept(), context: server)
                    var buffer = IOBuffer(capacity: 8)
                    _ = try await tls.read(into: &buffer)
                    try await tls.write(byte(2))
                    _ = try await tls.read(into: &buffer) // the client's go-ahead
                    try await tls.write(byte(3))
                    _ = try await tls.read(into: &buffer) // until the client closes
                    return true
                } catch {
                    return false
                }
            }
            let tcp = try await TCPStream.connect(host: "127.0.0.1", port: port)
            let tls = try await TLSStream.connect(tcp, serverName: "vega.test", context: client)
            var buffer = IOBuffer(capacity: 8)
            try await tls.write(byte(1))
            _ = try await tls.read(into: &buffer)
            var seen = [tls.hasPendingInput]
            try await tls.write(byte(1))
            seen.append(await eventually(true) { tls.hasPendingInput })
            buffer.clear()
            _ = try await tls.read(into: &buffer)
            seen.append(tls.hasPendingInput)
            _ = consume tls // closes it, which ends the peer's last read
            _ = await peer.value
            return seen
        }
        #expect(seen == [false, true, false])
    }
    #endif
}
