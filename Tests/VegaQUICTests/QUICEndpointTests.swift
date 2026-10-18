// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
//===----------------------------------------------------------------------===//
// QUICEndpoint over a real UDP socket: the tests' client (QUICTestPeer)
// sends from a socket of its own, and the server side is an application's
// tasks on QUICConnection and QUICStream.
//===----------------------------------------------------------------------===//

import Testing
import Vega
import VegaIO
import VegaCrypto
import VegaTLS
import QUICTestPeer
import VegaQUIC
@_spi(Garuda) @testable import VegaQUICCore

/// The test peer's datagrams over a socket.
final class Wire {
    let socket: UDPSocket
    let server: SocketAddress

    init(socket: consuming UDPSocket, server: SocketAddress) {
        self.socket = socket
        self.server = server
    }

    func send(_ datagram: [UInt8]) async throws {
        var buffer = IOBuffer(capacity: datagram.count)
        _ = datagram.withUnsafeBytes { buffer.append($0) }
        _ = try await socket.send(buffer, to: server)
    }

    /// Datagrams into `peer` until `done` or two seconds pass.
    func pump(into peer: QUICTestPeer, until done: () -> Bool) async throws {
        var buffer = IOBuffer(capacity: 2048)
        for _ in 0..<200 where !done() {
            buffer.clear()
            do throws(IOError) {
                _ = try await Runtime.withIOTimeout(for: .milliseconds(10)) { () async throws(IOError) -> Int in
                    try await self.socket.receiveFrom(into: &buffer).count
                }
            } catch {
                if error == .timedOut { continue }
                throw error
            }
            try peer.receive(buffer.withUnsafeBytes { Array($0) })
        }
    }
}

func serverConfig() throws -> QUICServerConfiguration {
    let identity = try TLSIdentity.selfSigned(names: ["localhost"])
    let certificate = try CertificateKey(chainPEM: identity.certificateChain, keyPEM: identity.privateKey)
    return QUICServerConfiguration(certificateKey: certificate, applicationProtocols: ["echo"])
}

/// A handshake, from the client's side, up to its Finished.
func handshake(_ client: QUICTestPeer, _ wire: Wire, alpn: String = "echo") async throws {
    let hello = client.clientHello(serverName: "localhost", alpn: [alpn])
    try await wire.send(try client.packet(.initial, cryptoFrame(offset: 0, hello)))
    try await wire.pump(into: client) { client.handshakeReceived }
    #expect(client.serverFinishedVerified)
    try await wire.send(try client.packet(.handshake, client.ack(.handshake)
                                           + cryptoFrame(offset: 0, client.finishedMessage)))
}

@Suite("QUICEndpoint")
struct QUICEndpointTests {
    @Test func acceptsAndEchoesAStream() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let config = try serverConfig()
        let (echoed, finished, alpn, name) = try rt.block { () async throws -> ([UInt8]?, Bool, String, String) in
            let endpoint = try QUICEndpoint.bind(host: "127.0.0.1", port: 0, configuration: config, runtime: rt)
            let server = rt.spawn { () async -> (String, String) in
                guard let connection = await endpoint.accept() else { return ("", "") }
                let alpn = connection.applicationProtocol, name = connection.serverName
                while let stream = await connection.acceptStream() {
                    rt.spawn {
                        guard let bytes = try? await stream.readAll() else { return }
                        try? await stream.write(bytes.reversed())
                        stream.finish()
                    }
                }
                return (alpn, name)
            }

            let wire = Wire(socket: try UDPSocket.bind(host: "127.0.0.1", port: 0),
                            server: try SocketAddress(host: "127.0.0.1", port: endpoint.localPort))
            let client = try QUICTestPeer()
            try await handshake(client, wire)
            try await wire.send(try client.packet(.application, client.ack(.application)
                                                   + streamFrame(0, Array("hello, quic".utf8), fin: true)))
            try await wire.pump(into: client) { client.finished.contains(0) }
            let echoed = client.streams[0]
            let finished = client.finished.contains(0)
            await endpoint.close(grace: .milliseconds(100))
            let (alpn, name) = await server.value
            return (echoed, finished, alpn, name)
        }
        #expect(echoed == Array("hello, quic".utf8.reversed()))
        #expect(finished)
        #expect(alpn == "echo")
        #expect(name == "localhost")
    }

    /// The server opens a stream to the client, and the client's reset of
    /// its own stream reaches the server's reader.
    @Test func serverOpensAStreamAndSeesAReset() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let config = try serverConfig()
        let (pushed, readError) = try rt.block { () async throws -> ([UInt8]?, QUICConnectionError?) in
            let endpoint = try QUICEndpoint.bind(host: "127.0.0.1", port: 0, configuration: config, runtime: rt)
            let server = rt.spawn { () async -> QUICConnectionError? in
                guard let connection = await endpoint.accept() else { return nil }
                if let push = try? await connection.openStream(unidirectional: true) {
                    try? await push.write(Array("pushed".utf8))
                    push.finish()
                }
                guard let stream = await connection.acceptStream() else { return nil }
                var buffer = IOBuffer(capacity: 1024)
                while (try? await stream.read(into: &buffer)) ?? 0 > 0 { buffer.clear() }
                return stream.error
            }
            let wire = Wire(socket: try UDPSocket.bind(host: "127.0.0.1", port: 0),
                            server: try SocketAddress(host: "127.0.0.1", port: endpoint.localPort))
            let client = try QUICTestPeer()
            try await handshake(client, wire)
            // Server-initiated unidirectional: ID 3.
            try await wire.pump(into: client) { client.finished.contains(3) }
            try await wire.send(try client.packet(.application, client.ack(.application)
                                                   + streamFrame(0, Array("part".utf8), fin: false)
                                                   + resetStreamFrame(0, code: 7, finalSize: 4)))
            let readError = await server.value
            await endpoint.close(grace: .milliseconds(100))
            return (client.streams[3], readError)
        }
        #expect(pushed == Array("pushed".utf8))
        #expect(readError == .streamReset(code: 7))
    }

    @Test func closeEndsAccept() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let config = try serverConfig()
        let accepted = try rt.block { () async throws -> Bool in
            let endpoint = try QUICEndpoint.bind(host: "127.0.0.1", port: 0, configuration: config, runtime: rt)
            let waiter = rt.spawn { await endpoint.accept() != nil }
            try? await Runtime.sleep(for: .milliseconds(20))
            await endpoint.close(grace: .zero)
            return await waiter.value
        }
        #expect(!accepted)
    }
}
#endif
