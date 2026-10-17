// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
//===----------------------------------------------------------------------===//
// QUICEndpoint as a client: `connect` from one endpoint to a server endpoint
// over real UDP on 127.0.0.1, both sides an application's tasks on
// QUICConnectionHandle and QUICStreamHandle.
//===----------------------------------------------------------------------===//

import Testing
import Vega
import VegaIO
import VegaCrypto
import VegaTLS
import VegaQUICNet
@testable import VegaQUIC

private func identity() throws -> (pem: String, key: CertificateKey) {
    let identity = try TLSIdentity.selfSigned(names: ["localhost"])
    return (identity.certificateChain,
            try CertificateKey(chainPEM: identity.certificateChain, keyPEM: identity.privateKey))
}

/// A server that answers each stream with its bytes reversed, and opens a
/// unidirectional stream of its own on every connection.
private func echoServer(_ endpoint: QUICEndpoint, _ rt: Runtime) -> Task<Void, Never> {
    rt.spawn {
        while let connection = await endpoint.accept() {
            rt.spawn {
                if let push = try? await connection.openStream(unidirectional: true) {
                    try? await push.write(Array("pushed".utf8))
                    push.finish()
                }
                while let stream = await connection.acceptStream() {
                    rt.spawn {
                        guard let bytes = try? await stream.readAll() else { return }
                        if stream.isUnidirectional { return }
                        try? await stream.write(bytes.reversed())
                        stream.finish()
                    }
                }
            }
        }
    }
}

@Suite("QUICEndpoint client")
struct QUICEndpointClientTests {
    @Test func connectsAndEchoesAStream() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (pem, key) = try identity()
        let serverConfig = QUICServerConfig(certKey: key, alpn: [Array("echo".utf8)])
        let verifier = try CertificateVerifier(trustRoots: .certificates(pem))
        let (echoed, ids, pushed, alpn) = try rt.block { () async throws -> ([UInt8], [UInt64], [UInt8], [UInt8]) in
            let server = try QUICEndpoint.listen(host: "127.0.0.1", port: 0, configuration: serverConfig, runtime: rt)
            let serving = echoServer(server, rt)
            let client = try QUICEndpoint.client(runtime: rt, host: "127.0.0.1")
            let config = QUICClientConfig(serverName: "localhost", alpn: [Array("echo".utf8)],
                                          certificateVerification: .verifier(verifier))
            let connection = try await client.connect(host: "127.0.0.1", port: server.localPort, configuration: config)
            let alpn = connection.alpn

            let stream = try await connection.openStream()
            try await stream.write(Array("hello, quic".utf8))
            stream.finish()
            let echoed = try await stream.readAll()

            // A second bidirectional stream and a unidirectional one: IDs 4
            // and 2, the client's own numbering.
            let second = try await connection.openStream()
            let uni = try await connection.openStream(unidirectional: true)
            try await uni.write(Array("one way".utf8))
            uni.finish()
            try await second.write(Array("ab".utf8))
            second.finish()
            #expect(try await second.readAll() == Array("ba".utf8))

            // The server's stream: 3.
            guard let push = await connection.acceptStream() else { throw QUICConnectionError.endpointClosed }
            let pushed = try await push.readAll()
            let ids = [stream.id, second.id, uni.id, push.id]

            connection.close()
            await client.close(grace: .milliseconds(100))
            await server.close(grace: .milliseconds(100))
            await serving.value
            return (echoed, ids, pushed, alpn)
        }
        #expect(echoed == Array("hello, quic".utf8.reversed()))
        #expect(ids == [0, 4, 2, 3])
        #expect(pushed == Array("pushed".utf8))
        #expect(alpn == Array("echo".utf8))
    }

    @Test func anUntrustedServerIsRefused() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (_, key) = try identity()
        let serverConfig = QUICServerConfig(certKey: key, alpn: [Array("echo".utf8)])
        let error = try rt.block { () async throws -> QUICConnectionError? in
            let server = try QUICEndpoint.listen(host: "127.0.0.1", port: 0, configuration: serverConfig, runtime: rt)
            let serving = echoServer(server, rt)
            let client = try QUICEndpoint.client(runtime: rt, host: "127.0.0.1")
            // The system's roots: a self-signed certificate is not among them.
            let config = QUICClientConfig(serverName: "localhost", alpn: [Array("echo".utf8)])
            var failure: QUICConnectionError?
            do throws(QUICConnectionError) {
                _ = try await client.connect(host: "127.0.0.1", port: server.localPort, configuration: config)
            } catch {
                failure = error
            }
            await client.close(grace: .zero)
            await server.close(grace: .milliseconds(100))
            await serving.value
            return failure
        }
        #expect(error == .connectionClosed(code: quicCryptoError(TLSAlert.badCertificate), application: false))
    }

    @Test func insecureNoVerificationConnects() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (_, key) = try identity()
        let serverConfig = QUICServerConfig(certKey: key, alpn: [Array("echo".utf8)])
        let echoed = try rt.block { () async throws -> [UInt8] in
            let server = try QUICEndpoint.listen(host: "127.0.0.1", port: 0, configuration: serverConfig, runtime: rt)
            let serving = echoServer(server, rt)
            let client = try QUICEndpoint.client(runtime: rt, host: "127.0.0.1")
            let config = QUICClientConfig(serverName: "localhost", alpn: [Array("echo".utf8)],
                                          certificateVerification: .insecureNoVerification)
            let connection = try await client.connect(host: "127.0.0.1", port: server.localPort, configuration: config)
            let stream = try await connection.openStream()
            try await stream.write(Array("abc".utf8))
            stream.finish()
            let echoed = try await stream.readAll()
            await client.close(grace: .milliseconds(100))
            await server.close(grace: .milliseconds(100))
            await serving.value
            return echoed
        }
        #expect(echoed == Array("cba".utf8))
    }
}
#endif
