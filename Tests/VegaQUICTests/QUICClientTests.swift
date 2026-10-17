// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
//===----------------------------------------------------------------------===//
// The client role: a client QUICConnection against a server QUICConnection,
// in memory -- the handshake, streams each way, HANDSHAKE_DONE, close, Retry
// and Version Negotiation -- and the certificate checks behind it.
//===----------------------------------------------------------------------===//

import Testing
import VegaCrypto
import VegaTLS
@testable import VegaWire
@testable import VegaQUIC

private func makeIdentity(_ names: [String] = ["localhost"]) throws -> (pem: String, key: CertificateKey) {
    let identity = try TLSIdentity.selfSigned(names: names)
    return (identity.certificateChain,
            try CertificateKey(chainPEM: identity.certificateChain, keyPEM: identity.privateKey))
}

private func datagrams(_ connection: QUICConnection, nowMs: UInt64) -> [[UInt8]] {
    var out: [[UInt8]] = []
    var buffer = [UInt8](repeating: 0, count: 1500)
    while true {
        let n = buffer.withUnsafeMutableBufferPointer { connection.nextDatagram($0.baseAddress!, $0.count, nowMs: nowMs) }
        if n == 0 { return out }
        out.append(Array(buffer[0..<n]))
    }
}

private func deliver(_ datagram: [UInt8], to connection: QUICConnection, nowMs: UInt64) {
    var datagram = datagram
    datagram.withUnsafeMutableBufferPointer { connection.receive($0.baseAddress!, $0.count, ecn: 0, nowMs: nowMs) }
}

private func header(_ datagram: [UInt8]) -> QUICPacketHeader {
    datagram.withUnsafeBufferPointer { QUICPacket.parseHeader($0.baseAddress!, $0.count, localCIDLength: quicLocalCIDLength) }
}

/// Everything a stream has delivered so far, taken.
private func take(_ connection: QUICConnection, _ id: UInt64) -> [UInt8] {
    guard let stream = connection.stream(id) else { return [] }
    let n = stream.receive.ready.readableBytes
    let bytes = [UInt8](UnsafeBufferPointer(start: stream.receive.ready.readPointer, count: n))
    stream.receive.ready.consume(n)
    return bytes
}

/// A client and the server it reaches, the server made from the client's
/// first Initial as a listener would make it.
private final class Link {
    let client: QUICConnection
    var server: QUICConnection?
    let serverConfig: QUICServerConfig
    var now: UInt64 = 1_000
    /// What the server is made with, on the first Initial.
    var retry: (originalDCID: QUICConnectionID, retrySCID: QUICConnectionID)?
    var serverCID = QUICConnectionID.random()

    init(client: QUICClientConfig, server: QUICServerConfig) throws {
        self.client = try #require(QUICConnection(client: client, nowMs: 1_000))
        self.serverConfig = server
    }

    /// Datagrams back and forth until neither side has anything to say.
    func run(rounds: Int = 16) throws {
        for _ in 0..<rounds {
            now += 5
            let up = datagrams(client, nowMs: now)
            for datagram in up {
                if server == nil {
                    let h = header(datagram)
                    server = try #require(QUICConnection(config: serverConfig, version: h.version, clientDCID: h.dcid,
                                                         clientSCID: h.scid, localCID: serverCID, nowMs: now,
                                                         retry: retry))
                }
                deliver(datagram, to: server!, nowMs: now)
            }
            guard let server else { return }
            let down = datagrams(server, nowMs: now)
            for datagram in down { deliver(datagram, to: client, nowMs: now) }
            if up.isEmpty && down.isEmpty { return }
        }
    }
}

private func trusting(_ pem: String) throws -> QUICCertificateVerification {
    .verifier(try CertificateVerifier(trustRoots: .certificates(pem)))
}

@Suite("QUIC client")
struct QUICClientTests {
    @Test func firstDatagramIsAPaddedInitialWithTheClientHello() throws {
        let client = try #require(QUICConnection(client: QUICClientConfig(serverName: "localhost", alpn: [Array("h3".utf8)],
                                                                          certificateVerification: .insecureNoVerification),
                                                 nowMs: 0))
        #expect(!client.isServer)
        let first = datagrams(client, nowMs: 0)
        try #require(first.count == 1)
        #expect(first[0].count == QUICPacket.minimumInitialSize)
        let h = header(first[0])
        #expect(h.isValid && h.type == .initial)
        #expect(h.dcid == client.originalDCID && h.dcid.length >= 8)
        #expect(h.scid == client.localCID && Int(h.scid.length) == quicLocalCIDLength)
        #expect(h.token.count == 0)
    }

    @Test func handshakeStreamsAndClose() throws {
        let (pem, key) = try makeIdentity()
        let link = try Link(client: QUICClientConfig(serverName: "localhost", alpn: [Array("h3".utf8), Array("echo".utf8)],
                                                     certificateVerification: trusting(pem)),
                            server: QUICServerConfig(certKey: key, alpn: [Array("echo".utf8)]))
        try link.run()
        let client = link.client
        let server = try #require(link.server)
        #expect(client.tlsAlert == nil && server.tlsAlert == nil)
        #expect(client.status == .connected && server.status == .connected)
        #expect(client.handshakeComplete)
        #expect(client.selectedALPN == Array("echo".utf8))
        #expect(server.serverName == Array("localhost".utf8))
        // The client moved to the server's own connection ID.
        #expect(client.peerCID == server.localCID)
        #expect(client.peerCertificates.count == 1)
        // HANDSHAKE_DONE confirmed it, and both earlier levels' keys are gone:
        // the Initial ones when the first Handshake packet went, the
        // Handshake ones at confirmation.
        #expect(client.handshakeConfirmed)
        #expect(!client.keys[QUICLevel.initial.rawValue].send.isValid)
        #expect(!client.keys[QUICLevel.handshake.rawValue].send.isValid)
        #expect(client.takeEvents().contains { $0.kind == .handshakeComplete })
        _ = server.takeEvents()

        // The client's streams: bidirectional 0, 4; unidirectional 2.
        #expect(client.openStream(unidirectional: false) == 0)
        #expect(client.openStream(unidirectional: true) == 2)
        #expect(client.openStream(unidirectional: false) == 4)
        Array("ping".utf8).withUnsafeBufferPointer { client.send(0, $0.baseAddress!, $0.count, fin: true) }
        Array("one way".utf8).withUnsafeBufferPointer { client.send(2, $0.baseAddress!, $0.count, fin: true) }
        try link.run()
        #expect(take(server, 0) == Array("ping".utf8))
        #expect(take(server, 2) == Array("one way".utf8))
        #expect(server.stream(0)?.receive.finished == true)

        // The server's answer on 0, and streams of its own: 1 and 3.
        Array("pong".utf8).withUnsafeBufferPointer { server.send(0, $0.baseAddress!, $0.count, fin: true) }
        #expect(server.openStream(unidirectional: false) == 1)
        #expect(server.openStream(unidirectional: true) == 3)
        Array("push".utf8).withUnsafeBufferPointer { server.send(3, $0.baseAddress!, $0.count, fin: true) }
        Array("ask".utf8).withUnsafeBufferPointer { server.send(1, $0.baseAddress!, $0.count, fin: false) }
        try link.run()
        let events = client.takeEvents()
        #expect(events.contains { $0.kind == .streamFinished && $0.streamID == 0 })
        #expect(events.contains { $0.kind == .streamReadable && $0.streamID == 3 })
        #expect(take(client, 0) == Array("pong".utf8))
        #expect(take(client, 3) == Array("push".utf8))
        #expect(take(client, 1) == Array("ask".utf8))
        // And the client answers on the server's bidirectional stream.
        Array("answer".utf8).withUnsafeBufferPointer { client.send(1, $0.baseAddress!, $0.count, fin: true) }
        try link.run()
        #expect(take(server, 1) == Array("answer".utf8))
        #expect(client.status == .connected && server.status == .connected)

        // A close from the client, with an application code.
        _ = server.takeEvents()
        client.close(7, application: true, reason: Array("bye".utf8))
        try link.run()
        #expect(server.status == .closing)
        #expect(server.closeError == 7 && server.closeIsApplication)
        #expect(server.takeEvents().contains { $0.kind == .closed && $0.code == 7 })
    }

    @Test func aStreamTheServerHasNotOpenedIsAnError() throws {
        let (pem, key) = try makeIdentity()
        let link = try Link(client: QUICClientConfig(serverName: "localhost", alpn: [Array("h3".utf8)],
                                                     certificateVerification: trusting(pem)),
                            server: QUICServerConfig(certKey: key, alpn: [Array("h3".utf8)]))
        try link.run()
        // The client sending on stream 3, the server's unidirectional one:
        // the server did not open it, and could not have been written to.
        let client = link.client
        let stray = QUICStream(id: 3)
        stray.send.limit = 1 << 16
        client.streams[3] = stray
        Array("x".utf8).withUnsafeBufferPointer { client.send(3, $0.baseAddress!, $0.count, fin: true) }
        try link.run()
        #expect(link.server?.closeError == QUICError.streamStateError.rawValue)
    }

    @Test func certificateFromAnUntrustedRootIsRefused() throws {
        let (_, key) = try makeIdentity()
        let (otherPEM, _) = try makeIdentity()
        let link = try Link(client: QUICClientConfig(serverName: "localhost", alpn: [Array("h3".utf8)],
                                                     certificateVerification: trusting(otherPEM)),
                            server: QUICServerConfig(certKey: key, alpn: [Array("h3".utf8)]))
        try link.run()
        #expect(link.client.tlsAlert == TLSAlert.badCertificate)
        #expect(link.client.certificateError != nil)
        #expect(link.client.closeError == quicCryptoError(TLSAlert.badCertificate))
        // The server heard why.
        #expect(link.server?.closeError == quicCryptoError(TLSAlert.badCertificate))
    }

    @Test func certificateForAnotherNameIsRefused() throws {
        let (pem, key) = try makeIdentity()
        let link = try Link(client: QUICClientConfig(serverName: "example.com", alpn: [Array("h3".utf8)],
                                                     certificateVerification: trusting(pem)),
                            server: QUICServerConfig(certKey: key, alpn: [Array("h3".utf8)]))
        try link.run()
        #expect(link.client.tlsAlert == TLSAlert.badCertificate)
        #expect(link.client.status != .connected)
    }

    @Test func aCustomCheckSeesTheChainAndTheName() throws {
        let (_, key) = try makeIdentity()
        let seen = Seen()
        let link = try Link(client: QUICClientConfig(serverName: "localhost", alpn: [Array("h3".utf8)],
                                                     certificateVerification: .custom { chain, name in
                                                         seen.record(chain.count, name)
                                                         return true
                                                     }),
                            server: QUICServerConfig(certKey: key, alpn: [Array("h3".utf8)]))
        try link.run()
        #expect(link.client.status == .connected)
        #expect(seen.value == (1, "localhost"))
    }

    @Test func noCommonApplicationProtocolFails() throws {
        let (pem, key) = try makeIdentity()
        let link = try Link(client: QUICClientConfig(serverName: "localhost", alpn: [Array("h3".utf8)],
                                                     certificateVerification: trusting(pem)),
                            server: QUICServerConfig(certKey: key, alpn: [Array("echo".utf8)]))
        try link.run()
        #expect(link.server?.tlsAlert == TLSAlert.noApplicationProtocol)
        #expect(link.client.closeError == quicCryptoError(TLSAlert.noApplicationProtocol))
    }

    @Test func retryIsFollowed() throws {
        let (pem, key) = try makeIdentity()
        let link = try Link(client: QUICClientConfig(serverName: "localhost", alpn: [Array("h3".utf8)],
                                                     certificateVerification: trusting(pem)),
                            server: QUICServerConfig(certKey: key, alpn: [Array("h3".utf8)]))
        let client = link.client
        let first = datagrams(client, nowMs: link.now)
        let h = header(first[0])
        let retrySCID = QUICConnectionID.random()
        let token = Array("an address token".utf8)

        // A Retry with a bad tag, and one naming the client's own first
        // connection ID, are dropped.
        var forged = try #require(QUICRetry.packet(version: QUICVersion.v1, clientSCID: h.scid, retrySCID: retrySCID,
                                                   originalDCID: h.dcid, token: token))
        forged[forged.count - 1] ^= 1
        deliver(forged, to: client, nowMs: link.now)
        #expect(client.peerCID == client.originalDCID)
        let echoing = try #require(QUICRetry.packet(version: QUICVersion.v1, clientSCID: h.scid, retrySCID: h.dcid,
                                                    originalDCID: h.dcid, token: token))
        deliver(echoing, to: client, nowMs: link.now)
        #expect(client.peerCID == client.originalDCID)

        let retry = try #require(QUICRetry.packet(version: QUICVersion.v1, clientSCID: h.scid, retrySCID: retrySCID,
                                                  originalDCID: h.dcid, token: token))
        deliver(retry, to: client, nowMs: link.now)
        #expect(client.peerCID == retrySCID)

        // The ClientHello again, to the Retry's connection ID, with its token.
        let second = datagrams(client, nowMs: link.now)
        try #require(!second.isEmpty)
        #expect(second[0].count == QUICPacket.minimumInitialSize)
        let h2 = header(second[0])
        #expect(h2.type == .initial && h2.dcid == retrySCID && h2.scid == client.localCID)
        #expect(Array(UnsafeBufferPointer(start: h2.token.base, count: h2.token.count)) == token)

        // A second Retry is one too many.
        let again = try #require(QUICRetry.packet(version: QUICVersion.v1, clientSCID: h.scid,
                                                  retrySCID: QUICConnectionID.random(), originalDCID: retrySCID,
                                                  token: token))
        deliver(again, to: client, nowMs: link.now)
        #expect(client.peerCID == retrySCID)

        // A server that knows about the Retry, made from the second Initial.
        link.retry = (h.dcid, retrySCID)
        link.server = try #require(QUICConnection(config: link.serverConfig, version: h2.version, clientDCID: h2.dcid,
                                                  clientSCID: h2.scid, localCID: link.serverCID, nowMs: link.now,
                                                  retry: link.retry))
        for datagram in second { deliver(datagram, to: link.server!, nowMs: link.now) }
        try link.run()
        #expect(client.status == .connected)
        #expect(link.server?.status == .connected)
    }

    @Test func transportParametersMustMatchTheConnectionIDsSeen() throws {
        // A server claiming a Retry the client never had: someone rewrote
        // the handshake, and the client closes with TRANSPORT_PARAMETER_ERROR.
        let (pem, key) = try makeIdentity()
        let link = try Link(client: QUICClientConfig(serverName: "localhost", alpn: [Array("h3".utf8)],
                                                     certificateVerification: trusting(pem)),
                            server: QUICServerConfig(certKey: key, alpn: [Array("h3".utf8)]))
        link.retry = (link.client.originalDCID, QUICConnectionID.random())
        try link.run()
        #expect(link.client.status != .connected)
        #expect(link.client.closeError == QUICError.transportParameterError.rawValue)
    }

    @Test func versionNegotiationEndsTheAttempt() throws {
        let client = try #require(QUICConnection(client: QUICClientConfig(serverName: "localhost", alpn: [Array("h3".utf8)],
                                                                          certificateVerification: .insecureNoVerification),
                                                 nowMs: 0))
        _ = datagrams(client, nowMs: 0)
        func negotiation(_ versions: [UInt32]) -> [UInt8] {
            var out: [UInt8] = [0xC5, 0, 0, 0, 0, client.localCID.length]
            client.localCID.withBytes { out += UnsafeBufferPointer(start: $0, count: $1) }
            out.append(client.originalDCID.length)
            client.originalDCID.withBytes { out += UnsafeBufferPointer(start: $0, count: $1) }
            for v in versions { out += [UInt8(v >> 24), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)] }
            return out
        }
        // One listing the version in use is ignored (RFC 9000 section 6.2).
        deliver(negotiation([0x1a2a_3a4a, QUICVersion.v1]), to: client, nowMs: 1)
        #expect(client.status == .handshaking)
        deliver(negotiation([0x1a2a_3a4a, 0xff00_001d]), to: client, nowMs: 1)
        #expect(client.status == .drained)
        #expect(client.closeError == QUICError.versionNegotiationError.rawValue)
        #expect(client.peerVersions == [0x1a2a_3a4a, 0xff00_001d])
        #expect(client.takeEvents().contains { $0.kind == .closed })
    }

    /// RFC 9001 appendix A.4 and RFC 9369 appendix A.5: the sample Retry
    /// packets, whose tags must check.
    @Test func retryIntegrityVectors() throws {
        let odcid = try #require([UInt8]([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]).withUnsafeBufferPointer {
            QUICConnectionID($0.baseAddress!, $0.count)
        })
        let v1 = hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba")
        let v2 = hex("cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6")
        #expect(v1.withUnsafeBytes { QUICRetry.isValid($0, originalDCID: odcid, version: QUICVersion.v1) })
        #expect(v2.withUnsafeBytes { QUICRetry.isValid($0, originalDCID: odcid, version: QUICVersion.v2) })
        #expect(!v1.withUnsafeBytes { QUICRetry.isValid($0, originalDCID: odcid, version: QUICVersion.v2) })
        let scid = try #require(hex("f067a5502a4262b5").withUnsafeBufferPointer { QUICConnectionID($0.baseAddress!, $0.count) })
        let built = QUICRetry.packet(version: QUICVersion.v1, clientSCID: QUICConnectionID(), retrySCID: scid,
                                     originalDCID: odcid, token: Array("token".utf8))
        #expect(built == v1)
    }
}

private func hex(_ s: String) -> [UInt8] {
    var out: [UInt8] = []
    var it = s.makeIterator()
    while let a = it.next(), let b = it.next() { out.append(UInt8(String([a, b]), radix: 16)!) }
    return out
}

private final class Seen: @unchecked Sendable {
    var value: (Int, String) = (0, "")
    func record(_ count: Int, _ name: String) { value = (count, name) }
}

@Suite("CertificateVerifier")
struct CertificateVerifierTests {
    private func chain(_ names: [String]) throws -> (pem: String, der: [[UInt8]]) {
        let (pem, key) = try makeIdentity(names)
        return (pem, key.certificateChain)
    }

    @Test func aSelfSignedRootTrustedAsPEMVerifies() throws {
        let (pem, der) = try chain(["localhost", "*.example.com"])
        let verifier = try CertificateVerifier(trustRoots: .certificates(pem))
        try verifier.verify(chain: der, hostname: "localhost")
        try verifier.verify(chain: der, hostname: "www.example.com")
        try verifier.verify(chain: der, hostname: "")
        #expect(verifier.isTrusted(chain: der, hostname: "LOCALHOST"))
    }

    @Test func theWrongNameIsRefused() throws {
        let (pem, der) = try chain(["localhost", "*.example.com"])
        let verifier = try CertificateVerifier(trustRoots: .certificates(pem))
        #expect(!verifier.isTrusted(chain: der, hostname: "example.org"))
        // A wildcard covers one label, no more and no fewer.
        #expect(!verifier.isTrusted(chain: der, hostname: "example.com"))
        #expect(!verifier.isTrusted(chain: der, hostname: "a.b.example.com"))
        #expect(throws: CryptoError.self) { try verifier.verify(chain: der, hostname: "example.org") }
    }

    @Test func anIPAddressIsCheckedAgainstIPNames() throws {
        let (pem, der) = try chain(["127.0.0.1", "localhost"])
        let verifier = try CertificateVerifier(trustRoots: .certificates(pem))
        #expect(verifier.isTrusted(chain: der, hostname: "127.0.0.1"))
        #expect(!verifier.isTrusted(chain: der, hostname: "127.0.0.2"))
    }

    @Test func anUntrustedRootIsRefused() throws {
        let (_, der) = try chain(["localhost"])
        let (otherPEM, _) = try chain(["localhost"])
        let verifier = try CertificateVerifier(trustRoots: .certificates(otherPEM))
        do throws(CryptoError) {
            try verifier.verify(chain: der, hostname: "localhost")
            Issue.record("an untrusted chain verified")
        } catch {
            guard case .failed(let reason) = error else { Issue.record("\(error)"); return }
            #expect(reason.contains("certificate verify failed"))
        }
        // Nor do the system's roots vouch for a self-signed certificate.
        let system = try CertificateVerifier.system
        #expect(!system.isTrusted(chain: der, hostname: "localhost"))
    }

    @Test func garbageIsRefused() throws {
        let (pem, _) = try chain(["localhost"])
        let verifier = try CertificateVerifier(trustRoots: .certificates(pem))
        #expect(!verifier.isTrusted(chain: [], hostname: "localhost"))
        #expect(!verifier.isTrusted(chain: [[1, 2, 3]], hostname: "localhost"))
        #expect(throws: CryptoError.self) { _ = try CertificateVerifier(trustRoots: .certificates("not PEM")) }
    }
}
#endif
