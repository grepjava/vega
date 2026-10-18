#if canImport(Network)
import Foundation
import Network
import Security
import Testing
@testable import Vega

// A self-signed P-256 certificate for "localhost" and 127.0.0.1, valid to
// 2036, and its key, as PKCS #12 (passphrase "vega", 3DES and SHA-1, which
// every Apple OS imports): made with OpenSSL, `req -x509 -newkey ec` then
// `pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1`.
private let identityP12 = """
MIIDsgIBAzCCA3AGCSqGSIb3DQEHAaCCA2EEggNdMIIDWTCCAk8GCSqGSIb3DQEHBqCCAkAwggI8
AgEAMIICNQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIPAcFIAeGX14CAggAgIICCLPMwjuY
cANFRng7ehWCuNlsJlFS8U91SlnkfCgWohV3PGp8+wdBLiX6uF0ptbTMBACtRzj/JbHjCH4uz5lu
T5GQdFQkqWrTeWSJ5xq3tqgL3sQ9ddCO2SOXpjpHjYyuDJ6FVfWTy1Ng7vPQ9SKXZ2HG/x6tHy7q
0806A49ntRToADAut783EmzWel68SHWM6HoTPk0gEUa7ULleuvPLEpiIRb4bzX0g3DCDw0zj5SKe
6uIR824bvoCeF1V/M1PaDjiYsJIh9/UWlQOLoDHAfuOE2z6Ckk6sn/hP5noi6gEFQH7ORZBpYHQl
N7mK+Y/MYVuCkH/3dhI7Z09l6/J7u8FMRR3JpeMOTPcDtQsPSlPmLRIKvNDd1VZm5WSIbY07u25F
VxOPZpazCxsynKha7diJ07T6HjlRumHP2uDxHd49fCMV47wdOiNriJ/iEWIo6L6bIS8RC02HqD4D
/uOTriRXkhRgOVLbxZSEZK9ZETXMpJEgBpWNkahxweeLCeB2OP8x2IACer7kstoWeCbHEU0oghwU
KRjen9iyuV/888VNk1duwEQnkIfK3lF1shSCZhEEIkbkIb5Vtf1pofs1/iJSACQsikl15fa12rIU
dbg1crpNxECKCUa3jQeUvkKUmHHDiArjl47W3BrrJhzlxW4KA0EOSP6OOqzruh3Cycm0D17OpJXB
gjEwggECBgkqhkiG9w0BBwGggfQEgfEwge4wgesGCyqGSIb3DQEMCgECoIG0MIGxMBwGCiqGSIb3
DQEMAQMwDgQI5GcGRi/3OiICAggABIGQ2LaUg91giSG6uqlrGTTimtO7QCWjYEVlQ/8inkm+8Wd7
GmJOq52MYkW318spTLfEp/r1zGTGvKYiMKzkfzxo+LAvxF94i0QCWaVg4QVIc4uQCHxxTo7L9SU/
EFlcBj0UmXr14dn2cHARgwtRPbXGhflMvEm03DZs79xNHb9EzYYoVKqNblPi3+hmfZFa37KrMSUw
IwYJKoZIhvcNAQkVMRYEFHpaJ8mc38cH6h+mZJZbsJALf8stMDkwITAJBgUrDgMCGgUABBQ1a41K
uHCqcQi4uOs7EtUeftT+eQQQvTj6iA2bhJa9aaahiciALgICCAA=
"""

private let certificateDER = """
MIIBpzCCAU2gAwIBAgIUabp/zRkrb7/a6xhxb4uaEze/4kcwCgYIKoZIzj0EAwIwFDESMBAGA1UE
AwwJbG9jYWxob3N0MB4XDTI2MTAxODA2MDIxM1oXDTM2MTAxNTA2MDIxM1owFDESMBAGA1UEAwwJ
bG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjH1qvJyWi1kuPI4CvRmtHRDLc+bO
JGGl3iPBUbVtH85TVJ88UIYl/f7++K1W5cwYsv/6J1uNGyg/Z6tOzz6QNaN9MHswHQYDVR0OBBYE
FGewDj7EI0+OeAiec7wv1bQ6n/7nMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAdBgNVHSUE
FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAoQw
CgYIKoZIzj0EAwIDSAAwRQIgUdKfN8I5bjgOBOgJRJK5/0SChhpChac9IzkRV4J9encCIQDjOxTw
fGNE5BWLjYBgQ4cYWpZyex8qlrq/LWGH49i3cA==
"""

private func decode(_ base64: String) -> Data {
    Data(base64Encoded: base64.filter { !$0.isWhitespace })!
}

private func testIdentity() -> SecIdentity {
    var options: [String: Any] = [kSecImportExportPassphrase as String: "vega"]
    if #available(macOS 15, iOS 18, tvOS 18, watchOS 11, visionOS 2, *) {
        options[kSecImportToMemoryOnly as String] = true
    }
    var items: CFArray?
    let status = SecPKCS12Import(decode(identityP12) as CFData, options as CFDictionary, &items)
    precondition(status == errSecSuccess, "SecPKCS12Import: \(status)")
    let first = (items as! [[String: Any]])[0]
    return first[kSecImportItemIdentity as String] as! SecIdentity
}

nonisolated(unsafe) private let identity = testIdentity()
nonisolated(unsafe) private let certificate = SecCertificateCreateWithData(nil, decode(certificateDER) as CFData)!

/// TLS that Network.framework runs (`NetworkTLS`), both ends on
/// IOBackend.network, over loopback.
@Suite struct NetworkTLSTests {
    private func runtime() -> Runtime { Runtime(workers: 2, io: .network) }

    private static let pinned = NetworkTLS.Trust.anchors([certificate])

    /// What each end saw: the session, or how it failed.
    struct Ends: Sendable {
        var client: Result<NetworkTLS.Session, IOError>
        var server: Result<NetworkTLS.Session, IOError>
        var echoed = ""
    }

    /// One connection from `client` to a listener with `server`; the server
    /// echoes what it reads once its handshake is done.
    private func exchange(_ rt: Runtime, server: NetworkTLS, client: NetworkTLS) throws -> Ends {
        try rt.block { () async throws(IOError) -> Ends in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0, tls: server)
            let port = listener.localPort
            let served = rt.spawn(with: listener) { listener in await Self.serve(listener) }
            var ends = Ends(client: .failure(.cancelled), server: .failure(.cancelled))
            let (session, echoed) = await Self.call(port: port, tls: client)
            ends.client = session
            ends.echoed = echoed
            ends.server = await served.value
            return ends
        }
    }

    /// Accept one connection, finish its handshake and echo it.
    private static func serve(_ listener: borrowing TCPListener) async -> Result<NetworkTLS.Session, IOError> {
        do throws(IOError) {
            let conn = try await listener.accept()
            let session = try await conn.networkTLS()
            var buf = IOBuffer(capacity: 64)
            while try await conn.read(into: &buf) > 0 {
                try await conn.write(buf)
                buf.clear()
            }
            return .success(session)
        } catch {
            return .failure(error)
        }
    }

    /// Connect, send "ping", and read back what comes.
    private static func call(port: Int, tls: NetworkTLS) async -> (Result<NetworkTLS.Session, IOError>, String) {
        do throws(IOError) {
            let stream = try await TCPStream.connect(host: "127.0.0.1", port: port, tls: tls)
            let session = try await stream.networkTLS()
            var out = IOBuffer(capacity: 16)
            out.append("ping")
            try await stream.write(out)
            try stream.shutdownWrite()
            var back = IOBuffer(capacity: 16)
            while try await stream.read(into: &back) > 0 {}
            return (.success(session), back.string)
        } catch {
            return (.failure(error), "")
        }
    }

    @Test func echoesWithALPN() throws {
        let rt = runtime()
        defer { rt.shutdown() }
        let ends = try exchange(rt, server: .server(identity: identity, applicationProtocols: ["h2", "http/1.1"]),
                                client: .client(serverName: "localhost", applicationProtocols: ["h2"], trust: Self.pinned))
        let client = try ends.client.get(), server = try ends.server.get()
        #expect(ends.echoed == "ping")
        #expect(client.applicationProtocol == "h2")
        #expect(server.applicationProtocol == "h2")
        #expect(client.version == .TLSv13)
    }

    /// The system's trust store doesn't know a self-signed certificate.
    @Test func systemTrustRefusesSelfSigned() throws {
        let rt = runtime()
        defer { rt.shutdown() }
        let ends = try exchange(rt, server: .server(identity: identity), client: .client(serverName: "localhost"))
        #expect(throws: IOError.self) { try ends.client.get() }
    }

    /// Anchored, the certificate must still name the server.
    @Test func anchorsStillCheckTheName() throws {
        let rt = runtime()
        defer { rt.shutdown() }
        let ends = try exchange(rt, server: .server(identity: identity),
                                client: .client(serverName: "other.test", trust: Self.pinned))
        #expect(throws: IOError.self) { try ends.client.get() }
    }

    @Test func anyCertificateTakesAnything() throws {
        let rt = runtime()
        defer { rt.shutdown() }
        let ends = try exchange(rt, server: .server(identity: identity),
                                client: .client(serverName: "other.test", trust: .anyCertificate))
        _ = try ends.client.get()
        #expect(ends.echoed == "ping")
    }

    /// A server that asks for a client certificate: with one that leads to
    /// its anchors the handshake goes through, and without one it fails.
    @Test func mutualTLS() throws {
        let rt = runtime()
        defer { rt.shutdown() }
        let server = NetworkTLS.server(identity: identity, clientTrust: Self.pinned)
        let with = try exchange(rt, server: server,
                                client: .client(serverName: "localhost", trust: Self.pinned, identity: identity))
        _ = try with.server.get()
        #expect(with.echoed == "ping")
        let without = try exchange(rt, server: server, client: .client(serverName: "localhost", trust: Self.pinned))
        #expect(throws: IOError.self) { try without.server.get() }
    }

    /// Only on IOBackend.network; a plain stream has no NetworkTLS session.
    @Test func elsewhereUnsupported() throws {
        let rt = Runtime(workers: 1, io: .readiness)
        defer { rt.shutdown() }
        let refused = rt.block { () async -> Bool in
            do throws(IOError) {
                _ = try TCPListener.bind(host: "127.0.0.1", port: 0, tls: .server(identity: identity))
                return false
            } catch {
                return error == .unsupported
            }
        }
        #expect(refused)
        let net = runtime()
        defer { net.shutdown() }
        let plain = try net.block { () async throws(IOError) -> Bool in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let stream = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            do throws(IOError) {
                _ = try await stream.networkTLS()
                return false
            } catch {
                return error == .unsupported
            }
        }
        #expect(plain)
    }
}
#endif
