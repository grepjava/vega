#if canImport(Network)
import Foundation
import Network
import Security
import Testing
@testable import Vega

// A self-signed P-256 certificate for "localhost" and 127.0.0.1 and its
// key, as PKCS #12 (passphrase "vega"), from ci/network-tls-identity.sh.
// Apple refuses a TLS certificate valid for more than 825 days, even as an
// anchor, so this one runs out: renew it with that script before
// `identityExpires`, which `theIdentityIsNotAboutToExpire` watches.
private let identityExpires = "Jan 15 06:22:11 2029 GMT"

private let identityP12 = """
MIIDygIBAzCCA5AGCSqGSIb3DQEHAaCCA4EEggN9MIIDeTCCAm8GCSqGSIb3DQEHBqCCAmAwggJc
AgEAMIICVQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQI2+OLI85YhRICAggAgIICKNqg4sAZ
gWTLZgjqQdBL+HO840dPeAXBCAtO18eOXe1OvsEKeYs1IKmUiMog7f9inY4Y6axh2VHe0wStQ/Wa
LFRSN26rgQlfrLTOsUQbKol/Q/DjnYmZnbI/+Diutvo7ULZv6YE0sRXOjENFd3YvPR5wHqnfByVR
0UWB0RK88kvaBPXQM9iIA3vC3EU1OmVXWRm+8o2nVxCK8j9mWewEMzohJivlrbCZ6deSh+NnB+P6
GMvtLhazdNculEl3p5RTLd6IsGxgV9uRMcg5pj9e6o6+6tEaRrLQla5eEWiKvtL2yPM+hJ9YL8D1
/4F6LqV2J6NPEEyqXQh+3fiVAycLDpxPN4nSpPSPqIWEeMivDoRzbzUVcm21CnW1plcoHZng011b
WzzFflF/liUy9otxkb9+jvnavm+Vvl5dZXKcKqKiGm9iARW3A3nZNDwjV/unN1PUHiB4lPRawc8W
XyAexcXPZ+7WoycV2LuT5/x/70mEdCyg9SYYDckba55pZySfH2FWkoZHRWuRVtn4/SIBVKYvvyVq
x6cFRW3Dk/ZpU/ExA1Ulk885qtJIpdhuRIwnaHOystkn8N/CXWnpOF8jSR36Hp/Y6WH5ghHTXH4w
GzzS0wFcVlvZZP7LEC6M8o/faDn0mLU4HyBYDIEor4AGUVlIM2jIUZngIWitsN+X0SbZEAB7iiYN
aFx7KLU5qOHwjOOqdaCfTRR2BP5hlZby+dlg5Nl7arSyQzCCAQIGCSqGSIb3DQEHAaCB9ASB8TCB
7jCB6wYLKoZIhvcNAQwKAQKggbQwgbEwHAYKKoZIhvcNAQwBAzAOBAi4pYp5msSJtAICCAAEgZDE
I0HhkmYK2GfzXJb0h8qeulJSrG8vdrujUktxXjNMDE2jBFB8a43CauzjIPzKweMFC/PA6Gg16yCa
BdDCuBf1ndTJEDl1GPZblGBZ7lSVFoSiBFfOnvfBd9/eT5+JAqJ83Rcl5fiv1qY7IlZlZeJ1zeWO
sWEHKsgMVjM89jkuL+H+YJEKEHt3TuJTE1N85m8xJTAjBgkqhkiG9w0BCRUxFgQUa6V7q8WBhmaA
NWMx0+7dHvcj/+swMTAhMAkGBSsOAwIaBQAEFDLb33lmGAQttPrG3Cc+RanDlajOBAiTXHbV6p0F
5wICCAA=
"""

private let certificateDER = """
MIIByzCCAXCgAwIBAgIUX4VyTcQnkaha7t2KHHhfQYCs8u8wCgYIKoZIzj0EAwIwFDESMBAGA1UE
AwwJbG9jYWxob3N0MB4XDTI2MTAxODA2MjIxMVoXDTI5MDExNTA2MjIxMVowFDESMBAGA1UEAwwJ
bG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+gCXL3bdw92d7fvBQ4JQ4IW5MyrM
pBWZnR1GJA+KdUSJJMGZ0OiNOo78CGest24wI90P7InxCLlryfGsR5G1NaOBnzCBnDAdBgNVHQ4E
FgQUmMY4wDMkC/+F8KCOSyD1IHWmSWowHwYDVR0jBBgwFoAUmMY4wDMkC/+F8KCOSyD1IHWmSWow
GgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNJADBGAiEAh3TQ
9SoADrJkIPUZ4p9OpFmvBLKAmU20ngnLQgPP9qUCIQCYsvap/3KLSCIpBgbIPuANYbgIWJGBjaYZ
Tr4aWFDNUQ==
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
            // No half-close under Network.framework's TLS: the echo ends
            // when this stream goes, once it has the four bytes back.
            #expect(throws: IOError.unsupported) { try stream.shutdownWrite() }
            var back = IOBuffer(capacity: 16)
            try await Runtime.withIODeadline(.seconds(10)) { () async throws(IOError) in
                while back.count < 4, try await stream.read(into: &back) > 0 {}
            }
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

    /// A month's warning before the embedded identity runs out.
    @Test func theIdentityIsNotAboutToExpire() throws {
        let format = DateFormatter()
        format.locale = Locale(identifier: "en_US_POSIX")
        format.timeZone = TimeZone(identifier: "GMT")
        format.dateFormat = "MMM d HH:mm:ss yyyy 'GMT'"
        let expires = try #require(format.date(from: identityExpires.replacingOccurrences(of: "  ", with: " ")))
        #expect(expires.timeIntervalSinceNow > 30 * 24 * 3600,
                "NetworkTLSTests' identity expires \(identityExpires): renew it with ci/network-tls-identity.sh")
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
