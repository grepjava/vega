// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
//===----------------------------------------------------------------------===//
// A client's configuration.
//
// The connection is the same object at both ends (QUICConnectionState), told which
// end it is; what differs at a client is who it trusts and what it asks for,
// which is all this file holds.
//===----------------------------------------------------------------------===//

import VegaCrypto

/// How a client decides whether to believe the server's certificate chain.
public enum QUICCertificateVerification: Sendable {
    /// The system's trust roots (`CertificateVerifier.system`), and the
    /// leaf must name `serverName`. The default.
    case system
    /// A verifier of the caller's -- its own roots, such as a private CA --
    /// with the same name check.
    case verifier(CertificateVerifier)
    /// The caller's own check, given the chain (DER, leaf first) and the
    /// server name: true to accept.
    case custom(@Sendable (_ chain: [[UInt8]], _ serverName: String) -> Bool)
    /// None: any certificate is accepted, its signature over the handshake
    /// still checked. For tests and development only -- a connection made
    /// this way can be intercepted by anyone in the path.
    case insecureNoVerification

    /// The check the handshake runs: nil when the chain is accepted, the
    /// reason when it is not. Resolved now, so the system's roots are read
    /// by whoever makes the connection rather than mid-handshake.
    func check() -> (([[UInt8]], String) -> String?)? {
        switch self {
        case .system:
            let verifier: CertificateVerifier
            do throws(CryptoError) {
                verifier = try CertificateVerifier.system
            } catch {
                let reason = "system trust roots: \(error)"
                return { _, _ in reason }
            }
            return Self.check(verifier)
        case .verifier(let verifier):
            return Self.check(verifier)
        case .custom(let accept):
            return { chain, name in accept(chain, name) ? nil : "refused by the application's check" }
        case .insecureNoVerification:
            return nil
        }
    }

    private static func check(_ verifier: CertificateVerifier) -> ([[UInt8]], String) -> String? {
        { chain, name in
            do throws(CryptoError) {
                try verifier.verify(chain: chain, hostname: name)
                return nil
            } catch {
                if case .failed(let reason) = error { return reason }
                return "\(error)"
            }
        }
    }
}

public struct QUICClientConfiguration: Sendable {
    /// The server's name: sent as SNI (unless it is an IP address) and
    /// checked against its certificate.
    public var serverName: String
    /// Application protocols (ALPN) to offer, in order of preference. The
    /// server must choose one of them (RFC 9001 section 8.1).
    public var applicationProtocols: [String]
    public var certificateVerification: QUICCertificateVerification
    public var maxIdleTimeout: Duration = .seconds(30)
    public var initialMaxData: UInt64 = 1 << 20
    public var initialMaxStreamData: UInt64 = 256 * 1024
    /// How many streams the server may open towards the client.
    public var initialMaxStreamsBidi: UInt64 = 128
    public var initialMaxStreamsUni: UInt64 = 128
    /// RFC 9221 datagrams. Zero disables them.
    public var maxDatagramFrameSize: UInt64 = 1200

    public init(serverName: String, applicationProtocols: [String],
                certificateVerification: QUICCertificateVerification = .system) {
        self.serverName = serverName
        self.applicationProtocols = applicationProtocols
        self.certificateVerification = certificateVerification
    }

    package var alpn: [[UInt8]] { applicationProtocols.map { Array($0.utf8) } }
    package var maxIdleTimeoutMs: UInt64 { milliseconds(maxIdleTimeout) }
}
#endif

/// A duration in whole milliseconds, 0 for a negative one.
package func milliseconds(_ d: Duration) -> UInt64 {
    let c = d.components
    guard c.seconds >= 0, c.attoseconds >= 0 else { return 0 }
    return UInt64(c.seconds) * 1000 + UInt64(c.attoseconds / 1_000_000_000_000_000)
}
