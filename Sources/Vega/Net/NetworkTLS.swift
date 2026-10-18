#if canImport(Network)
import Darwin
import Foundation
import Network
import Security

/// TLS that Network.framework runs, for TCP on a runtime whose backend is
/// `IOBackend.network` (the default on iOS, tvOS, watchOS and visionOS;
/// `.network` or `VEGA_DRIVER=network` on macOS), as NIOTransportServices'
/// `tlsOptions` does: no TLS library in the process, and the system's trust
/// store, certificate checks and session cache. A stream made with it reads
/// and writes plaintext.
///
/// ```swift
/// let stream = try await TCPStream.connect(host: "example.com", port: 443,
///                                          tls: .client(applicationProtocols: ["h2", "http/1.1"]))
/// let session = try await stream.networkTLS()  // session.applicationProtocol: "h2"
/// ```
///
/// A server takes an identity from the keychain or a PKCS #12 file:
///
/// ```swift
/// let listener = try TCPListener.bind(port: 8443, tls: .server(identity: identity))
/// let stream = try await listener.accept()
/// _ = try await stream.networkTLS()  // the handshake
/// ```
///
/// On other backends, and on platforms without Network.framework, use
/// VegaTLS's `TLSStream`.
public struct NetworkTLS: @unchecked Sendable {
    /// The options as Network.framework takes them, for what has no
    /// shorthand here (`sec_protocol_options_*`). Set up before a stream or
    /// listener is made with them, and not changed after.
    public let options: NWProtocolTLS.Options

    public init(options: NWProtocolTLS.Options) {
        self.options = options
    }

    /// Which certificates the other side's must lead to.
    public enum Trust: @unchecked Sendable {
        /// The system's trust store (and, for a client, the server's name).
        case system
        /// Only these: a private CA, or a self-signed certificate itself.
        case anchors([SecCertificate])
        /// Any certificate, unchecked. For tests only: anyone can pose as
        /// the server.
        case anyCertificate
    }

    /// A client's TLS. `serverName` is checked against the certificate and
    /// sent as SNI (by default, the host connected to: set it when that is
    /// an address). `identity` is a client certificate, for servers that
    /// ask for one.
    public static func client(serverName: String? = nil, applicationProtocols: [String] = [],
                              trust: Trust = .system, identity: SecIdentity? = nil,
                              minimumVersion: tls_protocol_version_t = .TLSv12) -> NetworkTLS {
        let tls = NWProtocolTLS.Options()
        let o = tls.securityProtocolOptions
        if let serverName { sec_protocol_options_set_tls_server_name(o, serverName) }
        common(o, applicationProtocols, minimumVersion)
        verify(o, trust)
        if let identity, let id = sec_identity_create(identity) {
            sec_protocol_options_set_local_identity(o, id)
        }
        return NetworkTLS(options: tls)
    }

    /// A server's TLS with `identity`, its certificate and key. With
    /// `clientTrust`, a client must present a certificate that leads to it
    /// (mutual TLS).
    public static func server(identity: SecIdentity, applicationProtocols: [String] = [],
                              clientTrust: Trust? = nil,
                              minimumVersion: tls_protocol_version_t = .TLSv12) -> NetworkTLS {
        let tls = NWProtocolTLS.Options()
        let o = tls.securityProtocolOptions
        if let id = sec_identity_create(identity) { sec_protocol_options_set_local_identity(o, id) }
        common(o, applicationProtocols, minimumVersion)
        if let clientTrust {
            sec_protocol_options_set_peer_authentication_required(o, true)
            verify(o, clientTrust)
        }
        return NetworkTLS(options: tls)
    }

    private static func common(_ o: sec_protocol_options_t, _ alpn: [String], _ minimum: tls_protocol_version_t) {
        for p in alpn { sec_protocol_options_add_tls_application_protocol(o, p) }
        sec_protocol_options_set_min_tls_protocol_version(o, minimum)
    }

    private static func verify(_ o: sec_protocol_options_t, _ trust: Trust) {
        switch trust {
        case .system:
            break
        case .anyCertificate:
            sec_protocol_options_set_verify_block(o, { _, _, complete in complete(true) }, NetworkIO.target)
        case .anchors(let anchors):
            let anchors = anchors as CFArray
            sec_protocol_options_set_verify_block(o, { _, trust, complete in
                // The trust Network.framework made, with its policy (the
                // server's name, for a client), tried against these only.
                let t = sec_trust_copy_ref(trust).takeRetainedValue()
                SecTrustSetAnchorCertificates(t, anchors)
                SecTrustSetAnchorCertificatesOnly(t, true)
                complete(SecTrustEvaluateWithError(t, nil))
            }, NetworkIO.target)
        }
    }

    /// What a handshake settled on.
    public struct Session: Sendable {
        /// The protocol ALPN chose, if any.
        public let applicationProtocol: String?
        /// The TLS version.
        public let version: tls_protocol_version_t
    }
}

extension TCPStream {
    /// Connect to `host` and `port` with TLS that Network.framework runs:
    /// returns once the handshake is done. Throws `.unsupported` unless the
    /// runtime's backend is `.network`.
    public static func connect(host: String, port: Int, tls: NetworkTLS) async throws(IOError) -> TCPStream {
        guard NetworkIO.active else { throw .unsupported }
        return TCPStream(reg: try await NetworkIO.connect(host: host, port: port, tls: tls.options))
    }

    /// The TLS session of a stream made with `NetworkTLS`, once its
    /// handshake is done: an accepted stream's goes on after `accept`
    /// returns, and this waits for it (and throws how it failed). Throws
    /// `.unsupported` for a stream without it.
    public func networkTLS() async throws(IOError) -> NetworkTLS.Session {
        guard let nw = reg.nw, let stream = NetworkIO.handle(nw) as? NetworkStream else { throw .unsupported }
        try await stream.ready()
        guard let metadata = stream.tlsMetadata else { throw .unsupported }
        return NetworkTLS.Session(
            applicationProtocol: sec_protocol_metadata_get_negotiated_protocol(metadata).map { String(cString: $0) },
            version: sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata))
    }
}

extension TCPListener {
    /// Listen with TLS that Network.framework runs on every connection
    /// accepted: `accept` returns before the handshake, and the stream's
    /// `networkTLS()` waits for it. Throws `.unsupported` unless the
    /// runtime's backend is `.network`.
    public static func bind(host: String = "", port: Int, backlog: Int = 1024, reusePort: Bool = false,
                            tls: NetworkTLS) throws(IOError) -> TCPListener {
        guard NetworkIO.active else { throw .unsupported }
        return TCPListener(reg: try NetworkIO.listen(host: host, port: port, backlog: backlog, reusePort: reusePort,
                                                     tls: tls.options))
    }
}
#endif
