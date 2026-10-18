// On the OpenSSL or BoringSSL trait; not on iOS, tvOS, watchOS or visionOS.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)

/// Which certificate authorities to trust: a `TLSConfiguration`'s, a
/// `CertificateVerifier`'s.
public struct TrustRoots: Sendable, Hashable {
    /// Whether the system's are trusted: OpenSSL's default store
    /// (`SSL_CERT_FILE` and `SSL_CERT_DIR` override it), plus Windows'
    /// certificate store.
    public let includesSystem: Bool
    /// Certificates trusted besides, as PEM; empty for none. A self-signed
    /// certificate here is trusted as itself.
    public let pem: String

    /// The system's.
    public static let system = TrustRoots(includesSystem: true, pem: "")

    /// Only these, as PEM.
    public static func certificates(_ pem: String) -> TrustRoots {
        TrustRoots(includesSystem: false, pem: pem)
    }

    /// The system's and these.
    public static func systemAnd(_ pem: String) -> TrustRoots {
        TrustRoots(includesSystem: true, pem: pem)
    }
}
#endif
