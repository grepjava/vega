// On the OpenSSL or BoringSSL trait; not on iOS, tvOS, watchOS or visionOS.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import CVegaTLS

/// A certificate chain and the leaf's private key, for a handshake that is
/// ours rather than the TLS library's (QUIC's TLS 1.3): the chain's DER for
/// the Certificate message, the schemes and signature for CertificateVerify,
/// and which server names it is for.
///
/// ```swift
/// let identity = try CertificateKey(chainPEM: chain, keyPEM: key)
/// let scheme = identity.signatureSchemes.first { offered.contains($0) }!
/// let signature = try identity.signature(for: content, scheme: scheme)
/// ```
public final class CertificateKey: Sendable {
    /// The chain as DER, leaf first.
    public let certificateChain: [[UInt8]]
    /// The leaf's private key.
    public let key: SigningKey
    private let raw: Raw

    private final class Raw: @unchecked Sendable {
        let ptr: OpaquePointer
        init(_ ptr: OpaquePointer) { self.ptr = ptr }
        deinit { cv_certkey_free(ptr) }
    }

    /// From PEM text: the chain (leaf first) and the leaf's private key.
    public convenience init(chainPEM: String, keyPEM: String) throws(CryptoError) {
        var chain = chainPEM, key = keyPEM
        let loaded = chain.withUTF8 { c in
            key.withUTF8 { k in
                c.withMemoryRebound(to: CChar.self) { c in
                    k.withMemoryRebound(to: CChar.self) { k in
                        CertificateKey.load(c.baseAddress, c.count, k.baseAddress, k.count, files: false)
                    }
                }
            }
        }
        try self.init(loaded)
    }

    /// From PEM files (synchronously: do it at start-up).
    public convenience init(chainFile: String, keyFile: String) throws(CryptoError) {
        try self.init(CertificateKey.load(chainFile, 0, keyFile, 0, files: true))
    }

    private static func load(_ chain: UnsafePointer<CChar>?, _ chainLen: Int, _ key: UnsafePointer<CChar>?,
                             _ keyLen: Int, files: Bool) -> Result<OpaquePointer, CryptoError> {
        var err = [CChar](repeating: 0, count: 256)
        guard let ck = cv_certkey_load(chain, chainLen, key, keyLen, files ? 1 : 0, &err, err.count) else {
            let message = String(decoding: err.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            return .failure(.invalidKey(message.isEmpty ? "certificate and key" : message))
        }
        return .success(ck)
    }

    private init(_ loaded: Result<OpaquePointer, CryptoError>) throws(CryptoError) {
        let ck: OpaquePointer
        switch loaded {
        case let .success(p): ck = p
        case let .failure(e): throw e
        }
        let raw = Raw(ck)
        var chain: [[UInt8]] = []
        for i in 0..<cv_certkey_chain_count(ck) {
            let len = cv_certkey_cert_der(ck, i, nil, 0)
            guard len > 0 else { throw .library("certificate") }
            chain.append([UInt8](unsafeUninitializedCapacity: len) { buf, n in
                n = max(cv_certkey_cert_der(ck, i, buf.baseAddress, len), 0)
            })
        }
        self.raw = raw
        certificateChain = chain
        key = SigningKey(handle: try KeyHandle(cv_certkey_key(ck), "the certificate's key"))
    }

    /// The leaf's public key.
    public var publicKey: PublicKey { key.publicKey }

    /// The TLS 1.3 schemes the key signs with, best first.
    public var signatureSchemes: [TLSSignatureScheme] { key.signatureSchemes }

    /// A CertificateVerify's signature over content (ECDSA in DER).
    public func signature(for content: [UInt8], scheme: TLSSignatureScheme) throws(CryptoError) -> [UInt8] {
        try key.signature(for: content, scheme: scheme)
    }

    /// Whether the leaf is for host (a client's SNI): its DNS subject
    /// alternative names, or its common name when it has none, with
    /// "*.example.com" covering exactly one label.
    public func matches(host: String) -> Bool {
        var host = host
        return host.withUTF8 { h in
            h.withMemoryRebound(to: CChar.self) { cv_certkey_matches(raw.ptr, $0.baseAddress, $0.count) == 1 }
        }
    }

    /// RFC 6125 matching of one name pattern against a host,
    /// case-insensitive; a wildcard covers exactly one label.
    public static func hostMatches(pattern: String, host: String) -> Bool {
        guard !pattern.utf8.contains(0), !host.utf8.contains(0) else { return false }
        return cv_host_matches(pattern, host) == 1
    }
}
#endif
