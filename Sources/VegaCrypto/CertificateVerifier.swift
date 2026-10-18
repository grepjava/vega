// On the OpenSSL or BoringSSL trait; not on iOS, tvOS, watchOS or visionOS.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import CVegaTLS

/// Checks a TLS server's certificate chain for a handshake that is ours
/// rather than the TLS library's (QUIC's TLS 1.3): that it leads to a
/// trusted root, is valid now, is for a TLS server, and names the host the
/// client asked for.
///
/// Building one reads its roots (the system's are thousands of
/// certificates), so make one and share it: verifications may run on it
/// from any thread at once. `CertificateVerifier.system` is a shared one over
/// the system's roots.
///
/// ```swift
/// let verifier = try CertificateVerifier(trustRoots: .certificates(caPEM))
/// try verifier.verify(chain: certificates, serverName: "example.com")
/// ```
public final class CertificateVerifier: Sendable {
    private final class Raw: @unchecked Sendable {
        let ptr: OpaquePointer
        init(_ ptr: OpaquePointer) { self.ptr = ptr }
        deinit { cv_verifier_free(ptr) }
    }

    private let raw: Raw
    public let trustRoots: TrustRoots

    public init(trustRoots: TrustRoots = .system) throws(CryptoError) {
        self.trustRoots = trustRoots
        let system = trustRoots.includesSystem
        var pem = trustRoots.pem
        var err = [CChar](repeating: 0, count: 256)
        let made = pem.withUTF8 { p in
            p.withMemoryRebound(to: CChar.self) { cv_verifier_new(system ? 1 : 0, $0.baseAddress, $0.count, &err, err.count) }
        }
        guard let made else {
            let message = String(decoding: err.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            throw .invalidArgument(message.isEmpty ? "trust roots" : message)
        }
        raw = Raw(made)
    }

    private static let shared: Result<CertificateVerifier, CryptoError> = Result { () throws(CryptoError) in
        try CertificateVerifier(trustRoots: .system)
    }

    /// One over the system's roots, made on first use and shared.
    public static var system: CertificateVerifier {
        get throws(CryptoError) { try shared.get() }
    }

    /// Throws `.failed` with the reason when `chain` (DER, leaf first, as a
    /// TLS Certificate message carries it) is not to be trusted for
    /// `serverName` -- a DNS name, matched against the leaf's subject
    /// alternative names with wildcards as RFC 6125 has them, or an IP
    /// address, matched against its IP ones. An empty `serverName` fails: a
    /// chain checked against no name would be anyone's (`verifyChain` is
    /// the check without one, for a client's certificate).
    public func verify(chain: [[UInt8]], serverName: String) throws(CryptoError) {
        guard !serverName.isEmpty else { throw .failed("certificate verify failed: no server name to check it against") }
        try check(chain, serverName)
    }

    /// The chain alone, with no name: for a server checking a client's
    /// certificate. A client checking a server wants `verify`.
    public func verifyChain(_ chain: [[UInt8]]) throws(CryptoError) {
        try check(chain, "")
    }

    private func check(_ chain: [[UInt8]], _ hostname: String) throws(CryptoError) {
        guard !chain.isEmpty, chain.count <= Int(Int32.max) else { throw .failed("certificate verify failed: no certificate") }
        var err = [CChar](repeating: 0, count: 256)
        var host = hostname
        // Pointers to each certificate, all live for the call: the arrays
        // are pinned one inside the next.
        let ok: Int32 = host.withUTF8 { h in
            h.withMemoryRebound(to: CChar.self) { h in
                withPinned(chain, at: 0, []) { pointers in
                    let lens = chain.map { $0.count }
                    return pointers.withUnsafeBufferPointer { p in
                        lens.withUnsafeBufferPointer { l in
                            cv_verifier_verify(raw.ptr, p.baseAddress, l.baseAddress, Int32(chain.count),
                                               h.baseAddress, h.count, &err, err.count)
                        }
                    }
                }
            }
        }
        if ok != 1 {
            let message = String(decoding: err.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            throw .failed(message.isEmpty ? "certificate verify failed" : message)
        }
    }

    /// `verify`, as a yes or no.
    public func isTrusted(chain: [[UInt8]], serverName: String) -> Bool {
        do throws(CryptoError) {
            try verify(chain: chain, serverName: serverName)
            return true
        } catch {
            return false
        }
    }

    private func withPinned<R>(_ chain: [[UInt8]], at index: Int, _ pointers: [UnsafePointer<UInt8>?],
                               _ body: ([UnsafePointer<UInt8>?]) -> R) -> R {
        if index == chain.count { return body(pointers) }
        return chain[index].withUnsafeBufferPointer { p in
            withPinned(chain, at: index + 1, pointers + [p.baseAddress], body)
        }
    }
}
#endif
