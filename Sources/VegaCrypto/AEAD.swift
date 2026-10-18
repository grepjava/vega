// On the OpenSSL or BoringSSL trait; not on iOS, tvOS, watchOS or visionOS.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import CVegaTLS

/// The AEADs TLS 1.3 and QUIC use. Nonces are 12 bytes, tags 16.
public enum AEADAlgorithm: Sendable, Hashable, CaseIterable {
    case aes128GCM, aes256GCM, chacha20Poly1305

    @usableFromInline var code: Int32 {
        switch self {
        case .aes128GCM: CV_AEAD_AES128GCM
        case .aes256GCM: CV_AEAD_AES256GCM
        case .chacha20Poly1305: CV_AEAD_CHACHA20POLY1305
        }
    }

    public var keyByteCount: Int { self == .aes128GCM ? 16 : 32 }
    public static let nonceByteCount = 12
    public static let tagByteCount = 16
}

/// An AEAD key, bound once and used for many messages: a connection's
/// packet protection. The context is reused, so sealing a message costs no
/// key schedule and no allocation (with the pointer calls). The context
/// changes with every call, so it isn't `Sendable`: one task uses it, and
/// another makes its own.
///
/// ```swift
/// let aead = try AEAD(.aes128GCM, key: key)
/// let sealed = try aead.seal(nonce: nonce, aad: header, plaintext: payload)   // ciphertext || tag
/// let opened = try aead.open(nonce: nonce, aad: header, ciphertext: sealed)
/// ```
public struct AEAD: ~Copyable {
    public let algorithm: AEADAlgorithm
    @usableFromInline let ctx: OpaquePointer

    public init(_ algorithm: AEADAlgorithm, key: [UInt8]) throws(CryptoError) {
        guard key.count == algorithm.keyByteCount else { throw .invalidArgument("key length") }
        guard let ctx = key.withUnsafeBytes({ cv_aead_new(algorithm.code, $0.baseAddress, $0.count) }) else {
            throw .library("AEAD")
        }
        self.algorithm = algorithm
        self.ctx = ctx
    }

    deinit { cv_aead_free(ctx) }

    /// The ciphertext followed by the 16-byte tag.
    public func seal(nonce: [UInt8], aad: [UInt8] = [], plaintext: [UInt8]) throws(CryptoError) -> [UInt8] {
        guard nonce.count == AEADAlgorithm.nonceByteCount else { throw .invalidArgument("nonce length") }
        var out = [UInt8](repeating: 0, count: plaintext.count + AEADAlgorithm.tagByteCount)
        let n = nonce.withUnsafeBytes { iv in
            aad.withUnsafeBytes { a in
                plaintext.withUnsafeBytes { p in
                    out.withUnsafeMutableBytes { o in
                        seal(nonce: iv.baseAddress!, aad: a, plaintext: p, into: o.baseAddress!)
                    }
                }
            }
        }
        guard n >= 0 else { throw .library("AEAD seal") }
        return out
    }

    /// The plaintext of ciphertext || tag, if the tag verifies.
    public func open(nonce: [UInt8], aad: [UInt8] = [], ciphertext: [UInt8]) throws(CryptoError) -> [UInt8] {
        guard nonce.count == AEADAlgorithm.nonceByteCount else { throw .invalidArgument("nonce length") }
        guard ciphertext.count >= AEADAlgorithm.tagByteCount else { throw .authenticationFailure }
        // At least a byte, for an address to write nothing to.
        var out = [UInt8](repeating: 0, count: max(ciphertext.count - AEADAlgorithm.tagByteCount, 1))
        let n = nonce.withUnsafeBytes { iv in
            aad.withUnsafeBytes { a in
                ciphertext.withUnsafeBytes { c in
                    out.withUnsafeMutableBytes { o in open(nonce: iv.baseAddress!, aad: a, ciphertext: c, into: o.baseAddress!) }
                }
            }
        }
        guard n >= 0 else { throw .authenticationFailure }
        out.removeSubrange(n...)
        return out
    }

    /// Seals plaintext into out, which takes plaintext.count + 16 bytes and
    /// may be plaintext's own memory (in place). The bytes written, or -1.
    @inlinable
    public func seal(nonce: UnsafeRawPointer, aad: UnsafeRawBufferPointer, plaintext: UnsafeRawBufferPointer,
                     into out: UnsafeMutableRawPointer) -> Int {
        cv_aead_seal(ctx, nonce.assumingMemoryBound(to: UInt8.self), aad.baseAddress, aad.count,
                     plaintext.baseAddress, plaintext.count, out.assumingMemoryBound(to: UInt8.self))
    }

    /// Opens ciphertext (with its tag) into out, which takes
    /// ciphertext.count - 16 bytes and may be ciphertext's own memory. The
    /// plaintext's length, or -1 if the tag doesn't verify.
    @inlinable
    public func open(nonce: UnsafeRawPointer, aad: UnsafeRawBufferPointer, ciphertext: UnsafeRawBufferPointer,
                     into out: UnsafeMutableRawPointer) -> Int {
        cv_aead_open(ctx, nonce.assumingMemoryBound(to: UInt8.self), aad.baseAddress, aad.count,
                     ciphertext.baseAddress, ciphertext.count, out.assumingMemoryBound(to: UInt8.self))
    }
}

/// QUIC header protection (RFC 9001 5.4): the 5-byte mask for a packet's
/// first byte and packet number, from a 16-byte sample of its ciphertext.
/// AES-ECB for the GCM suites, ChaCha20 for ChaCha20-Poly1305. Not
/// `Sendable`, as `AEAD` isn't: one task at a time.
public struct HeaderProtection: ~Copyable {
    public let algorithm: AEADAlgorithm
    @usableFromInline let ctx: OpaquePointer

    public init(_ algorithm: AEADAlgorithm, key: [UInt8]) throws(CryptoError) {
        guard key.count == algorithm.keyByteCount else { throw .invalidArgument("key length") }
        guard let ctx = key.withUnsafeBytes({ cv_hp_new(algorithm.code, $0.baseAddress, $0.count) }) else {
            throw .library("header protection")
        }
        self.algorithm = algorithm
        self.ctx = ctx
    }

    deinit { cv_hp_free(ctx) }

    public func mask(sample: [UInt8]) throws(CryptoError) -> [UInt8] {
        guard sample.count == 16 else { throw .invalidArgument("sample length") }
        var out = [UInt8](repeating: 0, count: 5)
        let ok = sample.withUnsafeBytes { s in out.withUnsafeMutableBytes { mask(sample: s.baseAddress!, into: $0.baseAddress!) } }
        guard ok else { throw .library("header protection") }
        return out
    }

    /// Five bytes of mask into out, from the 16 bytes at sample.
    @inlinable
    public func mask(sample: UnsafeRawPointer, into out: UnsafeMutableRawPointer) -> Bool {
        cv_hp_mask(ctx, sample.assumingMemoryBound(to: UInt8.self), out.assumingMemoryBound(to: UInt8.self)) == 0
    }
}

/// The groups of a TLS 1.3 key share.
public enum KeyExchangeGroup: Sendable, Hashable, CaseIterable {
    case x25519, p256, p384

    var code: Int32 {
        switch self {
        case .x25519: CV_KEX_X25519
        case .p256: CV_KEX_P256
        case .p384: CV_KEX_P384
        }
    }

    /// The group's TLS NamedGroup code.
    public var tlsCode: UInt16 {
        switch self {
        case .x25519: 0x001D
        case .p256: 0x0017
        case .p384: 0x0018
        }
    }
}

/// An ephemeral key pair for one Diffie-Hellman exchange: send publicKey,
/// and derive the shared secret from the peer's.
///
/// ```swift
/// let ours = try KeyExchange(.x25519)
/// let secret = try ours.sharedSecret(with: theirPublicKey)
/// ```
public struct KeyExchange: ~Copyable, @unchecked Sendable {
    public let group: KeyExchangeGroup
    /// In TLS's form: 32 bytes for X25519, an uncompressed point (0x04, x,
    /// y) for the curves.
    public let publicKey: [UInt8]
    private let ctx: OpaquePointer

    /// A new key pair.
    public init(_ group: KeyExchangeGroup) throws(CryptoError) {
        guard let ctx = cv_kex_new(group.code, nil, 0) else { throw .library("key exchange") }
        self.init(group, ctx)
    }

    /// An X25519 key pair from its 32-byte private key (RFC 7748).
    public init(x25519PrivateKey key: [UInt8]) throws(CryptoError) {
        guard key.count == 32 else { throw .invalidArgument("X25519 private key length") }
        guard let ctx = key.withUnsafeBufferPointer({ cv_kex_new(CV_KEX_X25519, $0.baseAddress, 32) }) else {
            throw .library("key exchange")
        }
        self.init(.x25519, ctx)
    }

    private init(_ group: KeyExchangeGroup, _ ctx: OpaquePointer) {
        self.group = group
        self.ctx = ctx
        publicKey = [UInt8](unsafeUninitializedCapacity: 133) { buf, n in
            n = max(cv_kex_public(ctx, buf.baseAddress, buf.count), 0)
        }
    }

    deinit { cv_kex_free(ctx) }

    /// The shared secret with the peer's public key, in TLS's form.
    public func sharedSecret(with peer: [UInt8]) throws(CryptoError) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 66)
        let n = peer.withUnsafeBufferPointer { p in
            out.withUnsafeMutableBufferPointer { cv_kex_derive(ctx, p.baseAddress, p.count, $0.baseAddress, $0.count) }
        }
        guard n > 0 else {
            _ = CryptoError.library("")
            throw .invalidKey("the peer's public key")
        }
        out.removeSubrange(n...)
        return out
    }
}
#endif
