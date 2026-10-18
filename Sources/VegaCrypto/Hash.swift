// On the OpenSSL or BoringSSL trait; not on iOS, tvOS, watchOS or visionOS.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import CVegaTLS

/// Why a cryptographic operation failed.
///
/// A struct rather than an enum, so that kinds of failure can be added
/// without breaking anyone's exhaustive `switch`: switch over `code`, or
/// compare the error itself where its kind carries nothing more
/// (`catch CryptoError.authenticationFailure`, `error == .authenticationFailure`).
public struct CryptoError: Error, Hashable, Sendable, CustomStringConvertible {
    /// What kind of failure this is.
    public let code: Code
    public let message: String?

    /// The kinds of `CryptoError`.
    public struct Code: Hashable, Sendable, CustomStringConvertible {
        let rawValue: UInt8

        /// An argument of the wrong size or kind: a key or nonce's length, an
        /// algorithm the key isn't for.
        public static let invalidArgument = Code(rawValue: 0)
        /// A key that couldn't be read or made, or isn't one of the kinds
        /// supported (RSA of 2048 bits or more, P-256, P-384, P-521, Ed25519).
        public static let invalidKey = Code(rawValue: 1)
        /// An AEAD's tag didn't verify: the message was altered, or the key,
        /// nonce or associated data are not the sender's.
        public static let authenticationFailure = Code(rawValue: 2)
        /// The library failed; `message` is its reason.
        public static let failed = Code(rawValue: 3)

        public var description: String {
            let names = ["invalidArgument", "invalidKey", "authenticationFailure", "failed"]
            return Int(rawValue) < names.count ? names[Int(rawValue)] : "code \(rawValue)"
        }
    }

    init(_ code: Code, message: String? = nil) {
        self.code = code
        self.message = message
    }

    /// An argument of the wrong size or kind: a key or nonce's length, an
    /// algorithm the key isn't for.
    public static func invalidArgument(_ message: String) -> CryptoError { CryptoError(.invalidArgument, message: message) }
    /// A key that couldn't be read or made, or isn't one of the kinds
    /// supported (RSA of 2048 bits or more, P-256, P-384, P-521, Ed25519).
    public static func invalidKey(_ message: String) -> CryptoError { CryptoError(.invalidKey, message: message) }
    /// An AEAD's tag didn't verify: the message was altered, or the key,
    /// nonce or associated data are not the sender's.
    public static let authenticationFailure = CryptoError(.authenticationFailure)
    /// The library failed; `message` is its reason.
    public static func failed(_ message: String) -> CryptoError { CryptoError(.failed, message: message) }

    public var description: String {
        switch code {
        case .invalidArgument: "invalid argument: \(message ?? "")"
        case .invalidKey: "invalid key: \(message ?? "")"
        case .authenticationFailure: "authentication failure"
        case .failed: "\(message ?? "failed")"
        default: "\(code)"
        }
    }

    /// The library's reason for the last failure on this thread.
    static func library(_ what: String) -> CryptoError {
        var buf = [CChar](repeating: 0, count: 256)
        let n = cv_crypto_error(&buf, buf.count)
        guard n > 0 else { return .failed(what) }
        return .failed(what + ": " + String(decoding: buf.prefix(Int(n)).map { UInt8(bitPattern: $0) }, as: UTF8.self))
    }
}

/// The SHA-2 hashes.
public struct HashAlgorithm: Sendable, Hashable, CaseIterable {
    @usableFromInline let kind: Kind

    @usableFromInline init(_ kind: Kind) { self.kind = kind }

    public static let sha256 = HashAlgorithm(.sha256)
    public static let sha384 = HashAlgorithm(.sha384)
    public static let sha512 = HashAlgorithm(.sha512)

    public static var allCases: [HashAlgorithm] { Kind.allCases.map(HashAlgorithm.init) }

    @usableFromInline var code: Int32 {
        switch kind {
        case .sha256: CV_SHA256
        case .sha384: CV_SHA384
        case .sha512: CV_SHA512
        }
    }

    /// The digest's length in bytes.
    public var byteCount: Int {
        switch kind {
        case .sha256: 32
        case .sha384: 48
        case .sha512: 64
        }
    }

    @usableFromInline enum Kind: Hashable, Sendable, CaseIterable {
        case sha256
        case sha384
        case sha512
    }
}

/// A SHA-2 hash: one-shot, or incremental.
///
/// ```swift
/// let digest = Hash.sha256(Array("abc".utf8))
/// var transcript = try Hash(.sha256)
/// transcript.update(clientHello)
/// let soFar = transcript.snapshot()     // and keep going
/// ```
public struct Hash: ~Copyable, @unchecked Sendable {
    public let algorithm: HashAlgorithm
    private let ctx: OpaquePointer

    public init(_ algorithm: HashAlgorithm) throws(CryptoError) {
        guard let ctx = cv_hash_new(algorithm.code) else { throw .library("hash") }
        self.algorithm = algorithm
        self.ctx = ctx
    }

    private init(_ algorithm: HashAlgorithm, ctx: OpaquePointer) {
        self.algorithm = algorithm
        self.ctx = ctx
    }

    deinit { cv_hash_free(ctx) }

    public mutating func update(_ data: [UInt8]) {
        data.withUnsafeBytes { update($0) }
    }

    public mutating func update(_ data: UnsafeRawBufferPointer) {
        _ = cv_hash_update(ctx, data.baseAddress, data.count)
    }

    /// The digest of everything so far, leaving the hash running.
    public func snapshot() -> [UInt8] {
        [UInt8](unsafeUninitializedCapacity: algorithm.byteCount) { buf, n in
            n = max(Int(cv_hash_snapshot(ctx, buf.baseAddress)), 0)
        }
    }

    /// The digest, after which the hash starts over.
    public mutating func finalize() -> [UInt8] {
        [UInt8](unsafeUninitializedCapacity: algorithm.byteCount) { buf, n in
            n = max(Int(cv_hash_final(ctx, buf.baseAddress)), 0)
        }
    }

    /// A second hash that has seen what this one has.
    public func copy() throws(CryptoError) -> Hash {
        guard let c = cv_hash_copy(ctx) else { throw .library("hash") }
        return Hash(algorithm, ctx: c)
    }

    public static func digest(_ algorithm: HashAlgorithm, _ data: [UInt8]) -> [UInt8] {
        data.withUnsafeBytes { digest(algorithm, $0) }
    }

    public static func digest(_ algorithm: HashAlgorithm, _ data: UnsafeRawBufferPointer) -> [UInt8] {
        [UInt8](unsafeUninitializedCapacity: algorithm.byteCount) { buf, n in
            let r = cv_hash(algorithm.code, data.baseAddress, data.count, buf.baseAddress)
            precondition(r == algorithm.byteCount, "SHA-2 failed")
            n = Int(r)
        }
    }

    public static func sha256(_ data: [UInt8]) -> [UInt8] { digest(.sha256, data) }
    public static func sha384(_ data: [UInt8]) -> [UInt8] { digest(.sha384, data) }
    public static func sha512(_ data: [UInt8]) -> [UInt8] { digest(.sha512, data) }
}

/// HMAC (RFC 2104) with a SHA-2 hash. Keyed once, a value computes any
/// number of MACs, from any number of threads.
///
/// ```swift
/// let mac = try HMAC(.sha256, key: secret)
/// let tag = mac.authenticationCode(for: message)
/// guard mac.isValid(tag, for: message) else { ... }
/// ```
public final class HMAC: @unchecked Sendable {
    public let algorithm: HashAlgorithm
    private let ctx: OpaquePointer

    public init(_ algorithm: HashAlgorithm, key: [UInt8]) throws(CryptoError) {
        guard let ctx = key.withUnsafeBytes({ cv_hmac_new(algorithm.code, $0.baseAddress, $0.count) }) else {
            throw .library("HMAC")
        }
        self.algorithm = algorithm
        self.ctx = ctx
    }

    deinit { cv_hmac_free(ctx) }

    public func authenticationCode(for data: [UInt8]) -> [UInt8] {
        data.withUnsafeBytes { authenticationCode(for: $0) }
    }

    public func authenticationCode(for data: UnsafeRawBufferPointer) -> [UInt8] {
        [UInt8](unsafeUninitializedCapacity: algorithm.byteCount) { buf, n in
            let r = cv_hmac_compute(ctx, data.baseAddress, data.count, buf.baseAddress)
            precondition(r == algorithm.byteCount, "HMAC failed")
            n = Int(r)
        }
    }

    /// Whether mac is data's, compared in constant time.
    public func isValid(_ mac: [UInt8], for data: [UInt8]) -> Bool {
        ConstantTime.equals(authenticationCode(for: data), mac)
    }

    /// One MAC, without keeping the key.
    public static func authenticationCode(_ algorithm: HashAlgorithm, key: [UInt8], data: [UInt8]) -> [UInt8] {
        [UInt8](unsafeUninitializedCapacity: algorithm.byteCount) { buf, n in
            let r = key.withUnsafeBytes { k in
                data.withUnsafeBytes { d in
                    cv_hmac(algorithm.code, k.baseAddress, k.count, d.baseAddress, d.count, buf.baseAddress)
                }
            }
            precondition(r == algorithm.byteCount, "HMAC failed")
            n = Int(r)
        }
    }
}

/// PBKDF2 (RFC 8018) with HMAC-SHA-2: a key, or a password's hash, from a
/// password and salt.
public enum PBKDF2 {
    public static func deriveKey(_ algorithm: HashAlgorithm = .sha256, password: [UInt8], salt: [UInt8],
                                 iterations: Int, length: Int? = nil) throws(CryptoError) -> [UInt8] {
        let length = length ?? algorithm.byteCount
        guard iterations > 0, iterations <= Int(Int32.max) else { throw .invalidArgument("iterations") }
        guard length > 0, length <= Int(Int32.max) else { throw .invalidArgument("length") }
        var out = [UInt8](repeating: 0, count: length)
        let r = password.withUnsafeBytes { p in
            salt.withUnsafeBytes { s in
                out.withUnsafeMutableBufferPointer {
                    cv_pbkdf2(algorithm.code, p.baseAddress, p.count, s.baseAddress, s.count, UInt32(iterations),
                              $0.baseAddress, length)
                }
            }
        }
        guard r == 0 else { throw .library("PBKDF2") }
        return out
    }
}

/// HKDF (RFC 5869), and TLS 1.3's HKDF-Expand-Label (RFC 8446 7.1) that
/// QUIC's keys come from.
public enum HKDF {
    /// The pseudorandom key: algorithm.byteCount bytes. An empty salt is
    /// that many zeros.
    public static func extract(_ algorithm: HashAlgorithm, salt: [UInt8], inputKeyMaterial ikm: [UInt8]) -> [UInt8] {
        [UInt8](unsafeUninitializedCapacity: algorithm.byteCount) { buf, n in
            let r = salt.withUnsafeBytes { s in
                ikm.withUnsafeBytes { i in
                    cv_hkdf_extract(algorithm.code, s.baseAddress, s.count, i.baseAddress, i.count, buf.baseAddress)
                }
            }
            precondition(r == algorithm.byteCount, "HKDF failed")
            n = Int(r)
        }
    }

    /// length bytes (at most 255 times the hash's length) from prk and info.
    public static func expand(_ algorithm: HashAlgorithm, pseudoRandomKey prk: [UInt8], info: [UInt8],
                              length: Int) throws(CryptoError) -> [UInt8] {
        guard length >= 0, length <= 255 * algorithm.byteCount else { throw .invalidArgument("length") }
        var out = [UInt8](repeating: 0, count: length)
        let r = prk.withUnsafeBytes { p in
            info.withUnsafeBytes { i in
                out.withUnsafeMutableBufferPointer {
                    cv_hkdf_expand(algorithm.code, p.baseAddress, p.count, i.baseAddress, i.count, $0.baseAddress,
                                   length)
                }
            }
        }
        guard r == 0 else { throw .library("HKDF") }
        return out
    }

    /// Extract, then expand.
    public static func deriveKey(_ algorithm: HashAlgorithm, inputKeyMaterial ikm: [UInt8], salt: [UInt8] = [],
                                 info: [UInt8] = [], length: Int) throws(CryptoError) -> [UInt8] {
        try expand(algorithm, pseudoRandomKey: extract(algorithm, salt: salt, inputKeyMaterial: ikm), info: info,
                   length: length)
    }

    /// TLS 1.3's HKDF-Expand-Label: label without the "tls13 " it gets in
    /// front ("quic key", "c hs traffic").
    public static func expandLabel(_ algorithm: HashAlgorithm, secret: [UInt8], label: String,
                                   context: [UInt8] = [], length: Int) throws(CryptoError) -> [UInt8] {
        let full = Array("tls13 ".utf8) + Array(label.utf8)
        guard full.count <= 255, context.count <= 255, length >= 0, length <= 0xFFFF else {
            throw .invalidArgument("label")
        }
        var info = [UInt8]()
        info.reserveCapacity(4 + full.count + context.count)
        info.append(UInt8(truncatingIfNeeded: length >> 8))
        info.append(UInt8(truncatingIfNeeded: length))
        info.append(UInt8(full.count))
        info += full
        info.append(UInt8(context.count))
        info += context
        return try expand(algorithm, pseudoRandomKey: secret, info: info, length: length)
    }
}

/// Cryptographically secure random bytes, from the TLS library's generator.
public enum SecureRandom {
    public static func bytes(_ count: Int) -> [UInt8] {
        precondition(count >= 0)
        return [UInt8](unsafeUninitializedCapacity: count) { buf, n in
            fill(UnsafeMutableRawBufferPointer(buf))
            n = count
        }
    }

    public static func fill(_ buffer: UnsafeMutableRawBufferPointer) {
        guard buffer.count > 0 else { return }
        precondition(cv_crypto_random(buffer.baseAddress, buffer.count) == 0, "the random generator failed")
    }
}

/// Comparison that takes as long wherever the inputs differ: for MACs and
/// tokens, where an early exit would tell an attacker how much was right.
public enum ConstantTime {
    /// Whether a and b are equal. Their lengths aren't secret: different
    /// lengths are unequal at once.
    public static func equals(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        return a.withUnsafeBytes { x in
            b.withUnsafeBytes { y in cv_crypto_memeq(x.baseAddress, y.baseAddress, x.count) == 1 }
        }
    }
}
#endif
