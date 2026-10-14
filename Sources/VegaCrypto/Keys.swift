// On the OpenSSL or BoringSSL trait; not on iOS, tvOS, watchOS or visionOS.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import CVegaTLS

/// The kinds of signing key.
public enum KeyType: Sendable, Hashable, CaseIterable {
    case rsa, p256, p384, p521, ed25519

    var code: Int32 {
        switch self {
        case .rsa: CV_KEY_RSA
        case .p256: CV_KEY_EC_P256
        case .p384: CV_KEY_EC_P384
        case .p521: CV_KEY_EC_P521
        case .ed25519: CV_KEY_ED25519
        }
    }

    init?(code: Int32) {
        guard let t = KeyType.allCases.first(where: { $0.code == code }) else { return nil }
        self = t
    }

    /// The JWK "crv" of a curve: "P-256", "P-384", "P-521", "Ed25519".
    public var curveName: String? {
        switch self {
        case .rsa: nil
        case .p256: "P-256"
        case .p384: "P-384"
        case .p521: "P-521"
        case .ed25519: "Ed25519"
        }
    }

    /// The curve a JWK's "crv" names.
    public init?(curveName: String) {
        switch curveName {
        case "P-256": self = .p256
        case "P-384": self = .p384
        case "P-521": self = .p521
        case "Ed25519": self = .ed25519
        default: return nil
        }
    }
}

/// The signature algorithms of JWS (RFC 7518 3, RFC 8037), by their "alg"
/// names. HMAC is `HMAC`'s.
public enum SignatureAlgorithm: String, Sendable, Hashable, CaseIterable {
    case rs256 = "RS256", rs384 = "RS384", rs512 = "RS512"
    case ps256 = "PS256", ps384 = "PS384", ps512 = "PS512"
    case es256 = "ES256", es384 = "ES384", es512 = "ES512"
    case eddsa = "EdDSA"

    var code: Int32 {
        switch self {
        case .rs256: CV_JWS_RS256
        case .rs384: CV_JWS_RS384
        case .rs512: CV_JWS_RS512
        case .ps256: CV_JWS_PS256
        case .ps384: CV_JWS_PS384
        case .ps512: CV_JWS_PS512
        case .es256: CV_JWS_ES256
        case .es384: CV_JWS_ES384
        case .es512: CV_JWS_ES512
        case .eddsa: CV_JWS_EDDSA
        }
    }

    /// The kind of key that signs with it.
    public var keyType: KeyType {
        switch self {
        case .rs256, .rs384, .rs512, .ps256, .ps384, .ps512: .rsa
        case .es256: .p256
        case .es384: .p384
        case .es512: .p521
        case .eddsa: .ed25519
        }
    }
}

/// A TLS 1.3 SignatureScheme (RFC 8446 4.2.3), as on the wire: what a
/// CertificateVerify is signed with.
public struct TLSSignatureScheme: RawRepresentable, Sendable, Hashable, CustomStringConvertible {
    public var rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let ecdsaSecp256r1SHA256 = TLSSignatureScheme(rawValue: 0x0403)
    public static let ecdsaSecp384r1SHA384 = TLSSignatureScheme(rawValue: 0x0503)
    public static let ecdsaSecp521r1SHA512 = TLSSignatureScheme(rawValue: 0x0603)
    public static let rsaPSSRSAESHA256 = TLSSignatureScheme(rawValue: 0x0804)
    public static let rsaPSSRSAESHA384 = TLSSignatureScheme(rawValue: 0x0805)
    public static let rsaPSSRSAESHA512 = TLSSignatureScheme(rawValue: 0x0806)
    public static let ed25519 = TLSSignatureScheme(rawValue: 0x0807)

    public var description: String {
        switch self {
        case .ecdsaSecp256r1SHA256: "ecdsa_secp256r1_sha256"
        case .ecdsaSecp384r1SHA384: "ecdsa_secp384r1_sha384"
        case .ecdsaSecp521r1SHA512: "ecdsa_secp521r1_sha512"
        case .rsaPSSRSAESHA256: "rsa_pss_rsae_sha256"
        case .rsaPSSRSAESHA384: "rsa_pss_rsae_sha384"
        case .rsaPSSRSAESHA512: "rsa_pss_rsae_sha512"
        case .ed25519: "ed25519"
        default: "0x" + String(rawValue, radix: 16)
        }
    }
}

/// The library's key, shared by a SigningKey and its PublicKey.
final class KeyHandle: @unchecked Sendable {
    let raw: OpaquePointer
    let type: KeyType

    init(_ raw: OpaquePointer?, _ what: @autoclosure () -> String) throws(CryptoError) {
        guard let raw else {
            _ = CryptoError.library("")
            throw .invalidKey(what())
        }
        guard let type = KeyType(code: cv_key_type(raw)) else {
            cv_key_free(raw)
            throw .invalidKey(what())
        }
        self.raw = raw
        self.type = type
    }

    deinit { cv_key_free(raw) }

    func pem(privateKey: Bool) -> String {
        let p: Int32 = privateKey ? 1 : 0
        let len = cv_key_pem(raw, p, nil, 0)
        guard len > 0 else { return "" }
        let bytes = [UInt8](unsafeUninitializedCapacity: len) { buf, n in
            n = max(buf.withMemoryRebound(to: CChar.self) { cv_key_pem(raw, p, $0.baseAddress, len) }, 0)
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    func signJWS(_ data: [UInt8], _ algorithm: SignatureAlgorithm) throws(CryptoError) -> [UInt8] {
        guard algorithm.keyType == type else { throw .invalidArgument("\(algorithm.rawValue) with a \(type) key") }
        return try sign(data) { d, out in
            cv_key_sign_jws(raw, algorithm.code, d.baseAddress, d.count, out.baseAddress, out.count)
        }
    }

    func signTLS(_ data: [UInt8], _ scheme: TLSSignatureScheme) throws(CryptoError) -> [UInt8] {
        try sign(data) { d, out in
            cv_key_sign_tls(raw, scheme.rawValue, d.baseAddress, d.count, out.baseAddress, out.count)
        }
    }

    private func sign(_ data: [UInt8],
                      _ body: (UnsafeRawBufferPointer, UnsafeMutableBufferPointer<UInt8>) -> Int) throws(CryptoError) -> [UInt8] {
        let max = Int(cv_key_signature_max(raw))
        guard max > 0 else { throw .library("signature") }
        var out = [UInt8](repeating: 0, count: max)
        let n = data.withUnsafeBytes { d in out.withUnsafeMutableBufferPointer { body(d, $0) } }
        guard n > 0 else { throw .library("signature") }
        out.removeSubrange(n...)
        return out
    }

    func verifyJWS(_ signature: [UInt8], _ data: [UInt8], _ algorithm: SignatureAlgorithm) -> Bool {
        data.withUnsafeBytes { d in
            signature.withUnsafeBufferPointer { s in
                cv_key_verify_jws(raw, algorithm.code, d.baseAddress, d.count, s.baseAddress, s.count) == 1
            }
        }
    }

    func verifyTLS(_ signature: [UInt8], _ data: [UInt8], _ scheme: TLSSignatureScheme) -> Bool {
        data.withUnsafeBytes { d in
            signature.withUnsafeBufferPointer { s in
                cv_key_verify_tls(raw, scheme.rawValue, d.baseAddress, d.count, s.baseAddress, s.count) == 1
            }
        }
    }

    var tlsSchemes: [TLSSignatureScheme] {
        var codes = [UInt16](repeating: 0, count: 8)
        let n = Int(cv_key_tls_schemes(raw, &codes, Int32(codes.count)))
        return codes.prefix(n).map(TLSSignatureScheme.init(rawValue:))
    }
}

/// A public key: RSA, an EC curve's, or Ed25519's. Verifies JWS and TLS 1.3
/// signatures; immutable, so threads share one freely.
///
/// ```swift
/// let key = try PublicKey(.ec(curve: .p256, x: x, y: y))      // from a JWK
/// let ok = key.isValidSignature(signature, for: signingInput, algorithm: .es256)
/// ```
public final class PublicKey: Sendable {
    let handle: KeyHandle

    /// What a JWK carries of a public key, as unsigned big-endian bytes.
    public enum Components: Sendable, Hashable {
        /// "n" and "e".
        case rsa(modulus: [UInt8], exponent: [UInt8])
        /// "crv", "x" and "y", each the curve's size.
        case ec(curve: KeyType, x: [UInt8], y: [UInt8])
        /// OKP's "x" for "crv" Ed25519: 32 bytes.
        case ed25519(x: [UInt8])
    }

    init(handle: KeyHandle) { self.handle = handle }

    /// From PEM: a SubjectPublicKeyInfo ("PUBLIC KEY"), a certificate, or a
    /// private key, whose public half this is.
    public convenience init(pem: String) throws(CryptoError) {
        var pem = pem
        let raw = pem.withUTF8 { b in b.withMemoryRebound(to: CChar.self) { cv_key_from_pem($0.baseAddress, $0.count) } }
        self.init(handle: try KeyHandle(raw, "not a public key, certificate or private key in PEM"))
    }

    /// A certificate's public key, from its DER.
    public convenience init(certificateDER der: [UInt8]) throws(CryptoError) {
        let raw = der.withUnsafeBufferPointer { cv_key_from_certificate($0.baseAddress, $0.count) }
        self.init(handle: try KeyHandle(raw, "not a certificate in DER"))
    }

    /// From a JWK's members.
    public convenience init(_ components: Components) throws(CryptoError) {
        let raw: OpaquePointer?
        switch components {
        case let .rsa(n, e):
            raw = n.withUnsafeBufferPointer { n in
                e.withUnsafeBufferPointer { e in cv_key_from_rsa(n.baseAddress, n.count, e.baseAddress, e.count) }
            }
        case let .ec(curve, x, y):
            guard curve != .rsa, curve != .ed25519 else { throw .invalidArgument("\(curve) is not an EC curve") }
            raw = x.withUnsafeBufferPointer { x in
                y.withUnsafeBufferPointer { y in cv_key_from_ec(curve.code, x.baseAddress, x.count, y.baseAddress, y.count) }
            }
        case let .ed25519(x):
            raw = x.withUnsafeBufferPointer { cv_key_from_ed25519($0.baseAddress, $0.count) }
        }
        self.init(handle: try KeyHandle(raw, "bad key components"))
    }

    public var type: KeyType { handle.type }
    /// The key's size in bits.
    public var bits: Int { Int(cv_key_bits(handle.raw)) }

    /// As SubjectPublicKeyInfo PEM ("-----BEGIN PUBLIC KEY-----").
    public var pem: String { handle.pem(privateKey: false) }

    /// The JWK members.
    public var components: Components {
        let raw = handle.raw
        switch handle.type {
        case .rsa:
            var n = [UInt8](repeating: 0, count: 2048), e = [UInt8](repeating: 0, count: 16)
            var nLen = n.count, eLen = e.count
            guard cv_key_rsa_numbers(raw, &n, &nLen, &e, &eLen) == 0 else { preconditionFailure("an RSA key's numbers") }
            return .rsa(modulus: Array(n.prefix(nLen)), exponent: Array(e.prefix(eLen)))
        case .p256, .p384, .p521:
            var x = [UInt8](repeating: 0, count: 66), y = [UInt8](repeating: 0, count: 66)
            var xLen = x.count, yLen = y.count
            guard cv_key_ec_point(raw, &x, &xLen, &y, &yLen) == 0 else { preconditionFailure("an EC key's point") }
            return .ec(curve: handle.type, x: Array(x.prefix(xLen)), y: Array(y.prefix(yLen)))
        case .ed25519:
            var x = [UInt8](repeating: 0, count: 32)
            var len = x.count
            guard cv_key_raw_public(raw, &x, &len) == 0 else { preconditionFailure("an Ed25519 key's bytes") }
            return .ed25519(x: Array(x.prefix(len)))
        }
    }

    /// Whether signature is data's (a JWS signing input) signed with
    /// algorithm by this key's private half. ECDSA signatures are JWS's r || s;
    /// false for an algorithm that isn't this key's.
    public func isValidSignature(_ signature: [UInt8], for data: [UInt8], algorithm: SignatureAlgorithm) -> Bool {
        handle.verifyJWS(signature, data, algorithm)
    }

    /// The same for a TLS 1.3 signature (ECDSA in DER), such as a peer's
    /// CertificateVerify over the content RFC 8446 4.4.3 builds.
    public func isValidSignature(_ signature: [UInt8], for data: [UInt8], scheme: TLSSignatureScheme) -> Bool {
        handle.verifyTLS(signature, data, scheme)
    }
}

/// A private key: signs JWS (RS*, PS*, ES*, EdDSA) and TLS 1.3 signatures.
/// Immutable, so threads share one freely.
///
/// ```swift
/// let key = try SigningKey.generate(.p256)                  // an ACME account key
/// let stored = key.pem                                      // PKCS #8
/// let signature = try key.signature(for: signingInput, algorithm: .es256)
/// let jwk = key.publicKey.components
/// ```
public final class SigningKey: Sendable {
    let handle: KeyHandle

    /// Its public half.
    public let publicKey: PublicKey

    init(handle: KeyHandle) {
        self.handle = handle
        publicKey = PublicKey(handle: handle)
    }

    /// From a private key's PEM: PKCS #8 ("PRIVATE KEY"), or the traditional
    /// "RSA PRIVATE KEY" and "EC PRIVATE KEY". Not encrypted.
    public convenience init(pem: String) throws(CryptoError) {
        var pem = pem
        let raw = pem.withUTF8 { b in b.withMemoryRebound(to: CChar.self) { cv_key_from_pem($0.baseAddress, $0.count) } }
        let handle = try KeyHandle(raw, "not a private key in PEM")
        guard cv_key_has_private(handle.raw) == 1 else { throw .invalidKey("a public key, not a private one") }
        self.init(handle: handle)
    }

    /// An Ed25519 key from its 32-byte private key (the seed of RFC 8032).
    public convenience init(ed25519PrivateKey seed: [UInt8]) throws(CryptoError) {
        guard seed.count == 32 else { throw .invalidArgument("Ed25519 private key length") }
        let raw = seed.withUnsafeBufferPointer { cv_key_from_ed25519_private($0.baseAddress, 32) }
        self.init(handle: try KeyHandle(raw, "Ed25519 private key"))
    }

    /// A new key: RSA of rsaBits (2048 or more), a curve, or Ed25519.
    public static func generate(_ type: KeyType, rsaBits: Int = 2048) throws(CryptoError) -> SigningKey {
        guard type != .rsa || rsaBits >= 2048 && rsaBits <= 16384 else { throw .invalidArgument("RSA bits") }
        let raw = cv_key_generate(type.code, Int32(rsaBits))
        return SigningKey(handle: try KeyHandle(raw, "key generation"))
    }

    public var type: KeyType { handle.type }

    /// As PKCS #8 PEM ("-----BEGIN PRIVATE KEY-----").
    public var pem: String { handle.pem(privateKey: true) }

    /// data (a JWS signing input) signed with algorithm, as JWS has it:
    /// ECDSA as r || s at the curve's size, PS* with a salt the hash's length.
    public func signature(for data: [UInt8], algorithm: SignatureAlgorithm) throws(CryptoError) -> [UInt8] {
        try handle.signJWS(data, algorithm)
    }

    /// The TLS 1.3 schemes this key signs with, best first.
    public var signatureSchemes: [TLSSignatureScheme] { handle.tlsSchemes }

    /// data signed with a TLS 1.3 scheme (ECDSA in DER).
    public func signature(for data: [UInt8], scheme: TLSSignatureScheme) throws(CryptoError) -> [UInt8] {
        guard signatureSchemes.contains(scheme) else { throw .invalidArgument("\(scheme) with a \(type) key") }
        return try handle.signTLS(data, scheme)
    }
}
#endif
