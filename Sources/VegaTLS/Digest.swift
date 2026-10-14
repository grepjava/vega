// On every platform: from the TLS library on the OpenSSL or BoringSSL trait,
// and from CommonCrypto on Apple's, with or without one.
import CVegaTLS

/// SHA-256 and what is built on it, for a protocol's authentication: SCRAM's
/// keys, a signed cookie. Not a hash of anyone's own making -- the TLS
/// library's, or CommonCrypto's.
///
/// ```swift
/// let salted = try Digest.pbkdf2SHA256(password: Array("pencil".utf8), salt: salt, iterations: 4096)
/// let key = try Digest.hmacSHA256(key: salted, Array("Client Key".utf8))
/// ```
public enum Digest {
    /// False on a platform with neither a TLS library nor CommonCrypto,
    /// where every function here throws.
    public static var isAvailable: Bool { cv_digest_available() == 1 }

    public static func sha256(_ data: [UInt8]) throws(DigestError) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        let status = data.withUnsafeBytes { d in
            out.withUnsafeMutableBufferPointer { cv_sha256(d.baseAddress, d.count, $0.baseAddress) }
        }
        guard status == 0 else { throw DigestError() }
        return out
    }

    public static func hmacSHA256(key: [UInt8], _ data: [UInt8]) throws(DigestError) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        let status = key.withUnsafeBytes { k in
            data.withUnsafeBytes { d in
                out.withUnsafeMutableBufferPointer {
                    cv_hmac_sha256(k.baseAddress, k.count, d.baseAddress, d.count, $0.baseAddress)
                }
            }
        }
        guard status == 0 else { throw DigestError() }
        return out
    }

    /// PBKDF2 with HMAC-SHA-256: `length` bytes derived from `password` and
    /// `salt` in `iterations` rounds.
    public static func pbkdf2SHA256(password: [UInt8], salt: [UInt8], iterations: Int,
                                    length: Int = 32) throws(DigestError) -> [UInt8] {
        guard iterations > 0, iterations <= Int(UInt32.max), length > 0 else { throw DigestError() }
        var out = [UInt8](repeating: 0, count: length)
        let status = password.withUnsafeBytes { p in
            salt.withUnsafeBytes { s in
                out.withUnsafeMutableBufferPointer {
                    cv_pbkdf2_sha256(p.baseAddress, p.count, s.baseAddress, s.count, UInt32(iterations),
                                     $0.baseAddress, length)
                }
            }
        }
        guard status == 0 else { throw DigestError() }
        return out
    }
}

/// A digest that could not be taken: none on this platform, or an argument
/// out of range.
public struct DigestError: Error, Equatable, Sendable {
    public init() {}
}
