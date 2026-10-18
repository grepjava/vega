// On every platform: Digest throws it where the rest of VegaCrypto isn't.

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
}
