// On the OpenSSL or BoringSSL trait; not on iOS, tvOS, watchOS or visionOS.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import CVegaTLS
import Vega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// How a TLS endpoint behaves: rustls's `ClientConfig` or `ServerConfig`,
/// swift-nio-ssl's `TLSConfiguration`. Make a `TLSContext` from it once and
/// share that between connections.
///
/// ```swift
/// let server = try TLSContext(.server(identity: .files(chain: "cert.pem", key: "key.pem"),
///                                     applicationProtocols: ["h2", "http/1.1"]))
/// let client = try TLSContext(.client())            // the system's roots
/// ```
public struct TLSConfiguration: Sendable {
    public enum Role: Sendable, Hashable {
        case client, server
    }

    /// Which certificate authorities to trust.
    public enum TrustRoots: Sendable, Hashable {
        /// The system's: OpenSSL's default store (`SSL_CERT_FILE` and
        /// `SSL_CERT_DIR` override it), plus Windows' certificate store.
        case system
        /// Only these, as PEM.
        case certificates(String)
        /// The system's and these.
        case systemAnd(String)
    }

    /// Whether to check the peer's certificate.
    public enum Verification: Sendable, Hashable {
        /// Don't: any certificate, or (server) none, is accepted.
        case none
        /// Server only: ask clients for a certificate and check it if one
        /// comes, but let clients without one in.
        case optional
        /// Check it (against `trustRoots`, and on a client against the
        /// server name); a server refuses clients without one (mutual TLS).
        case required
    }

    public enum Version: UInt16, Sendable, Hashable, Comparable {
        case v1_2 = 0x0303
        case v1_3 = 0x0304

        public static func < (a: Version, b: Version) -> Bool { a.rawValue < b.rawValue }
    }

    public var role: Role
    /// Our certificate and key: a server's, or a client's for mutual TLS.
    public var identity: TLSIdentity?
    public var trustRoots: TrustRoots
    /// `.required` by default for a client, `.none` for a server.
    public var verification: Verification
    /// ALPN, in preference order: a client offers them, a server picks its
    /// first that the client offers (and refuses a client offering only
    /// others).
    public var applicationProtocols: [String]
    public var minimumVersion: Version = .v1_2
    /// nil: the newest the TLS library has.
    public var maximumVersion: Version?
    /// Server: other identities, by the name a client asks for (SNI).
    /// `"*.example.com"` matches one label. Unmatched names, and clients
    /// that ask for none, get `identity`.
    public var serverNames: [String: TLSIdentity] = [:]
    /// Client: sessions kept to resume, one per server name (0: none).
    public var sessionCacheSize = 256

    public init(role: Role, identity: TLSIdentity? = nil, trustRoots: TrustRoots = .system,
                verification: Verification? = nil, applicationProtocols: [String] = []) {
        self.role = role
        self.identity = identity
        self.trustRoots = trustRoots
        self.verification = verification ?? (role == .client ? .required : .none)
        self.applicationProtocols = applicationProtocols
    }

    /// A client checking servers against `trustRoots`.
    public static func client(trustRoots: TrustRoots = .system, applicationProtocols: [String] = [],
                              identity: TLSIdentity? = nil) -> TLSConfiguration {
        TLSConfiguration(role: .client, identity: identity, trustRoots: trustRoots,
                         applicationProtocols: applicationProtocols)
    }

    /// A server presenting `identity`.
    public static func server(identity: TLSIdentity, applicationProtocols: [String] = []) -> TLSConfiguration {
        TLSConfiguration(role: .server, identity: identity, applicationProtocols: applicationProtocols)
    }
}

/// A certificate chain (leaf first) and its private key, as PEM.
public struct TLSIdentity: Sendable, Hashable {
    public var certificateChain: String
    public var privateKey: String

    public init(certificateChain: String, privateKey: String) {
        self.certificateChain = certificateChain
        self.privateKey = privateKey
    }

    /// Read from PEM files (synchronously: do it at start-up).
    public static func files(chain: String, key: String) throws(IOError) -> TLSIdentity {
        TLSIdentity(certificateChain: try readText(chain), privateKey: try readText(key))
    }

    /// A new self-signed certificate for `names` (DNS names or IP
    /// addresses; the first is also the subject's CN) with a P-256 key,
    /// valid for `days`. For tests and development: a client trusts it only
    /// through `.certificates(identity.certificateChain)`.
    public static func selfSigned(names: [String], days: Int = 30) throws(IOError) -> TLSIdentity {
        var cert = [CChar](repeating: 0, count: 16 * 1024)
        var key = [CChar](repeating: 0, count: 8 * 1024)
        var certLen = Int32(cert.count), keyLen = Int32(key.count)
        let rc = cv_tls_self_signed(names.joined(separator: ","), Int32(days), &cert, &certLen, &key, &keyLen)
        guard rc == 0 else {
            throw IOError(code: IOError.tls.code, message: String(decoding: cert.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)), as: UTF8.self))
        }
        return TLSIdentity(certificateChain: string(cert, Int(certLen)), privateKey: string(key, Int(keyLen)))
    }
}

/// A `TLSConfiguration` made ready: OpenSSL's context, shared by any number
/// of connections on any threads.
public final class TLSContext: @unchecked Sendable {
    let raw: OpaquePointer
    public let configuration: TLSConfiguration
    /// The contexts for `serverNames`, which `raw` refers to.
    private let named: [TLSContext]

    public init(_ configuration: TLSConfiguration) throws(IOError) {
        let root = try TLSContext.make(configuration, identity: configuration.identity)
        var named: [TLSContext] = []
        for (name, identity) in configuration.serverNames.sorted(by: { $0.key < $1.key }) {
            var child = configuration
            child.identity = identity
            child.serverNames = [:]
            let context: TLSContext
            do {
                context = try TLSContext(child)
            } catch {
                cv_tls_ctx_free(root)
                throw error
            }
            named.append(context)
            if let e = TLSContext.call({ err, len in cv_tls_ctx_add_server_name(root, name, context.raw, err, len) }) {
                cv_tls_ctx_free(root)
                throw e
            }
        }
        self.configuration = configuration
        self.raw = root
        self.named = named
    }

    deinit { cv_tls_ctx_free(raw) }

    private static func make(_ c: TLSConfiguration, identity: TLSIdentity?) throws(IOError) -> OpaquePointer {
        var raw: OpaquePointer?
        if let e = call({ err, len in
            raw = cv_tls_ctx_new(c.role == .server ? 1 : 0, err, len)
            return raw == nil ? -1 : 0
        }) {
            throw e
        }
        let ctx = raw!
        func check(_ body: (UnsafeMutablePointer<CChar>, Int32) -> Int32) throws(IOError) {
            if let e = call(body) {
                cv_tls_ctx_free(ctx)
                throw e
            }
        }
        if let identity {
            try check { err, len in
                cv_tls_ctx_use_certificate(ctx, identity.certificateChain, Int32(identity.certificateChain.utf8.count),
                                           identity.privateKey, Int32(identity.privateKey.utf8.count), err, len)
            }
        } else if c.role == .server {
            cv_tls_ctx_free(ctx)
            throw IOError(code: IOError.tls.code, message: "a server needs an identity")
        }
        if c.verification != .none || c.role == .client {
            switch c.trustRoots {
            case .system:
                try check { err, len in cv_tls_ctx_use_system_trust(ctx, err, len) }
            case .certificates(let pem):
                try check { err, len in cv_tls_ctx_add_trust(ctx, pem, Int32(pem.utf8.count), err, len) }
            case .systemAnd(let pem):
                try check { err, len in cv_tls_ctx_use_system_trust(ctx, err, len) }
                try check { err, len in cv_tls_ctx_add_trust(ctx, pem, Int32(pem.utf8.count), err, len) }
            }
        }
        switch c.verification {
        case .none: cv_tls_ctx_set_verify(ctx, CV_TLS_VERIFY_NONE)
        case .optional: cv_tls_ctx_set_verify(ctx, c.role == .server ? CV_TLS_VERIFY_OPTIONAL : CV_TLS_VERIFY_REQUIRED)
        case .required: cv_tls_ctx_set_verify(ctx, CV_TLS_VERIFY_REQUIRED)
        }
        let newest = Int32(c.maximumVersion?.rawValue ?? 0)
        try check { err, len in cv_tls_ctx_set_versions(ctx, Int32(c.minimumVersion.rawValue), newest, err, len) }
        if !c.applicationProtocols.isEmpty {
            var wire: [UInt8] = []
            for p in c.applicationProtocols {
                let bytes = Array(p.utf8)
                guard !bytes.isEmpty, bytes.count < 256 else {
                    cv_tls_ctx_free(ctx)
                    throw IOError(code: IOError.tls.code, message: "an ALPN protocol name must be 1 to 255 bytes")
                }
                wire.append(UInt8(bytes.count))
                wire += bytes
            }
            try check { err, len in cv_tls_ctx_set_alpn(ctx, wire, Int32(wire.count), err, len) }
        }
        if c.role == .client { cv_tls_ctx_set_session_cache(ctx, Int32(max(c.sessionCacheSize, 0))) }
        return ctx
    }

    /// Run a C call that reports failure as -1 plus a message: the error,
    /// or nil.
    static func call(_ body: (UnsafeMutablePointer<CChar>, Int32) -> Int32) -> IOError? {
        var err = [CChar](repeating: 0, count: 256)
        let rc = err.withUnsafeMutableBufferPointer { body($0.baseAddress!, Int32($0.count)) }
        guard rc != 0 else { return nil }
        return IOError(code: IOError.tls.code, message: string(err, err.firstIndex(of: 0) ?? err.count))
    }
}

private func string(_ chars: [CChar], _ count: Int) -> String {
    String(decoding: chars.prefix(count).map(UInt8.init(bitPattern:)), as: UTF8.self)
}

private func readText(_ path: String) throws(IOError) -> String {
    guard let f = fopen(path, "rb") else {
        #if os(Windows)
        var code: Int32 = 0
        _ = _get_errno(&code)
        throw IOError(code: code)
        #else
        throw IOError(code: errno)
        #endif
    }
    defer { fclose(f) }
    var bytes: [UInt8] = []
    var chunk = [UInt8](repeating: 0, count: 16 * 1024)
    while true {
        let n = fread(&chunk, 1, chunk.count, f)
        if n > 0 { bytes += chunk.prefix(n) }
        if n < chunk.count {
            if ferror(f) != 0 { throw IOError(code: EIO) }
            break
        }
    }
    return String(decoding: bytes, as: UTF8.self)
}
#endif
