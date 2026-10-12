#if os(Linux)
import CVega
import Glibc

/// An IPv4, IPv6 or Unix socket address. Plain bytes: copying it is free.
public struct SocketAddress: Sendable, Hashable, CustomStringConvertible {
    var raw: cv_sockaddr

    init(raw: cv_sockaddr) { self.raw = raw }

    /// `host` is an address, or a name resolved with a blocking lookup (the
    /// first address found is used). On a worker thread, prefer
    /// ``lookup(host:port:)``, which resolves names on the blocking pool.
    public init(host: String, port: Int) throws(IOError) {
        switch Self.resolve(host, port, numericOnly: false) {
        case .success(let all): self = all![0]
        case .failure(let e): throw e
        }
    }

    /// Every address for `host` and `port`, in the order to try them. An
    /// address (`"10.0.0.1"`, `"::1"`) is parsed in place; a name is looked
    /// up with `getaddrinfo` on the blocking pool, so no worker thread waits
    /// on DNS.
    public static func lookup(host: String, port: Int) async throws(IOError) -> [SocketAddress] {
        if let numeric = try resolve(host, port, numericOnly: true).get() { return numeric }
        return try await Runtime.blocking { () throws(IOError) -> [SocketAddress] in
            try resolve(host, port, numericOnly: false).get()!
        }
    }

    static let maxLookupResults = 16

    /// nil when `numericOnly` and `host` is a name.
    static func resolve(_ host: String, _ port: Int, numericOnly: Bool) -> Result<[SocketAddress]?, IOError> {
        withUnsafeTemporaryAllocation(of: cv_sockaddr.self, capacity: maxLookupResults) { buf in
            var count: Int32 = 0
            let e = cv_resolve_all(host, Int32(port), numericOnly ? 1 : 0, buf.baseAddress!,
                                   Int32(maxLookupResults), &count)
            if e == -1 { return .success(nil) }
            guard e == 0 else { return .failure(IOError(code: e)) }
            return .success((0..<Int(count)).map { SocketAddress(raw: buf[$0]) })
        }
    }

    /// The port, or nil for a Unix address.
    public var port: Int? {
        let p = withUnsafePointer(to: raw) { cv_sockaddr_port($0) }
        return p >= 0 ? Int(p) : nil
    }

    /// The IP address as text, or a Unix socket's path ("" if unnamed).
    public var host: String {
        withUnsafePointer(to: raw) { a in
            withUnsafeTemporaryAllocation(of: CChar.self, capacity: 128) { buf in
                cv_sockaddr_host(a, buf.baseAddress!, 128) == 0
                    ? String(cString: buf.baseAddress!) : ""
            }
        }
    }

    public var isIPv6: Bool { withUnsafePointer(to: raw) { cv_sockaddr_family($0) } == AF_INET6 }

    /// `1.2.3.4:80`, `[::1]:80`, or a Unix path.
    public var description: String {
        guard let port else { return host }
        return isIPv6 ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    @inline(__always) private func withBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        withUnsafeBytes(of: raw.storage) {
            body(UnsafeRawBufferPointer(rebasing: $0[..<min(Int(raw.len), $0.count)]))
        }
    }

    public static func == (a: SocketAddress, b: SocketAddress) -> Bool {
        a.raw.len == b.raw.len && a.withBytes { x in b.withBytes { y in x.elementsEqual(y) } }
    }

    public func hash(into hasher: inout Hasher) {
        withBytes { hasher.combine(bytes: $0) }
    }
}
#endif
