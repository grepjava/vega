#if os(Linux) || canImport(Darwin)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

// An async stub resolver: queries go to the nameservers in resolv.conf over
// Vega's own UDP sockets (TCP when an answer is truncated), so a lookup is a
// wait like any other, bounded by its timeout and cancellable, and never
// holds a thread the way getaddrinfo does. Ported from Garuda's resolver.

/// Why a lookup failed.
public enum ResolveError: Error, Sendable, Hashable, CustomStringConvertible {
    /// No nameserver answered, across every server and attempt.
    case unanswered
    /// The name doesn't exist (NXDOMAIN).
    case noSuchName
    /// The name exists but has no address of the kind asked for.
    case noAddress
    /// The answer was truncated over UDP and again over TCP.
    case truncated
    /// The task was cancelled.
    case cancelled
    /// The name can't be asked about (an empty label, over 255 bytes, ...).
    case badName

    public var description: String {
        switch self {
        case .unanswered: "no nameserver answered"
        case .noSuchName: "no such name"
        case .noAddress: "no address for the name"
        case .truncated: "answer truncated over UDP and TCP"
        case .cancelled: "cancelled"
        case .badName: "not a valid name"
        }
    }

    /// As an `IOError`, for APIs that throw those.
    var ioError: IOError {
        switch self {
        case .cancelled: .cancelled
        case .unanswered: IOError(code: ETIMEDOUT)
        default: IOError(code: EADDRNOTAVAIL)
        }
    }
}

/// Looks names up by asking nameservers directly, like hickory-resolver in
/// Rust: no thread blocks in `getaddrinfo`.
///
/// ```swift
/// let addresses = try await Resolver.system.lookup(host: "example.com", port: 443)
/// let stream = try await TCPStream.connect(host: "example.com", port: 443, resolver: .system)
/// ```
///
/// Order of business for a name: an IP address is returned as is; then
/// /etc/hosts; then the cache; then the nameservers, A and AAAA at once,
/// each candidate from the search list in turn, each server `attempts`
/// times. Answers are cached for their TTL (clamped to 1 s–1 h); "no such
/// name" and "no address" for 30 s, so a typo can't become a query storm.
/// Unlike `getaddrinfo` it doesn't consult nsswitch, mDNS or other sources.
public final class Resolver: Sendable {
    /// The system's configuration (/etc/resolv.conf and /etc/hosts), read
    /// once on first use.
    public static let system = Resolver()

    public let config: ResolverConfig
    let hosts: HostsFile
    let cache: ResolverCache

    /// - Parameters:
    ///   - hostsPath: a hosts file to consult first, or nil for none.
    ///   - cacheLimit: the most answers kept.
    public init(config: ResolverConfig = .system(), hostsPath: String? = "/etc/hosts",
                cacheLimit: Int = 512) {
        self.config = config
        hosts = hostsPath.map(HostsFile.read) ?? HostsFile()
        cache = ResolverCache(limit: cacheLimit)
    }

    /// Every address for `host`, IPv6 first, each with `port`. Call from a
    /// task on a Vega runtime.
    public func lookup(host: String, port: Int) async throws(ResolveError) -> [SocketAddress] {
        if let literal = literal(host, port) { return literal }
        if let local = hosts.lookup(host, length: nil) { return addresses(local, port) }
        let both = await withTaskGroup(of: (Bool, Result<[[UInt8]], ResolveError>).self) { group in
            group.addTask { (true, await self.result(host, .aaaa)) }
            group.addTask { (false, await self.result(host, .a)) }
            var v6: Result<[[UInt8]], ResolveError> = .failure(.unanswered)
            var v4 = v6
            for await (isV6, r) in group {
                if isV6 { v6 = r } else { v4 = r }
            }
            return (v6, v4)
        }
        switch both {
        case (.success(let a), .success(let b)): return addresses(a + b, port)
        case (.success(let a), .failure), (.failure, .success(let a)): return addresses(a, port)
        case (.failure(let x), .failure(let y)): throw Self.worse(x, y)
        }
    }

    /// The IPv4 addresses for `host`, each with `port`.
    public func lookupIPv4(host: String, port: Int) async throws(ResolveError) -> [SocketAddress] {
        try await lookup(host, port, .a)
    }

    /// The IPv6 addresses for `host`, each with `port`.
    public func lookupIPv6(host: String, port: Int) async throws(ResolveError) -> [SocketAddress] {
        try await lookup(host, port, .aaaa)
    }

    /// Forget every cached answer.
    public func clearCache() {
        cache.removeAll()
    }

    private func lookup(_ host: String, _ port: Int, _ type: DNSRecordType) async throws(ResolveError) -> [SocketAddress] {
        let length = type == .a ? 4 : 16
        if let literal = literal(host, port) {
            let some = literal.filter { ($0.isIPv6 ? 16 : 4) == length }
            if some.isEmpty { throw .noAddress }
            return some
        }
        if let local = hosts.lookup(host, length: length) { return addresses(local, port) }
        return addresses(try await result(host, type).get(), port)
    }

    private func literal(_ host: String, _ port: Int) -> [SocketAddress]? {
        guard case .success(let parsed?) = SocketAddress.resolve(host, port, numericOnly: true) else { return nil }
        return parsed
    }

    private func addresses(_ ips: [[UInt8]], _ port: Int) -> [SocketAddress] {
        ips.compactMap { SocketAddress(ip: $0, port: port) }
    }

    /// When both families failed, the error that says more: a fault to
    /// retry beats an answer that the name has no address.
    private static func worse(_ x: ResolveError, _ y: ResolveError) -> ResolveError {
        let order: [ResolveError] = [.cancelled, .badName, .unanswered, .truncated, .noAddress, .noSuchName]
        return order.firstIndex(of: x)! <= order.firstIndex(of: y)! ? x : y
    }

    // MARK: - Asking

    private func result(_ name: String, _ type: DNSRecordType) async -> Result<[[UInt8]], ResolveError> {
        // Keyed on the name as asked, before the search list.
        let key = ResolverCache.Key(name: name.lowercased(), type: type.rawValue)
        if let cached = cache.take(key, now: Runtime.nowNanos) { return cached }

        var sawEmpty = false, sawNoSuchName = false
        let servers = config.nameservers.compactMap { server -> SocketAddress? in
            guard case .success(let a?) = SocketAddress.resolve(server, config.port, numericOnly: true) else { return nil }
            return a.first
        }
        candidates: for candidate in config.candidates(for: name) {
            for server in servers {
                for _ in 0..<max(config.attempts, 1) {
                    var answer = await ask(candidate, type, server, overTCP: false)
                    // Truncated means "ask me over TCP": the same server holds the answer.
                    if case .truncated = answer { answer = await ask(candidate, type, server, overTCP: true) }
                    switch answer {
                    case .addresses(let found, let ttl):
                        let r = Result<[[UInt8]], ResolveError>.success(found)
                        cache.store(key, r, ttl: ttl, now: Runtime.nowNanos)
                        return r
                    case .noSuchName:
                        // Every server will say so: on to the next candidate.
                        sawNoSuchName = true
                        continue candidates
                    case .empty:
                        sawEmpty = true
                        continue candidates
                    case .truncated:
                        return .failure(.truncated)
                    case .badName:
                        return .failure(.badName)
                    case .cancelled:
                        return .failure(.cancelled)
                    case .unanswered:
                        continue
                    }
                }
            }
        }
        // A name that exists with no record, or doesn't exist, is remembered;
        // silence is a network fault and isn't.
        guard sawEmpty || sawNoSuchName else { return .failure(.unanswered) }
        let r = Result<[[UInt8]], ResolveError>.failure(sawEmpty ? .noAddress : .noSuchName)
        cache.store(key, r, ttl: 0, now: Runtime.nowNanos)
        return r
    }

    /// What one question to one server produced.
    enum Answer: Sendable {
        /// The addresses, and the smallest TTL among the records used.
        case addresses([[UInt8]], ttl: UInt32)
        case noSuchName
        case truncated
        /// The name exists, with no record of the type asked for.
        case empty
        case unanswered
        case badName
        case cancelled
    }

    /// Ask `server` about `name` once, within the configured timeout.
    private func ask(_ name: String, _ type: DNSRecordType, _ server: SocketAddress,
                     overTCP: Bool) async -> Answer {
        // A fresh, unpredictable id each time, so an answer aimed at an
        // earlier query (the truncated one, say) can't be taken for this.
        var id: UInt16 = 0
        withUnsafeMutableBytes(of: &id) { cv_random_bytes($0.baseAddress, 2) }
        var query: [UInt8] = []
        do {
            try DNSMessage.encodeQuery(id: id, name: name, type: type, into: &query)
        } catch {
            return .badName
        }
        let question = query
        do {
            return try await Runtime.timeout(config.timeout) { () async throws -> Answer in
                overTCP ? try await Self.askTCP(question, id, name, type, server)
                        : try await Self.askUDP(question, id, name, type, server)
            }
        } catch {
            return Task.isCancelled ? .cancelled : .unanswered
        }
    }

    private static func askUDP(_ query: [UInt8], _ id: UInt16, _ name: String, _ type: DNSRecordType,
                               _ server: SocketAddress) async throws -> Answer {
        // Connected, so the kernel drops datagrams from anyone but the server.
        let socket = try UDPSocket.connect(to: server)
        var out = IOBuffer(capacity: query.count)
        _ = query.withUnsafeBytes { out.append($0) }
        _ = try await socket.send(out)
        var reply = IOBuffer(capacity: 4096)
        while true {
            reply.clear()
            _ = try await socket.receive(into: &reply)
            // Not an answer to this question: keep waiting for the real one.
            if let answer = reply.withUnsafeBytes({ believe($0, id, name, type) }) { return answer }
        }
    }

    /// The same question over TCP, framed with a two-byte length.
    private static func askTCP(_ query: [UInt8], _ id: UInt16, _ name: String, _ type: DNSRecordType,
                               _ server: SocketAddress) async throws -> Answer {
        let stream = try await TCPStream.connect(to: server)
        var framed = IOBuffer(capacity: query.count + 2)
        _ = withUnsafeBytes(of: UInt16(query.count).bigEndian) { framed.append($0) }
        _ = query.withUnsafeBytes { framed.append($0) }
        try await stream.write(framed)
        // A stream splits where it likes: read to the length, not to a boundary.
        var reply = IOBuffer(capacity: 2 + 512)
        while reply.count < 2 {
            if try await stream.read(into: &reply) == 0 { return .unanswered }
        }
        let length = reply.withUnsafeBytes { Int($0[0]) << 8 | Int($0[1]) }
        guard length > 0 else { return .unanswered }
        reply.reserveCapacity(2 + length)
        while reply.count < 2 + length {
            if try await stream.read(into: &reply) == 0 { return .unanswered }
        }
        let answer = reply.withUnsafeBytes { bytes in
            believe(UnsafeRawBufferPointer(rebasing: bytes[2..<(2 + length)]), id, name, type)
        }
        return answer ?? .unanswered
    }

    /// The answer `bytes` give to the question asked, or nil if they don't
    /// answer it: the id and the echoed question must both match, so a
    /// spoofer has to guess the name as well as the id.
    static func believe(_ bytes: UnsafeRawBufferPointer, _ id: UInt16, _ name: String,
                        _ type: DNSRecordType) -> Answer? {
        guard let parsed = try? DNSMessage.parse(bytes) else { return nil }
        guard parsed.isResponse, parsed.id == id, parsed.questionType == type.rawValue,
              sameName(parsed.questionName, name) else { return nil }
        if parsed.isTruncated { return .truncated }
        if parsed.responseCode == 3 { return .noSuchName }
        guard parsed.responseCode == 0 else { return nil }

        var found: [[UInt8]] = []
        // The shortest TTL of the records used, CNAMEs included: an address
        // outlasting the alias that led to it may be for the wrong name.
        var ttl = UInt32.max
        let wants = type == .aaaa ? 16 : 4
        for record in parsed.answers {
            switch record.data {
            case .address(let bytes) where bytes.count == wants:
                // The server follows CNAME chains and sends the addresses
                // along: taking every address takes the chain's end.
                found.append(bytes)
                ttl = min(ttl, record.ttl)
            case .canonicalName:
                ttl = min(ttl, record.ttl)
            default:
                continue
            }
        }
        return found.isEmpty ? .empty : .addresses(found, ttl: ttl == .max ? 0 : ttl)
    }

    /// Equal but for ASCII case and a trailing dot, which a server may change
    /// when it echoes the question.
    static func sameName(_ a: String, _ b: String) -> Bool {
        func normalise(_ s: String) -> [UInt8] {
            var out = Array(s.utf8)
            if out.last == UInt8(ascii: ".") { out.removeLast() }
            for i in out.indices where out[i] >= 65 && out[i] <= 90 { out[i] += 32 }
            return out
        }
        return normalise(a) == normalise(b)
    }
}

/// Answers and their expiry, shared by a resolver's lookups.
final class ResolverCache: @unchecked Sendable {
    struct Key: Hashable {
        var name: String
        var type: UInt16
    }

    private struct Entry {
        var result: Result<[[UInt8]], ResolveError>
        var expires: UInt64
    }

    let limit: Int
    /// TTL clamps: 0 often means a misconfigured load balancer (a query per
    /// connection), and a week outlives any deployment that would notice.
    var minimumSeconds: UInt64 = 1
    var maximumSeconds: UInt64 = 3600
    /// Negative answers are more likely mistakes being fixed: kept briefly.
    var negativeSeconds: UInt64 = 30

    private let lock = RawLock()
    private var entries: [Key: Entry] = [:]
    private(set) var hits = 0
    private(set) var misses = 0

    init(limit: Int) {
        self.limit = max(limit, 1)
    }

    deinit { lock.destroy() }

    var count: Int { lock.withLock { entries.count } }

    var stats: (hits: Int, misses: Int) { lock.withLock { (hits, misses) } }

    /// The answer if still good; an expired one is dropped.
    func take(_ key: Key, now: UInt64) -> Result<[[UInt8]], ResolveError>? {
        lock.withLock {
            guard let entry = entries[key] else {
                misses += 1
                return nil
            }
            guard now < entry.expires else {
                entries.removeValue(forKey: key)
                misses += 1
                return nil
            }
            hits += 1
            return entry.result
        }
    }

    /// Remember a result: addresses for `ttl` seconds (clamped), a negative
    /// answer for `negativeSeconds`.
    func store(_ key: Key, _ result: Result<[[UInt8]], ResolveError>, ttl: UInt32, now: UInt64) {
        let seconds: UInt64
        if case .success = result {
            seconds = min(max(UInt64(ttl), minimumSeconds), maximumSeconds)
        } else {
            seconds = negativeSeconds
        }
        lock.withLock {
            if entries.count >= limit, entries[key] == nil { makeRoom(now: now) }
            entries[key] = Entry(result: result, expires: now &+ seconds * 1_000_000_000)
        }
    }

    func removeAll() {
        lock.withLock { entries.removeAll() }
    }

    /// Drop the expired entries, or failing that the one expiring soonest
    /// (the cheapest loss, and no LRU bookkeeping on every lookup).
    private func makeRoom(now: UInt64) {
        let before = entries.count
        entries = entries.filter { now < $0.value.expires }
        guard entries.count == before,
              let soonest = entries.min(by: { $0.value.expires < $1.value.expires }) else { return }
        entries.removeValue(forKey: soonest.key)
    }
}
#endif
