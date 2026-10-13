#if os(Linux) || canImport(Darwin) || os(Windows)
import CVega

/// What a `Resolver` asks and whom: the parts of resolv.conf a stub resolver
/// acts on. Options it doesn't implement are ignored, not refused: the file
/// is the system's.
public struct ResolverConfig: Sendable, Equatable {
    /// Nameserver addresses, tried in order.
    public var nameservers: [String]
    /// The port nameservers listen on. resolv.conf can't say; tests can.
    public var port: Int = 53
    /// Domains appended to a name with fewer than `ndots` dots.
    public var search: [String]
    /// A name with at least this many dots is tried as it stands first.
    public var ndots = 1
    /// How long to wait for each answer.
    public var timeout: Duration = .seconds(5)
    /// Tries per nameserver.
    public var attempts = 2

    /// Used when resolv.conf names no nameserver: localhost, never a public
    /// resolver nobody chose.
    public static let fallbackNameserver = "127.0.0.1"

    public init(nameservers: [String] = [], search: [String] = []) {
        self.nameservers = nameservers
        self.search = search
    }

    /// Whether `name` is tried as it stands before the search list. A
    /// trailing dot makes it absolute.
    func isAbsolute(_ name: String) -> Bool {
        if name.hasSuffix(".") { return true }
        var dots = 0
        for byte in name.utf8 where byte == UInt8(ascii: ".") { dots += 1 }
        return dots >= ndots
    }

    /// The names to ask, in order. With enough dots, the name first and then
    /// the search list; with too few, the search list first (with ndots 5, as
    /// in Kubernetes, every external name walks the list before itself).
    func candidates(for name: String) -> [String] {
        if name.hasSuffix(".") { return [String(name.dropLast())] }
        var out: [String] = []
        out.reserveCapacity(search.count + 1)
        if isAbsolute(name) { out.append(name) }
        for domain in search { out.append("\(name).\(domain)") }
        if !isAbsolute(name) { out.append(name) }
        return out
    }
}

extension ResolverConfig {
    /// The system's configuration, from `path`. A missing or unreadable file
    /// gives the defaults, and no nameserver gives `fallbackNameserver`.
    public static func system(path: String = "/etc/resolv.conf") -> ResolverConfig {
        var config = readSmallFile(path).map(parse) ?? ResolverConfig()
        if config.nameservers.isEmpty { config.nameservers = [fallbackNameserver] }
        return config
    }

    /// Parse resolv.conf text.
    public static func parse(_ text: String) -> ResolverConfig {
        parse(Array(text.utf8))
    }

    static func parse(_ bytes: [UInt8]) -> ResolverConfig {
        var config = ResolverConfig()
        for fields in configLines(bytes) {
            switch fields[0] {
            case "nameserver":
                if fields.count > 1 { config.nameservers.append(String(fields[1])) }
            case "search":
                // The last search line wins, as in every resolver.
                config.search = fields.dropFirst().map(String.init)
            case "domain":
                // The older one-entry spelling; search supersedes it.
                if config.search.isEmpty, fields.count > 1 {
                    config.search = [String(fields[1])]
                }
            case "options":
                for option in fields.dropFirst() {
                    if let value = number(option, after: "ndots:") {
                        config.ndots = min(value, 15)
                    } else if let value = number(option, after: "timeout:") {
                        config.timeout = .seconds(min(max(value, 1), 30))
                    } else if let value = number(option, after: "attempts:") {
                        config.attempts = min(max(value, 1), 5)
                    }
                }
            default:
                continue
            }
        }
        // "search ." is systemd for no search list.
        config.search.removeAll { $0 == "." || $0.isEmpty }
        return config
    }

    private static func number(_ field: Substring, after prefix: String) -> Int? {
        guard field.hasPrefix(prefix) else { return nil }
        let digits = field.dropFirst(prefix.count)
        guard !digits.isEmpty, digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        return Int(digits)
    }
}

/// /etc/hosts: names (lowercased) to addresses, in file order.
struct HostsFile: Sendable, Equatable {
    var entries: [String: [[UInt8]]] = [:]

    static func read(path: String) -> HostsFile {
        readSmallFile(path, limit: 1024 * 1024).map(parse) ?? HostsFile()
    }

    static func parse(_ text: String) -> HostsFile {
        parse(Array(text.utf8))
    }

    static func parse(_ bytes: [UInt8]) -> HostsFile {
        var hosts = HostsFile()
        for fields in configLines(bytes) where fields.count > 1 {
            guard let ip = ipBytes(String(fields[0])) else { continue }
            for name in fields.dropFirst() {
                let key = name.lowercased()
                if hosts.entries[key]?.contains(ip) != true { hosts.entries[key, default: []].append(ip) }
            }
        }
        return hosts
    }

    /// The addresses for `name`, of one length (4 or 16) or both (nil).
    func lookup(_ name: String, length: Int?) -> [[UInt8]]? {
        var key = name.lowercased()
        if key.hasSuffix(".") { key.removeLast() }
        guard let all = entries[key] else { return nil }
        let some = length.map { n in all.filter { $0.count == n } } ?? all
        return some.isEmpty ? nil : some
    }
}

/// `text` as an IPv4 or IPv6 address's bytes, or nil if it isn't one.
func ipBytes(_ text: String) -> [UInt8]? {
    guard case .success(let parsed?) = SocketAddress.resolve(text, 0, numericOnly: true),
          let first = parsed.first else { return nil }
    return first.ipBytes
}

/// The whitespace-separated fields of each non-empty line, comments (# and ;)
/// removed. Tolerates CRLF.
private func configLines(_ bytes: [UInt8]) -> [[Substring]] {
    var out: [[Substring]] = []
    for raw in bytes.split(separator: 10, omittingEmptySubsequences: true) {
        var line = String(decoding: raw, as: UTF8.self)
        if let cut = line.firstIndex(where: { $0 == "#" || $0 == ";" }) {
            line = String(line[..<cut])
        }
        let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\r" })
        if !fields.isEmpty { out.append(fields) }
    }
    return out
}

/// A small regular file's bytes, or nil (missing, not a regular file,
/// over `limit`, unreadable).
private func readSmallFile(_ path: String, limit: Int = 64 * 1024) -> [UInt8]? {
    var bytes = [UInt8](repeating: 0, count: limit)
    let n = bytes.withUnsafeMutableBytes { cv_read_small_file(path, $0.baseAddress, limit) }
    guard n >= 0 else { return nil }
    bytes.removeSubrange(n...)
    return bytes
}
#endif
