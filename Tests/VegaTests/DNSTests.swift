#if os(Linux) || canImport(Darwin) || os(Windows)
import CVega
import Synchronization
import Testing
@testable import Vega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// Builds a message by hand, so a test says what is on the wire rather than
/// what some encoder thought it meant.
private struct Wire {
    var bytes: [UInt8] = []

    mutating func u8(_ value: UInt8) { bytes.append(value) }

    mutating func u16(_ value: UInt16) {
        bytes.append(UInt8(truncatingIfNeeded: value >> 8))
        bytes.append(UInt8(truncatingIfNeeded: value))
    }

    mutating func u32(_ value: UInt32) {
        u16(UInt16(truncatingIfNeeded: value >> 16))
        u16(UInt16(truncatingIfNeeded: value))
    }

    /// A header with one question and `answers` answers, as a reply.
    mutating func header(id: UInt16 = 0x1234, flags: UInt16 = 0x8180,
                         questions: UInt16 = 1, answers: UInt16 = 0) {
        u16(id); u16(flags); u16(questions); u16(answers)
        u16(0); u16(0)
    }

    mutating func name(_ text: String) {
        for label in text.split(separator: ".") {
            u8(UInt8(label.utf8.count))
            bytes.append(contentsOf: Array(label.utf8))
        }
        u8(0)
    }

    /// A compression pointer to `offset`.
    mutating func pointer(to offset: Int) {
        u16(UInt16(0xc000 | offset))
    }

    mutating func question(_ text: String, type: UInt16 = 1) {
        name(text); u16(type); u16(1)
    }
}

private func parse(_ wire: Wire) throws -> DNSResponse {
    try wire.bytes.withUnsafeBytes { try DNSMessage.parse($0) }
}

private func parseError(_ wire: Wire) -> DNSError? {
    do {
        _ = try wire.bytes.withUnsafeBytes { try DNSMessage.parse($0) }
        return nil
    } catch {
        return error as? DNSError
    }
}

@Suite struct DNSMessageTests {
    @Test func aQueryIsTheBytesTheRFCAsksFor() throws {
        var buffer: [UInt8] = []
        try DNSMessage.encodeQuery(id: 0xbeef, name: "alpha.example", type: .a, into: &buffer)
        #expect(buffer == [
            0xbe, 0xef,                                  // id
            0x01, 0x00,                                  // recursion desired
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            5, 97, 108, 112, 104, 97,                    // "alpha"
            7, 101, 120, 97, 109, 112, 108, 101,         // "example"
            0,                                           // root
            0x00, 0x01,                                  // A
            0x00, 0x01,                                  // IN
        ])
    }

    @Test func aTrailingDotIsTheRootAndNotAnEmptyLabel() throws {
        var withDot: [UInt8] = []
        var without: [UInt8] = []
        try DNSMessage.encodeQuery(id: 1, name: "alpha.example.", type: .a, into: &withDot)
        try DNSMessage.encodeQuery(id: 1, name: "alpha.example", type: .a, into: &without)
        #expect(withDot == without)
    }

    @Test func aQueryReplacesTheBufferContents() throws {
        var buffer: [UInt8] = Array(repeating: 0xff, count: 500)
        try DNSMessage.encodeQuery(id: 1, name: "a.example", type: .aaaa, into: &buffer)
        #expect(buffer.count == 12 + 1 + 1 + 1 + 7 + 1 + 4)
        #expect(buffer[0] == 0)
        #expect(buffer[1] == 1)
    }

    @Test func anEmptyLabelIsRefused() {
        var buffer: [UInt8] = []
        for name in ["alpha..example", ".alpha", ""] {
            #expect(throws: DNSError.badLabel) {
                try DNSMessage.encodeQuery(id: 1, name: name, type: .a, into: &buffer)
            }
        }
    }

    @Test func aLabelOverSixtyThreeBytesIsRefused() {
        var buffer: [UInt8] = []
        let label = String(repeating: "a", count: 64)
        #expect(throws: DNSError.badLabel) {
            try DNSMessage.encodeQuery(id: 1, name: "\(label).example", type: .a, into: &buffer)
        }
    }

    @Test func aNameOverTwoHundredAndFiftyFiveBytesIsRefused() {
        var buffer: [UInt8] = []
        let label = String(repeating: "a", count: 63)
        let name = [String](repeating: label, count: 5).joined(separator: ".")
        #expect(throws: DNSError.nameTooLong) {
            try DNSMessage.encodeQuery(id: 1, name: name, type: .a, into: &buffer)
        }
    }

    @Test func anAnswerIsRead() throws {
        var wire = Wire()
        wire.header(answers: 1)
        wire.question("alpha.example")
        wire.name("alpha.example")
        wire.u16(1); wire.u16(1); wire.u32(300); wire.u16(4)
        wire.bytes.append(contentsOf: [93, 184, 216, 34])

        let response = try parse(wire)
        #expect(response.id == 0x1234)
        #expect(response.isResponse)
        #expect(!response.isTruncated)
        #expect(response.responseCode == 0)
        #expect(response.questionName == "alpha.example")
        #expect(response.questionType == 1)
        #expect(response.answers == [
            DNSRecord(name: "alpha.example", ttl: 300, data: .address([93, 184, 216, 34]))
        ])
    }

    @Test func aCompressedNameIsFollowed() throws {
        var wire = Wire()
        wire.header(answers: 1)
        wire.question("alpha.example")
        wire.pointer(to: 12)
        wire.u16(1); wire.u16(1); wire.u32(60); wire.u16(4)
        wire.bytes.append(contentsOf: [10, 0, 0, 1])

        let response = try parse(wire)
        #expect(response.answers.count == 1)
        #expect(response.answers[0].name == "alpha.example")
        #expect(response.answers[0].data == .address([10, 0, 0, 1]))
    }

    @Test func anAAAARecordIsSixteenBytes() throws {
        var wire = Wire()
        wire.header(answers: 1)
        wire.question("alpha.example", type: 28)
        wire.pointer(to: 12)
        wire.u16(28); wire.u16(1); wire.u32(60); wire.u16(16)
        wire.bytes.append(contentsOf: Array(repeating: 0, count: 15) + [1])

        let response = try parse(wire)
        #expect(response.answers[0].data == .address(Array(repeating: 0, count: 15) + [1]))
    }

    @Test func anAliasIsReadAsTheNameItPointsAt() throws {
        var wire = Wire()
        wire.header(answers: 2)
        wire.question("www.example")
        wire.pointer(to: 12)
        wire.u16(5); wire.u16(1); wire.u32(60)
        wire.u16(15)                                    // "alpha.example" on the wire
        wire.name("alpha.example")
        wire.name("alpha.example")
        wire.u16(1); wire.u16(1); wire.u32(60); wire.u16(4)
        wire.bytes.append(contentsOf: [10, 0, 0, 2])

        let response = try parse(wire)
        #expect(response.answers.count == 2)
        #expect(response.answers[0].data == .canonicalName("alpha.example"))
        #expect(response.answers[1].data == .address([10, 0, 0, 2]))
    }

    @Test func aTypeWeDoNotModelIsKeptRatherThanRefused() throws {
        var wire = Wire()
        wire.header(answers: 1)
        wire.question("alpha.example")
        wire.pointer(to: 12)
        wire.u16(16); wire.u16(1); wire.u32(60); wire.u16(3)   // TXT
        wire.bytes.append(contentsOf: [2, 104, 105])
        #expect(try parse(wire).answers[0].data == .other(16))
    }

    @Test func truncationAndNameErrorsAreReported() throws {
        var wire = Wire()
        wire.header(flags: 0x8380)
        wire.question("alpha.example")
        #expect(try parse(wire).isTruncated)

        var nx = Wire()
        nx.header(flags: 0x8183)
        nx.question("nope.example")
        #expect(try parse(nx).responseCode == 3)
    }

    // What a stranger can send.

    @Test func aPointerToItselfIsRefused() {
        var wire = Wire()
        wire.header()
        wire.pointer(to: 12)                            // at offset 12
        wire.u16(1); wire.u16(1)
        #expect(parseError(wire) == .badPointer)
    }

    @Test func aForwardPointerIsRefused() {
        var wire = Wire()
        wire.header()
        wire.pointer(to: 40)
        wire.u16(1); wire.u16(1)
        wire.bytes.append(contentsOf: Array(repeating: 0, count: 24))
        #expect(parseError(wire) == .badPointer)
    }

    /// Two pointers that would cycle: one hop has to go forwards, and is
    /// refused there.
    @Test func aPairOfPointersThatWouldCycleIsRefused() {
        var wire = Wire()
        wire.header(answers: 1)
        wire.question("alpha.example")                  // 12...28
        let first = wire.bytes.count                    // 29
        wire.pointer(to: first + 2)                     // 29 -> 31, forwards
        wire.pointer(to: first)                         // 31 -> 29, backwards
        wire.pointer(to: first + 2)                     // owner name -> 31
        wire.u16(1); wire.u16(1); wire.u32(60); wire.u16(4)
        wire.bytes.append(contentsOf: [10, 0, 0, 1])
        #expect(parseError(wire) == .badPointer)
    }

    @Test func aChainThatKeepsGoingBackIsAccepted() throws {
        var wire = Wire()
        wire.header(answers: 1)
        wire.question("alpha.example")
        wire.pointer(to: 12)
        wire.u16(5); wire.u16(1); wire.u32(60)
        wire.u16(2)
        wire.pointer(to: 12)
        let response = try parse(wire)
        #expect(response.answers[0].name == "alpha.example")
        #expect(response.answers[0].data == .canonicalName("alpha.example"))
    }

    @Test func lengthsRunningPastTheEndAreRefused() {
        var label = Wire()
        label.header()
        label.u8(40)                                    // claims forty bytes
        label.bytes.append(contentsOf: Array("short".utf8))
        #expect(parseError(label) == .truncated)

        var record = Wire()
        record.header(answers: 1)
        record.question("alpha.example")
        record.pointer(to: 12)
        record.u16(1); record.u16(1); record.u32(60)
        record.u16(4000)                                // four bytes are present
        record.bytes.append(contentsOf: [10, 0, 0, 1])
        #expect(parseError(record) == .truncated)

        var answers = Wire()
        answers.header(answers: 65535)
        answers.question("alpha.example")
        #expect(parseError(answers) == .truncated)

        var short = Wire()
        short.u16(0x1234); short.u16(0x8180)
        #expect(parseError(short) == .truncated)
    }

    @Test func aReservedLabelKindIsRefused() {
        var wire = Wire()
        wire.header()
        wire.u8(0x80)
        wire.u8(0)
        #expect(parseError(wire) == .badLabel)
    }
}

private func writeText(_ text: String, to path: String) -> Bool {
    guard let file = fopen(path, "w") else { return false }
    defer { fclose(file) }
    return text.withCString { fputs($0, file) >= 0 }
}

/// A TCP listener and a UDP socket on one port. The port UDP picked may be
/// taken or reserved for TCP (Windows reserves blocks of 100 for Hyper-V,
/// and hands out ports in sequence): retry past a whole block.
private struct BoundPair: ~Copyable {
    var listener: TCPListener
    var udp: UDPSocket
}

private func bindPair(host: String, port: Int) throws -> BoundPair {
    var attempts = 0
    while true {
        let udp = try UDPSocket.bind(host: host, port: port)
        do {
            let listener = try TCPListener.bind(host: host, port: try udp.localAddress.port ?? 0)
            return BoundPair(listener: listener, udp: udp)
        } catch {
            attempts += 1
            if port != 0 || attempts >= 250 { throw error }
        }
    }
}

private func tempPath(_ name: String) -> String {
    "\(testTempDirectory())/vega-\(getpid())-\(name)"
}

@Suite struct ResolverConfigTests {
    @Test func theFileIsParsed() {
        let config = ResolverConfig.parse("""
        # nameserver 1.1.1.1
        ; nameserver 2.2.2.2
        nameserver 10.0.0.1 # the real one\r
        nameserver 10.0.0.2
        search first.internal
        search second.internal third.internal ; the last wins
        options edns0 trust-ad rotate ndots:3 timeout:2 attempts:4
        """)
        #expect(config.nameservers == ["10.0.0.1", "10.0.0.2"])
        #expect(config.search == ["second.internal", "third.internal"])
        #expect(config.ndots == 3)
        #expect(config.timeout == .seconds(2))
        #expect(config.attempts == 4)
    }

    @Test func domainIsTheOlderSpellingAndSearchSupersedesIt() {
        #expect(ResolverConfig.parse("domain old.internal\nsearch new.internal").search == ["new.internal"])
        #expect(ResolverConfig.parse("domain old.internal").search == ["old.internal"])
    }

    /// systemd's way of saying there's no search list.
    @Test func aLoneDotIsNotASearchDomain() {
        #expect(ResolverConfig.parse("nameserver 127.0.0.53\nsearch .").search.isEmpty)
    }

    @Test func numericOptionsAreBounded() {
        let config = ResolverConfig.parse("options ndots:99 timeout:900 attempts:99")
        #expect(config.ndots == 15)
        #expect(config.timeout == .seconds(30))
        #expect(config.attempts == 5)
        #expect(ResolverConfig.parse("options ndots: ndots:x ndots:2").ndots == 2)
    }

    @Test func candidatesFollowNdots() {
        var config = ResolverConfig(search: ["a.internal", "b.internal"])
        #expect(config.candidates(for: "example.com")
                == ["example.com", "example.com.a.internal", "example.com.b.internal"])
        #expect(config.candidates(for: "db") == ["db.a.internal", "db.b.internal", "db"])
        config.ndots = 5
        #expect(config.candidates(for: "example.com")
                == ["example.com.a.internal", "example.com.b.internal", "example.com"])
        // A trailing dot is absolute whatever ndots says, and isn't sent.
        #expect(config.candidates(for: "example.com.") == ["example.com"])
        #expect(ResolverConfig().candidates(for: "db") == ["db"])
    }

    @Test func theSystemFileIsRead() {
        let path = tempPath("resolv.conf")
        #expect(writeText("nameserver 10.1.2.3\nsearch one.internal\noptions ndots:2\n", to: path))
        defer { unlink(path) }
        let config = ResolverConfig.system(path: path)
        #expect(config.nameservers == ["10.1.2.3"])
        #expect(config.search == ["one.internal"])
        #expect(config.ndots == 2)
    }

    /// No file, or one naming no nameserver: localhost, not a public resolver.
    @Test func withoutANameserverLocalhostIsUsed() {
        #expect(ResolverConfig.system(path: tempPath("missing.conf")).nameservers == ["127.0.0.1"])
        let path = tempPath("search-only.conf")
        #expect(writeText("search only.internal\n", to: path))
        defer { unlink(path) }
        let config = ResolverConfig.system(path: path)
        #expect(config.nameservers == ["127.0.0.1"])
        #expect(config.search == ["only.internal"])
    }

    #if !os(Windows) // no fifos there
    /// A fifo would block the reader, and a directory isn't a file: both
    /// refused by the open itself.
    @Test func onlyRegularFilesAreRead() {
        let path = tempPath("fifo")
        unlink(path)
        #expect(mkfifo(path, 0o644) == 0)
        defer { unlink(path) }
        var buf = [UInt8](repeating: 0, count: 64)
        #expect(buf.withUnsafeMutableBytes { cv_read_small_file(path, $0.baseAddress, 64) } == -1)
        #expect(buf.withUnsafeMutableBytes { cv_read_small_file("/tmp", $0.baseAddress, 64) } == -1)
        unlink(path)
        #expect(writeText("nameserver 10.9.9.9\n", to: path))
        #expect(buf.withUnsafeMutableBytes { cv_read_small_file(path, $0.baseAddress, 64) } == 20)
        // Longer than the limit is refused, not cut.
        #expect(buf.withUnsafeMutableBytes { cv_read_small_file(path, $0.baseAddress, 19) } == -1)
    }
    #endif

    @Test func hostsFile() {
        let hosts = HostsFile.parse("""
        127.0.0.1   localhost
        ::1         localhost ip6-localhost
        10.0.0.5    DB.internal db  # a comment
        not-an-ip   broken
        """)
        #expect(hosts.lookup("localhost", length: nil) == [[127, 0, 0, 1], Array(repeating: 0, count: 15) + [1]])
        #expect(hosts.lookup("localhost", length: 4) == [[127, 0, 0, 1]])
        #expect(hosts.lookup("db.INTERNAL.", length: nil) == [[10, 0, 0, 5]])
        #expect(hosts.lookup("db", length: 16) == nil)
        #expect(hosts.lookup("broken", length: nil) == nil)
    }
}

@Suite struct ResolverCacheTests {
    @Test func entriesExpireAndClamp() {
        let cache = ResolverCache(limit: 8)
        let key = ResolverCache.Key(name: "a", type: 1)
        let s: UInt64 = 1_000_000_000
        cache.store(key, .success([[1, 2, 3, 4]]), ttl: 0, now: 0)    // clamped up to 1 s
        #expect(cache.take(key, now: s - 1) == .success([[1, 2, 3, 4]]))
        #expect(cache.take(key, now: s) == nil)
        cache.store(key, .success([[1, 2, 3, 4]]), ttl: 999_999, now: 0)    // down to 1 h
        #expect(cache.take(key, now: 3599 * s) != nil)
        #expect(cache.take(key, now: 3600 * s) == nil)
        cache.store(key, .failure(.noSuchName), ttl: 999, now: 0)    // negative: 30 s
        #expect(cache.take(key, now: 29 * s) == .failure(.noSuchName))
        #expect(cache.take(key, now: 30 * s) == nil)
    }

    @Test func aFullCacheDropsTheSoonestToExpire() {
        let cache = ResolverCache(limit: 2)
        let a = ResolverCache.Key(name: "a", type: 1), b = ResolverCache.Key(name: "b", type: 1)
        let c = ResolverCache.Key(name: "c", type: 1)
        cache.store(a, .success([[1, 1, 1, 1]]), ttl: 100, now: 0)
        cache.store(b, .success([[2, 2, 2, 2]]), ttl: 10, now: 0)
        cache.store(c, .success([[3, 3, 3, 3]]), ttl: 50, now: 0)
        #expect(cache.count == 2)
        #expect(cache.take(b, now: 0) == nil)
        #expect(cache.take(a, now: 0) != nil)
        #expect(cache.take(c, now: 0) != nil)
    }
}

// MARK: - Against a fake nameserver

/// How the fake nameserver answers one question.
private enum Reply: Sendable {
    case addresses([[UInt8]], ttl: UInt32 = 300)
    case noSuchName
    case empty
    /// Truncated over UDP; these addresses over TCP.
    case truncated([[UInt8]])
    case silent
    /// A reply with the wrong id first, then the real one.
    case spoofThen([[UInt8]])
}

/// A nameserver on loopback, UDP and TCP on one port, answering with
/// `answer(name, type)` and logging every question it gets.
private final class FakeNameserver: @unchecked Sendable {
    let port: Int
    private let lock = RawLock()
    private var log: [String] = []
    private var tasks: [Task<Void, Never>] = []

    var questions: [String] { lock.withLock { log } }

    init(_ rt: Runtime, host: String = "127.0.0.1", port wanted: Int = 0,
         answer: @escaping @Sendable (String, UInt16) -> Reply) throws {
        let pair = try bindPair(host: host, port: wanted)
        port = pair.listener.localPort
        let listener = pair.listener
        let udp = pair.udp
        let udpTask = rt.spawn(with: udp) { [self] udp in
            var buf = IOBuffer(capacity: 1500)
            while true {
                buf.clear()
                guard let (_, from) = try? await udp.receiveFrom(into: &buf) else { return }
                let query = buf.withUnsafeBytes { Array($0) }
                for datagram in self.respond(to: query, overTCP: false, answer) {
                    _ = try? await udp.send(buffer(datagram), to: from)
                }
            }
        }
        let tcpTask = rt.spawn(with: listener) { [self] listener in
            while let stream = try? await listener.accept() {
                var buf = IOBuffer(capacity: 1500)
                while buf.count < 2 || buf.count < 2 + buf.withUnsafeBytes({ Int($0[0]) << 8 | Int($0[1]) }) {
                    guard let n = try? await stream.read(into: &buf), n > 0 else { break }
                }
                guard buf.count > 2 else { continue }
                let query = buf.withUnsafeBytes { Array($0[2...]) }
                for message in self.respond(to: query, overTCP: true, answer) {
                    var framed = [UInt8(message.count >> 8), UInt8(message.count & 0xff)]
                    framed += message
                    try? await stream.write(buffer(framed))
                }
            }
        }
        tasks = [udpTask, tcpTask]
    }

    func stop() {
        for t in tasks { t.cancel() }
    }

    private func respond(to query: [UInt8], overTCP: Bool,
                         _ answer: (String, UInt16) -> Reply) -> [[UInt8]] {
        guard let q = try? query.withUnsafeBytes({ try DNSMessage.parse($0) }) else { return [] }
        lock.withLock { log.append("\(overTCP ? "tcp" : "udp") \(q.questionType == 28 ? "AAAA" : "A") \(q.questionName)") }
        let id = UInt16(query[0]) << 8 | UInt16(query[1])
        let question = Array(query[12...])
        func message(id: UInt16, flags: UInt16, _ ips: [[UInt8]], ttl: UInt32 = 300) -> [UInt8] {
            let mine = ips.filter { $0.count == (q.questionType == 28 ? 16 : 4) }
            var w = Wire()
            w.header(id: id, flags: flags, answers: UInt16(mine.count))
            w.bytes += question
            for ip in mine {
                w.pointer(to: 12)
                w.u16(q.questionType); w.u16(1); w.u32(ttl); w.u16(UInt16(ip.count))
                w.bytes += ip
            }
            return w.bytes
        }
        switch answer(q.questionName, q.questionType) {
        case .addresses(let ips, let ttl): return [message(id: id, flags: 0x8180, ips, ttl: ttl)]
        case .noSuchName: return [message(id: id, flags: 0x8183, [])]
        case .empty: return [message(id: id, flags: 0x8180, [])]
        case .truncated(let ips):
            return overTCP ? [message(id: id, flags: 0x8180, ips)] : [message(id: id, flags: 0x8380, [])]
        case .silent: return []
        case .spoofThen(let ips):
            return [message(id: id &+ 1, flags: 0x8180, [[6, 6, 6, 6]]), message(id: id, flags: 0x8180, ips)]
        }
    }
}

private func buffer(_ bytes: [UInt8]) -> IOBuffer {
    var b = IOBuffer(capacity: max(bytes.count, 1))
    _ = bytes.withUnsafeBytes { b.append($0) }
    return b
}

private func config(_ servers: FakeNameserver..., timeout: Duration = .seconds(2)) -> ResolverConfig {
    var c = ResolverConfig(nameservers: servers.map { _ in "127.0.0.1" })
    c.port = servers[0].port
    c.timeout = timeout
    c.attempts = 1
    return c
}

private let v4: [UInt8] = [10, 1, 2, 3]
private let v6: [UInt8] = [0x20, 0x01, 0x0d, 0xb8] + Array(repeating: 0, count: 11) + [7]

@Suite struct ResolverTests {
    /// Run `body` with a resolver for a fake nameserver answering `answer`.
    private func withFake<T: Sendable>(
        timeout: Duration = .seconds(2),
        _ answer: @escaping @Sendable (String, UInt16) -> Reply,
        _ body: @escaping @Sendable (Resolver, FakeNameserver) async throws -> T
    ) throws -> T {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        return try rt.block { () async throws -> T in
            let server = try FakeNameserver(rt, answer: answer)
            defer { server.stop() }
            let resolver = Resolver(config: config(server, timeout: timeout), hostsPath: nil)
            return try await body(resolver, server)
        }
    }

    @Test func bothFamiliesIPv6First() throws {
        let (all, only4, only6) = try withFake({ _, _ in .addresses([v4, v6]) }) { r, _ in
            (try await r.lookup(host: "svc.test", port: 443),
             try await r.lookupIPv4(host: "svc.test", port: 80),
             try await r.lookupIPv6(host: "svc.test", port: 80))
        }
        #expect(all.map(\.description) == ["[2001:db8::7]:443", "10.1.2.3:443"])
        #expect(only4.map(\.description) == ["10.1.2.3:80"])
        #expect(only6.map(\.description) == ["[2001:db8::7]:80"])
    }

    @Test func oneFamilyIsEnough() throws {
        let all = try withFake({ _, type in type == 1 ? .addresses([v4]) : .empty }) { r, _ in
            try await r.lookup(host: "svc.test", port: 1)
        }
        #expect(all.map(\.description) == ["10.1.2.3:1"])
    }

    @Test func answersAreCached() throws {
        let questions = try withFake({ _, _ in .addresses([v4]) }) { r, server in
            for _ in 0..<3 { _ = try await r.lookupIPv4(host: "svc.test", port: 1) }
            _ = try await r.lookupIPv4(host: "SVC.test", port: 1)   // case doesn't matter
            r.clearCache()
            _ = try await r.lookupIPv4(host: "svc.test", port: 1)
            return server.questions
        }
        #expect(questions == ["udp A svc.test", "udp A svc.test"])
    }

    @Test func noSuchNameIsReportedAndRemembered() throws {
        let (first, second, questions) = try withFake({ _, _ in .noSuchName }) { r, server in
            var errors: [ResolveError] = []
            for _ in 0..<2 {
                do throws(ResolveError) {
                    _ = try await r.lookup(host: "nope.test", port: 1)
                } catch {
                    errors.append(error)
                }
            }
            return (errors.first, errors.last, server.questions.count)
        }
        #expect(first == .noSuchName)
        #expect(second == .noSuchName)
        #expect(questions == 2)    // A and AAAA once each
    }

    @Test func aNameWithNoRecordsHasNoAddress() throws {
        let error = try withFake({ _, _ in .empty }) { r, _ -> ResolveError? in
            do throws(ResolveError) {
                _ = try await r.lookup(host: "bare.test", port: 1)
                return nil
            } catch {
                return error
            }
        }
        #expect(error == .noAddress)
    }

    /// A bare name goes through the search list first.
    @Test func theSearchListIsWalked() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (found, questions) = try rt.block { () async throws -> ([SocketAddress], [String]) in
            let server = try FakeNameserver(rt) { name, _ in
                name == "db.two.internal" ? .addresses([v4]) : .noSuchName
            }
            defer { server.stop() }
            var c = config(server)
            c.search = ["one.internal", "two.internal"]
            let r = Resolver(config: c, hostsPath: nil)
            return (try await r.lookupIPv4(host: "db", port: 5432), server.questions)
        }
        #expect(found.map(\.description) == ["10.1.2.3:5432"])
        #expect(questions == ["udp A db.one.internal", "udp A db.two.internal"])
    }

    @Test func aTruncatedAnswerIsAskedAgainOverTCP() throws {
        let (found, questions) = try withFake({ _, _ in .truncated([v4, [10, 9, 9, 9]]) }) { r, server in
            (try await r.lookupIPv4(host: "big.test", port: 1), server.questions)
        }
        #expect(found.map(\.host) == ["10.1.2.3", "10.9.9.9"])
        #expect(questions == ["udp A big.test", "tcp A big.test"])
    }

    /// A reply with the wrong id is ignored, not believed or fatal.
    @Test func aSpoofedReplyIsIgnored() throws {
        let found = try withFake({ _, _ in .spoofThen([v4]) }) { r, _ in
            try await r.lookupIPv4(host: "svc.test", port: 1)
        }
        #expect(found.map(\.host) == ["10.1.2.3"])
    }

    /// A silent server times out and the next one is asked.
    @Test func aSilentServerIsSkipped() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let found = try rt.block { () async throws -> [SocketAddress] in
            let silent = try FakeNameserver(rt) { _, _ in .silent }
            let good = try FakeNameserver(rt) { _, _ in .addresses([v4]) }
            defer { silent.stop(); good.stop() }
            // Different ports, so two resolvers: the silent one gives up...
            let r1 = Resolver(config: config(silent, timeout: .milliseconds(100)), hostsPath: nil)
            do throws(ResolveError) {
                _ = try await r1.lookupIPv4(host: "svc.test", port: 1)
                Issue.record("a silent server answered")
            } catch {
                #expect(error == .unanswered)
            }
            // ...and a server list whose first entry is dead moves on.
            var c = config(good, timeout: .milliseconds(100))
            c.nameservers = ["127.0.0.2", "127.0.0.1"]
            return try await Resolver(config: c, hostsPath: nil).lookupIPv4(host: "svc.test", port: 1)
        }
        #expect(found.map(\.host) == ["10.1.2.3"])
    }

    /// After a dead server's timeout, lookups start with the one that answered.
    @Test func theServerThatAnsweredIsTriedFirst() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (first, second) = try rt.block { () async throws -> (Duration, Duration) in
            // Two loopback addresses with one port: a server that never
            // answers (a refused port would fail at once), then a good one.
            // The port is free on ::1 but may be taken on 127.0.0.1 by
            // another test, so try a few.
            var pair: (FakeNameserver, FakeNameserver)?
            for _ in 0..<10 where pair == nil {
                let good = try FakeNameserver(rt, host: "::1") { _, _ in .addresses([v4]) }
                if let silent = try? FakeNameserver(rt, host: "127.0.0.1", port: good.port, answer: { _, _ in .silent }) {
                    pair = (good, silent)
                } else {
                    good.stop()
                }
            }
            let (good, silent) = try #require(pair)
            defer { good.stop(); silent.stop() }
            var c = config(good, timeout: .milliseconds(300))
            c.nameservers = ["127.0.0.1", "::1"]
            let r = Resolver(config: c, hostsPath: nil)
            var start = ContinuousClock.now
            _ = try await r.lookupIPv4(host: "one.test", port: 1)
            let first = ContinuousClock.now - start
            start = ContinuousClock.now
            _ = try await r.lookupIPv4(host: "two.test", port: 1) // not cached
            let second = ContinuousClock.now - start
            #expect(silent.questions.count == 1)
            return (first, second)
        }
        #expect(first >= .milliseconds(250))
        #expect(second < .milliseconds(150))
    }

    @Test func cancellingALookupEndsIt() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (error, elapsed) = try rt.block { () async throws -> (ResolveError?, Duration) in
            let silent = try FakeNameserver(rt) { _, _ in .silent }
            defer { silent.stop() }
            let r = Resolver(config: config(silent, timeout: .seconds(10)), hostsPath: nil)
            let start = ContinuousClock.now
            let lookup = rt.spawn { () async -> ResolveError? in
                do throws(ResolveError) {
                    _ = try await r.lookup(host: "svc.test", port: 1)
                    return nil
                } catch {
                    return error
                }
            }
            try await Runtime.sleep(for: .milliseconds(50))
            lookup.cancel()
            return (await lookup.value, ContinuousClock.now - start)
        }
        #expect(error == .cancelled)
        #expect(elapsed < .seconds(5))
    }

    @Test func addressesAndHostsNeedNoServer() throws {
        let path = tempPath("hosts")
        #expect(writeText("10.0.0.5 db.internal\n::1 db.internal\n", to: path))
        defer { unlink(path) }
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let (literal, v6literal, hosts, v4only) = try rt.block {
            () async throws -> ([SocketAddress], [SocketAddress], [SocketAddress], [SocketAddress]) in
            // Nameserver port 9 (discard): any query would go unanswered.
            var c = ResolverConfig(nameservers: ["127.0.0.1"])
            c.port = 9
            c.timeout = .milliseconds(50)
            let r = Resolver(config: c, hostsPath: path)
            return (try await r.lookup(host: "192.0.2.1", port: 80),
                    try await r.lookup(host: "::1", port: 80),
                    try await r.lookup(host: "DB.internal", port: 5432),
                    try await r.lookupIPv4(host: "db.internal", port: 5432))
        }
        #expect(literal.map(\.description) == ["192.0.2.1:80"])
        #expect(v6literal.map(\.description) == ["[::1]:80"])
        #expect(hosts.map(\.description) == ["10.0.0.5:5432", "[::1]:5432"])
        #expect(v4only.map(\.description) == ["10.0.0.5:5432"])
    }

    @Test func aBadNameIsRefusedWithoutAsking() throws {
        let (error, questions) = try withFake({ _, _ in .addresses([v4]) }) { r, server -> (ResolveError?, Int) in
            do throws(ResolveError) {
                _ = try await r.lookupIPv4(host: "a..b", port: 1)
                return (nil, server.questions.count)
            } catch {
                return (error, server.questions.count)
            }
        }
        #expect(error == .badName)
        #expect(questions == 0)
    }

    /// TCPStream.connect with a resolver: the name resolves through the fake
    /// server to 127.0.0.1, where a listener waits.
    @Test func connectThroughTheResolver() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let peer = try rt.block { () async throws -> String in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            let accepted = rt.spawn(with: listener) { l -> Bool in (try? await l.accept()) != nil }
            let server = try FakeNameserver(rt) { _, type in type == 1 ? .addresses([[127, 0, 0, 1]]) : .empty }
            defer { server.stop() }
            let r = Resolver(config: config(server), hostsPath: nil)
            let stream = try await TCPStream.connect(host: "app.test", port: port, resolver: r)
            #expect(await accepted.value)
            return try stream.peerAddress.description
        }
        #expect(peer.hasPrefix("127.0.0.1:"))
    }

    /// The system's own nameservers, when the network is there to ask:
    /// VEGA_DNS_LIVE=1.
    @Test(.enabled(if: getenv("VEGA_DNS_LIVE") != nil))
    func theSystemResolverAnswers() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let found = try rt.block { () async throws -> [SocketAddress] in
            try await Resolver.system.lookup(host: "example.com", port: 443)
        }
        #expect(!found.isEmpty)
        #expect(found.allSatisfy { $0.port == 443 })
    }
}
#endif
