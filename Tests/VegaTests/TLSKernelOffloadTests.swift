// Kernel TLS: Linux only. Each test runs against a peer whose TLS is in
// userspace, so a wrong key, IV or sequence number fails the exchange. On a
// kernel without the tls module the streams stay in userspace: the
// exchanges still run, and only the checks that the kernel took over are
// left out.
#if os(Linux) && (OpenSSL || BoringSSL)
import Glibc
import Testing
import Vega
import VegaIO
import VegaTest
import VegaTLS

private let identity = try! TLSIdentity.selfSigned(names: ["vega.test", "127.0.0.1"])

/// Whether the kernel has TLS loaded: it lists the TCP upper-layer protocols
/// it can attach. Unprivileged processes can't have the module loaded.
private let kernelTLS: Bool = {
    guard let f = fopen("/proc/sys/net/ipv4/tcp_available_ulp", "r") else { return false }
    defer { fclose(f) }
    var line = [CChar](repeating: 0, count: 256)
    guard fgets(&line, Int32(line.count), f) != nil else { return false }
    let text = String(decoding: line.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)), as: UTF8.self)
    return text.split(whereSeparator: { $0 == " " || $0 == "\n" }).contains("tls")
}()

/// Whether the kernel can take new TLS 1.3 keys on a connection (KeyUpdate):
/// Linux 6.14 on.
private let kernelRekeys: Bool = {
    var u = utsname()
    guard uname(&u) == 0 else { return false }
    let release = withUnsafeBytes(of: u.release) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
    let parts = release.split(separator: ".").prefix(2).map { Int($0.prefix { $0.isNumber }) ?? 0 }
    return parts.count == 2 && (parts[0], parts[1]) >= (6, 14)
}()

/// Whether the kernel has ChaCha20-Poly1305 for TLS: loaded, or a module to
/// load (WSL's kernel, for one, has neither).
private let kernelChaCha: Bool = {
    if let f = fopen("/proc/crypto", "r") {
        defer { fclose(f) }
        var line = [CChar](repeating: 0, count: 512)
        while fgets(&line, Int32(line.count), f) != nil {
            if String(cString: line).contains("chacha20") { return true }
        }
    }
    var u = utsname()
    guard uname(&u) == 0 else { return false }
    let release = withUnsafeBytes(of: u.release) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
    return ["", ".zst", ".xz", ".gz"].contains {
        access("/lib/modules/\(release)/kernel/crypto/chacha20poly1305.ko\($0)", F_OK) == 0
    }
}()

/// A protocol version and cipher suite to run with.
struct Suite: Sendable, CustomStringConvertible {
    var description: String
    var maximum: TLSConfiguration.Version?
    var ciphers: String?

    /// Whether the kernel can take this suite: with no tls module, or
    /// without the cipher, the streams stay in userspace.
    var inKernel: Bool { kernelTLS && (ciphers?.contains("CHACHA20") != true || kernelChaCha) }

    static let all = [
        Suite(description: "TLS 1.3", maximum: nil, ciphers: nil),
        Suite(description: "TLS 1.2 AES-128-GCM", maximum: .v1_2, ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256"),
        Suite(description: "TLS 1.2 AES-256-GCM", maximum: .v1_2, ciphers: "ECDHE-ECDSA-AES256-GCM-SHA384"),
        Suite(description: "TLS 1.2 ChaCha20-Poly1305", maximum: .v1_2, ciphers: "ECDHE-ECDSA-CHACHA20-POLY1305"),
    ]
}

private func contexts(server serverOffload: TLSConfiguration.KernelOffload,
                      client clientOffload: TLSConfiguration.KernelOffload,
                      suite: Suite = Suite.all[0]) throws -> (server: TLSContext, client: TLSContext) {
    var s = TLSConfiguration.server(identity: identity)
    s.kernelOffload = serverOffload
    s.maximumVersion = suite.maximum
    s.cipherList = suite.ciphers
    var c = TLSConfiguration.client(trustRoots: .certificates(identity.certificateChain))
    c.kernelOffload = clientOffload
    c.maximumVersion = suite.maximum
    return (try TLSContext(s), try TLSContext(c))
}

private func pattern(_ i: Int) -> UInt8 { UInt8(truncatingIfNeeded: i &* 31 &+ i >> 9) }

private func filled(_ count: Int, from start: Int = 0) -> IOBuffer {
    var b = IOBuffer(capacity: max(count, 1))
    b.withUnsafeSpareCapacity { room in
        for i in 0..<count { room[i] = pattern(start + i) }
        return count
    }
    return b
}

/// What the kernel had of each end, and what went wrong.
private struct Outcome: Sendable {
    var client: TLSConfiguration.KernelOffload = .off
    var server: TLSConfiguration.KernelOffload = .off
    var serverError: IOError?
    var resumed = false
}

/// Over loopback TCP: the client sends a message of each size, the server
/// echoes it back, then the client closes and the server reads the end.
/// Each echo is checked byte for byte.
private func echo(server: TLSContext, client: TLSContext, sizes: [Int]) throws -> Outcome {
    let rt = Runtime(workers: 2)
    defer { rt.shutdown() }
    return try rt.block { () async throws -> Outcome in
        let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
        let port = listener.localPort
        let serverTask = rt.spawn(with: listener) { l async -> (TLSConfiguration.KernelOffload, IOError?) in
            do throws(IOError) {
                let tls = try await TLSStream.accept(try await l.accept(), context: server)
                var buf = IOBuffer(capacity: 64 * 1024)
                while true {
                    buf.clear()
                    if try await tls.read(into: &buf) == 0 { break } // close_notify
                    try await tls.write(buf)
                }
                let state = tls.kernelOffload
                _ = try await tls.close()
                return (state, nil)
            } catch {
                return (.off, error)
            }
        }
        let tcp = try await TCPStream.connect(host: "127.0.0.1", port: port)
        let tls = try await TLSStream.connect(tcp, serverName: "vega.test", context: client)
        var outcome = Outcome()
        var start = 0
        var buf = IOBuffer(capacity: 64 * 1024)
        for size in sizes {
            try await tls.write(filled(size, from: start))
            var got = 0
            while got < size {
                buf.clear()
                let n = try await tls.read(into: &buf)
                try #require(n > 0)
                buf.withUnsafeBytes { bytes in
                    for i in 0..<n where bytes[i] != pattern(start + got + i) {
                        Issue.record("byte \(start + got + i) differs")
                        break
                    }
                }
                got += n
            }
            start += size
        }
        outcome.client = tls.kernelOffload
        outcome.resumed = tls.isResumed
        _ = try await tls.close()
        (outcome.server, outcome.serverError) = await serverTask.value
        return outcome
    }
}

/// The server sends `total` bytes and closes; the client reads to the end.
/// Returns what the client read, and what the kernel had of each end.
private func download(server: TLSContext, client: TLSContext, total: Int,
                      send: @escaping @Sendable (borrowing TLSStream<TCPStream>, Int) async throws(IOError) -> Void)
    throws -> (bytes: Int, mismatches: Int, Outcome) {
    let rt = Runtime(workers: 2)
    defer { rt.shutdown() }
    return try rt.block { () async throws -> (Int, Int, Outcome) in
        let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
        let port = listener.localPort
        let serverTask = rt.spawn(with: listener) { l async -> (TLSConfiguration.KernelOffload, IOError?) in
            do throws(IOError) {
                let tls = try await TLSStream.accept(try await l.accept(), context: server)
                try await send(tls, total)
                let state = tls.kernelOffload
                _ = try await tls.close()
                return (state, nil)
            } catch {
                return (.off, error)
            }
        }
        let tcp = try await TCPStream.connect(host: "127.0.0.1", port: port)
        let tls = try await TLSStream.connect(tcp, serverName: "vega.test", context: client)
        var buf = IOBuffer(capacity: 256 * 1024)
        var got = 0, mismatches = 0
        while true {
            buf.clear()
            let n = try await tls.read(into: &buf)
            if n == 0 { break }
            buf.withUnsafeBytes { bytes in
                for i in 0..<n where bytes[i] != pattern(got + i) { mismatches += 1 }
            }
            got += n
        }
        var outcome = Outcome()
        outcome.client = tls.kernelOffload
        (outcome.server, outcome.serverError) = await serverTask.value
        return (got, mismatches, outcome)
    }
}

/// A temporary file of `count` pattern bytes, open for reading; removed on
/// return.
private func withFile<R>(_ count: Int, _ body: (Int32) throws -> R) throws -> R {
    var template = Array("/tmp/vega-ktls-XXXXXX".utf8CString)
    let fd = template.withUnsafeMutableBufferPointer { mkstemp($0.baseAddress!) }
    try #require(fd >= 0)
    let path = String(cString: template)
    defer { close(fd); unlink(path) }
    let bytes = (0..<count).map(pattern)
    let written = bytes.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
    try #require(written == count)
    return try body(fd)
}

/// A read half and where to send what it reads, for one task.
private struct Pump<Reader: AsyncReader & ~Copyable & Sendable>: ~Copyable, Sendable {
    var reader: Reader
    var sender: MPSCChannel<[UInt8]>.Sender
}

private let sizes = [1, 100, 5000, 16 * 1024, 16 * 1024 + 1, 40_000, 64 * 1024, 200_000]

@Suite struct TLSKernelOffloadTests {
    /// An offloaded server against a userspace client: the kernel takes
    /// both directions, and what each end writes reaches the other.
    @Test(arguments: Suite.all)
    func offloadedServer(suite: Suite) throws {
        let (server, client) = try contexts(server: .transmitAndReceive, client: .off, suite: suite)
        let outcome = try echo(server: server, client: client, sizes: sizes)
        #expect(outcome.serverError == nil, "\(String(describing: outcome.serverError))")
        #expect(outcome.client == .off)
        if suite.inKernel { #expect(outcome.server == .transmitAndReceive) }
    }

    /// The other way round: an offloaded client against a userspace server.
    @Test(arguments: Suite.all)
    func offloadedClient(suite: Suite) throws {
        let (server, client) = try contexts(server: .off, client: .transmitAndReceive, suite: suite)
        let outcome = try echo(server: server, client: client, sizes: sizes)
        #expect(outcome.serverError == nil, "\(String(describing: outcome.serverError))")
        #expect(outcome.server == .off)
        if suite.inKernel { #expect(outcome.client == .transmitAndReceive) }
    }

    /// Both ends in the kernel, and transmit only: the kernel encrypts, the
    /// library still decrypts.
    @Test(arguments: Suite.all)
    func bothEndsAndTransmitOnly(suite: Suite) throws {
        let (server, client) = try contexts(server: .transmitAndReceive, client: .transmitAndReceive, suite: suite)
        let both = try echo(server: server, client: client, sizes: sizes)
        #expect(both.serverError == nil, "\(String(describing: both.serverError))")
        if suite.inKernel {
            #expect(both.server == .transmitAndReceive)
            #expect(both.client == .transmitAndReceive)
        }
        let (txServer, txClient) = try contexts(server: .transmit, client: .transmit, suite: suite)
        let tx = try echo(server: txServer, client: txClient, sizes: sizes)
        #expect(tx.serverError == nil, "\(String(describing: tx.serverError))")
        if suite.inKernel {
            #expect(tx.server == .transmit)
            #expect(tx.client == .transmit)
        }
    }

    /// Tens of megabytes down from an offloaded server, and from a
    /// userspace one to an offloaded client; the close at the end is
    /// close_notify, not a truncation.
    @Test(arguments: [(TLSConfiguration.KernelOffload.transmitAndReceive, TLSConfiguration.KernelOffload.off),
                      (.off, .transmitAndReceive)])
    func largeTransfer(server serverOffload: TLSConfiguration.KernelOffload,
                       client clientOffload: TLSConfiguration.KernelOffload) throws {
        let (server, client) = try contexts(server: serverOffload, client: clientOffload)
        let total = 24 << 20
        let (got, mismatches, outcome) = try download(server: server, client: client, total: total) { tls, total async throws(IOError) in
            var sent = 0
            while sent < total {
                let n = min(1 << 20, total - sent)
                try await tls.write(filled(n, from: sent))
                sent += n
            }
        }
        #expect(outcome.serverError == nil, "\(String(describing: outcome.serverError))")
        #expect(got == total)
        #expect(mismatches == 0)
        if kernelTLS {
            #expect(outcome.server == serverOffload)
            #expect(outcome.client == clientOffload)
        }
    }

    /// Megabytes both ways at once through split streams, an offloaded end
    /// against a userspace one.
    @Test func splitBothWaysAtOnce() throws {
        let (server, client) = try contexts(server: .transmitAndReceive, client: .off)
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let total = 16 << 20
        let (received, offload) = try rt.block { () async throws -> (Int, TLSConfiguration.KernelOffload) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            // The server echoes: one task reads and hands chunks over, another writes.
            let serverTask = rt.spawn(with: listener) { l async -> TLSConfiguration.KernelOffload in
                guard let conn = try? await l.accept(),
                      let tls = try? await TLSStream.accept(conn, context: server) else { return .off }
                let halves = tls.split()
                let channel = MPSCChannel<[UInt8]>(capacity: 4)
                rt.spawn(with: Pump(reader: halves.reader, sender: channel.sender)) { pump async in
                    var buf = IOBuffer(capacity: 64 * 1024)
                    while let n = try? await pump.reader.read(into: &buf), n > 0 {
                        let chunk = buf.withUnsafeBytes { Array($0) }
                        buf.clear()
                        guard (try? await pump.sender.send(chunk)) != nil else { return }
                    }
                }
                var rx = channel.receiver
                var out = IOBuffer(capacity: 64 * 1024)
                while let chunk = try? await rx.receive() {
                    out.clear()
                    chunk.withUnsafeBytes { _ = out.append($0) }
                    guard (try? await halves.writer.write(out)) != nil else { break }
                }
                let offloaded = halves.writer.isKernelOffloaded
                try? await halves.writer.close()
                return offloaded ? .transmit : .off
            }
            let tcp = try await TCPStream.connect(host: "127.0.0.1", port: port)
            let tls = try await TLSStream.connect(tcp, serverName: "vega.test", context: client)
            let halves = tls.split()
            rt.spawn(with: halves.writer) { writer async in
                var sent = 0
                while sent < total {
                    let n = min(100_000, total - sent)
                    guard (try? await writer.write(filled(n, from: sent))) != nil else { return }
                    sent += n
                }
                try? await writer.close()
            }
            var got = 0
            var buf = IOBuffer(capacity: 64 * 1024)
            while true {
                buf.clear()
                let n = try await halves.reader.read(into: &buf)
                if n == 0 { break }
                buf.withUnsafeBytes { bytes in
                    for i in 0..<n where bytes[i] != pattern(got + i) {
                        Issue.record("byte \(got + i) differs")
                        break
                    }
                }
                got += n
            }
            return (got, await serverTask.value)
        }
        #expect(received == total)
        if kernelTLS { #expect(offload == .transmit) }
    }

    /// sendFile on a stream the kernel encrypts: sendfile(2) from the file
    /// to the socket. A slice of the file, then the whole.
    @Test(arguments: [TLSConfiguration.KernelOffload.transmit, .off])
    func sendFile(offload: TLSConfiguration.KernelOffload) throws {
        let size = 6 << 20
        let (server, client) = try contexts(server: offload, client: .off)
        try withFile(size) { fd in
            let (got, mismatches, outcome) = try download(server: server, client: client, total: size) { tls, total async throws(IOError) in
                // The first 1000 bytes, then the rest: offsets are honoured.
                let first = try await tls.sendFile(fd, offset: 0, count: 1000)
                let rest = try await tls.sendFile(fd, offset: 1000, count: total) // past the end: what there is
                if first + rest != total { throw IOError(code: EIO) }
            }
            #expect(outcome.serverError == nil, "\(String(describing: outcome.serverError))")
            #expect(got == size)
            #expect(mismatches == 0)
            if kernelTLS { #expect(outcome.server == offload) }
        }
    }

    /// sendFile from the writing half of a split stream.
    @Test func sendFileFromAWriteHalf() throws {
        let size = 3 << 20
        let (server, client) = try contexts(server: .transmitAndReceive, client: .off)
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let got = try withFile(size) { fd in
            try rt.block { () async throws -> Int in
                let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
                let port = listener.localPort
                rt.spawn(with: listener) { l async in
                    guard let conn = try? await l.accept(),
                          let tls = try? await TLSStream.accept(conn, context: server) else { return }
                    let halves = tls.split()
                    _ = try? await halves.writer.sendFile(fd, offset: 0, count: size)
                    try? await halves.writer.close()
                }
                let tcp = try await TCPStream.connect(host: "127.0.0.1", port: port)
                let tls = try await TLSStream.connect(tcp, serverName: "vega.test", context: client)
                var buf = IOBuffer(capacity: 256 * 1024)
                var got = 0
                while true {
                    buf.clear()
                    let n = try await tls.read(into: &buf)
                    if n == 0 { break }
                    buf.withUnsafeBytes { bytes in
                        for i in 0..<n where bytes[i] != pattern(got + i) {
                            Issue.record("byte \(got + i) differs")
                            break
                        }
                    }
                    got += n
                }
                return got
            }
        }
        #expect(got == size)
    }

    /// TLS 1.3 KeyUpdate both ways: the userspace end asks the offloaded one
    /// to update, and the other way round, while they keep talking.
    @Test(.enabled(if: kernelRekeys || !kernelTLS))
    func keyUpdates() throws {
        let (server, client) = try contexts(server: .transmitAndReceive, client: .off)
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (rounds, offload, serverError) = try rt.block { () async throws -> (Int, TLSConfiguration.KernelOffload, IOError?) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            // The server echoes, and every third message updates its own
            // keys, asking the client for its update too.
            let serverTask = rt.spawn(with: listener) { l async -> (TLSConfiguration.KernelOffload, IOError?) in
                do throws(IOError) {
                    let tls = try await TLSStream.accept(try await l.accept(), context: server)
                    var buf = IOBuffer(capacity: 64 * 1024)
                    var messages = 0
                    while true {
                        buf.clear()
                        if try await tls.read(into: &buf) == 0 { break }
                        messages += 1
                        if messages % 3 == 0 { try await tls.updateKeys(requestPeerUpdate: true) }
                        try await tls.write(buf)
                    }
                    let state = tls.kernelOffload
                    _ = try await tls.close()
                    return (state, nil)
                } catch {
                    return (.off, error)
                }
            }
            let tcp = try await TCPStream.connect(host: "127.0.0.1", port: port)
            let tls = try await TLSStream.connect(tcp, serverName: "vega.test", context: client)
            var rounds = 0
            var buf = IOBuffer(capacity: 64 * 1024)
            for round in 0..<12 {
                // Every other round the client updates, asking the server's
                // kernel to update its keys as well.
                if round % 2 == 1 { try await tls.updateKeys(requestPeerUpdate: round % 4 == 1) }
                let size = 1000 + round * 3000
                try await tls.write(filled(size, from: round))
                var got = 0
                while got < size {
                    buf.clear()
                    let n = try await tls.read(into: &buf)
                    try #require(n > 0)
                    buf.withUnsafeBytes { bytes in
                        for i in 0..<n where bytes[i] != pattern(round + got + i) {
                            Issue.record("round \(round): byte \(got + i) differs")
                            break
                        }
                    }
                    got += n
                }
                rounds += 1
            }
            _ = try await tls.close()
            let (state, error) = await serverTask.value
            return (rounds, state, error)
        }
        #expect(serverError == nil, "\(String(describing: serverError))")
        #expect(rounds == 12)
        if kernelTLS { #expect(offload == .transmitAndReceive) }
    }

    /// A TLS 1.3 client with receive offload still keeps the server's
    /// session tickets: the library reads them before the kernel takes over.
    @Test func anOffloadedClientResumes() throws {
        let (server, client) = try contexts(server: .off, client: .transmitAndReceive)
        var resumed: [Bool] = []
        for _ in 0..<3 {
            let rt = Runtime(workers: 2)
            defer { rt.shutdown() }
            let (again, offload) = try rt.block { () async throws -> (Bool, TLSConfiguration.KernelOffload) in
                let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
                let port = listener.localPort
                rt.spawn(with: listener) { l async in
                    guard let conn = try? await l.accept(),
                          let tls = try? await TLSStream.accept(conn, context: server) else { return }
                    var buf = IOBuffer(capacity: 64)
                    _ = try? await tls.read(into: &buf)
                    try? await tls.write(buf)
                    _ = try? await tls.close()
                }
                let tcp = try await TCPStream.connect(host: "127.0.0.1", port: port)
                let tls = try await TLSStream.connect(tcp, serverName: "vega.test", context: client)
                try await tls.write(filled(10))
                var buf = IOBuffer(capacity: 64)
                while try await tls.read(into: &buf) > 0 {}
                return (tls.isResumed, tls.kernelOffload)
            }
            resumed.append(again)
            // Receive too, unless the server's close_notify came in the
            // same read as its tickets and the library read it.
            if kernelTLS { #expect(offload != .off) }
        }
        #expect(resumed == [false, true, true])
    }

    /// Mutual TLS: the client sends a certificate in its last flight, and
    /// both ends still hand their records over at the right place.
    @Test(arguments: [Suite.all[0], Suite.all[1]])
    func mutualTLS(suite: Suite) throws {
        let clientIdentity = try TLSIdentity.selfSigned(names: ["client.vega.test"])
        var s = TLSConfiguration.server(identity: identity)
        s.kernelOffload = .transmitAndReceive
        s.verification = .required
        s.trustRoots = .certificates(clientIdentity.certificateChain)
        s.maximumVersion = suite.maximum
        s.cipherList = suite.ciphers
        var c = TLSConfiguration.client(trustRoots: .certificates(identity.certificateChain), identity: clientIdentity)
        c.kernelOffload = .transmitAndReceive
        c.maximumVersion = suite.maximum
        let outcome = try echo(server: try TLSContext(s), client: try TLSContext(c), sizes: sizes)
        #expect(outcome.serverError == nil, "\(String(describing: outcome.serverError))")
        if suite.inKernel {
            #expect(outcome.server == .transmitAndReceive)
            #expect(outcome.client == .transmitAndReceive)
        }
    }

    /// Resumed sessions, whose handshakes run in another order (TLS 1.2's
    /// server finishes first), hand over as full ones do, and resume as
    /// they do in userspace.
    @Test(arguments: [Suite.all[0], Suite.all[1]])
    func resumedSessions(suite: Suite) throws {
        func run(_ offload: TLSConfiguration.KernelOffload) throws -> [Bool] {
            let (server, client) = try contexts(server: offload, client: offload, suite: suite)
            var resumed: [Bool] = []
            for _ in 0..<3 {
                let outcome = try echo(server: server, client: client, sizes: [10, 20_000])
                resumed.append(outcome.resumed)
                #expect(outcome.serverError == nil, "\(String(describing: outcome.serverError))")
                if suite.inKernel && offload != .off {
                    #expect(outcome.server == .transmitAndReceive)
                    #expect(outcome.client != .off)
                }
            }
            return resumed
        }
        let offloaded = try run(.transmitAndReceive)
        #expect(offloaded[1])
        #expect(offloaded == (try run(.off)))
    }

    /// Over anything but a TCP stream there's no kernel to hand records to:
    /// the stream stays in userspace and works as ever.
    @Test func otherTransportsStayInUserspace() throws {
        let (server, client) = try contexts(server: .transmitAndReceive, client: .transmitAndReceive)
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (text, offload) = try rt.block { () async throws -> (String, TLSConfiguration.KernelOffload) in
            let pair = duplex(capacity: 64 * 1024)
            rt.spawn(with: pair.second) { t async in
                guard let tls = try? await TLSStream.accept(t, context: server) else { return }
                var buf = IOBuffer(capacity: 1024)
                _ = try? await tls.read(into: &buf)
                try? await tls.write(buf)
                _ = try? await tls.close()
            }
            let tls = try await TLSStream.connect(pair.first, serverName: "vega.test", context: client)
            var hello = IOBuffer(capacity: 16)
            hello.append("hello")
            try await tls.write(hello)
            var buf = IOBuffer(capacity: 1024)
            while try await tls.read(into: &buf) > 0 {}
            return (buf.string, tls.kernelOffload)
        }
        #expect(text == "hello")
        #expect(offload == .off)
    }
}
#endif
