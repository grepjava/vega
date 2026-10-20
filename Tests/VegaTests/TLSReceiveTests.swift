#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import Testing
import Vega
import VegaIO
import VegaTLS

private let identity = try! TLSIdentity.selfSigned(names: ["vega.test", "127.0.0.1"])

/// `receive()` over TLS: it waits for ciphertext holding no buffer, then
/// decrypts into a receive block. Each test runs on every way the platform
/// has of receiving.
@Suite struct TLSReceiveTests {
    /// Messages with pauses between them, so the server's engine drains and
    /// its next receive waits with nothing, then a large one across many
    /// records, then close_notify.
    static let sizes = (0..<20).map { 1000 + $0 * 500 } + [100_000]

    static var expected: [UInt8] { sizes.flatMap { ReceiveTests.pattern($0) } }

    /// Connect over `rt`'s loopback and send `sizes`; the server's end.
    static func serve(_ rt: Runtime) async throws -> TLSStream<TCPStream> {
        let server = try TLSContext(.server(identity: identity))
        let client = try TLSContext(.client(trustRoots: .certificates(identity.certificateChain)))
        let p = try await ReceiveTests.pair()
        rt.spawn(with: p.writer) { conn async in
            guard let tls = try? await TLSStream.connect(conn, serverName: "vega.test", context: client) else { return }
            for size in sizes {
                try? await tls.write(IOBuffer(copying: ReceiveTests.pattern(size)))
                try? await Runtime.sleep(for: .milliseconds(2))
            }
            guard let conn = try? await tls.close() else { return }
            // Read to the server's end before closing: closing with its
            // session tickets unread resets the connection on Windows,
            // which drops what the server had yet to read.
            var sink = IOBuffer(capacity: 4096)
            while let n = try? await conn.read(into: &sink), n > 0 { sink.clear() }
        }
        return try await TLSStream.accept(p.reader, context: server)
    }

    @Test func receivesEachMessageThenTheEnd() throws {
        for (name, rt) in ReceiveTests.runtimes() {
            defer { rt.shutdown() }
            let got = try rt.block { () async throws -> [UInt8] in
                let tls = try await Self.serve(rt)
                var out: [UInt8] = []
                while true {
                    let bytes = try await tls.receive()
                    if bytes.isEmpty { break }
                    bytes.withUnsafeBytes { out += $0 }
                }
                return out
            }
            #expect(got == Self.expected, "\(name)")
        }
    }

    @Test func theReadHalfReceivesToo() throws {
        for (name, rt) in ReceiveTests.runtimes() {
            defer { rt.shutdown() }
            let got = try rt.block { () async throws -> [UInt8] in
                let halves = try await Self.serve(rt).split()
                var out: [UInt8] = []
                while true {
                    let bytes = try await halves.reader.receive()
                    if bytes.isEmpty { break }
                    bytes.withUnsafeBytes { out += $0 }
                }
                return out
            }
            #expect(got == Self.expected, "\(name)")
        }
    }

    @Test func readsAndReceivesMixKeepTheOrder() throws {
        for (name, rt) in ReceiveTests.runtimes() {
            defer { rt.shutdown() }
            let got = try rt.block { () async throws -> [UInt8] in
                let tls = try await Self.serve(rt)
                var out: [UInt8] = []
                var buffer = IOBuffer(capacity: 3000)
                for turn in 0... {
                    if turn % 2 == 0 {
                        let bytes = try await tls.receive()
                        if bytes.isEmpty { break }
                        bytes.withUnsafeBytes { out += $0 }
                    } else {
                        buffer.clear()
                        if try await tls.read(into: &buffer) == 0 { break }
                        buffer.withUnsafeBytes { out += $0 }
                    }
                }
                return out
            }
            #expect(got == Self.expected, "\(name)")
        }
    }
}
#endif
