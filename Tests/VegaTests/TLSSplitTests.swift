#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import Testing
import Vega
import VegaIO
import VegaHTTP1
import VegaHTTP2
import VegaTest
import VegaTLS

private let identity = try! TLSIdentity.selfSigned(names: ["vega.test", "127.0.0.1"])

/// A read half and where to send what it reads, for one task.
private struct Pump<Reader: AsyncReader & ~Copyable & Sendable>: ~Copyable, Sendable {
    var reader: Reader
    var sender: MPSCChannel<[UInt8]>.Sender
}

private func pattern(_ i: Int) -> UInt8 { UInt8(truncatingIfNeeded: i &* 31 &+ i >> 9) }

@Suite struct TLSSplitTests {
    /// Each end reads in one task while another writes: megabytes go both
    /// ways at once through buffers far smaller than the data.
    @Test func readAndWriteAtOnce() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let server = try TLSContext(.server(identity: identity))
        let client = try TLSContext(.client(trustRoots: .certificates(identity.certificateChain)))
        let total = 4 << 20
        let received = try rt.block { () async throws -> [UInt8] in
            let pair = duplex(capacity: 16 * 1024)
            // The server echoes: a task reads into a channel, this one writes.
            rt.spawn(with: pair.second) { t async in
                guard let tls = try? await TLSStream.accept(t, context: server) else { return }
                let halves = tls.split { $0.split() }
                let channel = MPSCChannel<[UInt8]>(capacity: 4)
                rt.spawn(with: Pump(reader: halves.reader, sender: channel.sender)) { pump async in
                    var buf = IOBuffer(capacity: 32 * 1024)
                    while let n = try? await pump.reader.read(into: &buf), n > 0 {
                        let chunk = buf.withUnsafeBytes { Array($0) }
                        buf.clear()
                        guard (try? await pump.sender.send(chunk)) != nil else { return }
                    }
                }
                var rx = channel.receiver
                var out = IOBuffer(capacity: 32 * 1024)
                while let chunk = try? await rx.receive() {
                    out.clear()
                    chunk.withUnsafeBytes { out.append($0) }
                    guard (try? await halves.writer.write(out)) != nil else { return }
                }
                try? await halves.writer.close()
            }
            let tls = try await TLSStream.connect(pair.first, serverName: "vega.test", context: client)
            let halves = tls.split { $0.split() }
            rt.spawn(with: halves.writer) { writer async in
                var chunk = IOBuffer(capacity: 64 * 1024)
                var sent = 0
                while sent < total {
                    chunk.clear()
                    chunk.withUnsafeSpareCapacity { room in
                        for i in 0..<room.count { room[i] = pattern(sent + i) }
                        return room.count
                    }
                    try? await writer.write(chunk)
                    sent += chunk.count
                }
                try? await writer.close()
            }
            var got: [UInt8] = []
            var buf = IOBuffer(capacity: 32 * 1024)
            while try await halves.reader.read(into: &buf) > 0 {
                buf.withUnsafeBytes { got += $0 }
                buf.clear()
            }
            return got
        }
        #expect(received.count == total)
        #expect(received.indices.allSatisfy { received[$0] == pattern($0) })
    }

    /// HTTP/2 the usual way: TLS over TCP, "h2" agreed with ALPN.
    @Test func http2OverTLS() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let server = try TLSContext(.server(identity: identity, applicationProtocols: ["h2", "http/1.1"]))
        let client = try TLSContext(.client(trustRoots: .certificates(identity.certificateChain),
                                            applicationProtocols: ["h2"]))
        let (alpn, bodies) = try rt.block { () async throws -> (String?, [String]) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            rt.spawn(with: listener) { l async in
                while let conn = try? await l.accept() {
                    rt.spawn(with: conn) { conn async in
                        guard let tls = try? await TLSStream.accept(conn, context: server),
                              tls.applicationProtocol == "h2" else { return }
                        try? await HTTP2Server.serve(tls.split()) { request in
                            HTTPResponse(body: "\(request.head.fields["host"] ?? "-") \(request.head.target) \(request.body.count)")
                        }
                    }
                }
            }
            let tcp = try await TCPStream.connect(host: "127.0.0.1", port: port)
            let tls = try await TLSStream.connect(tcp, serverName: "vega.test", context: client)
            let alpn = tls.applicationProtocol
            let bodies = try await HTTP2Client.withConnection(tls.split(), authority: "vega.test") { h2 in
                try await withThrowingTaskGroup(of: (Int, String).self) { group in
                    for i in 0..<32 {
                        group.addTask {
                            let r = try await h2.send(HTTPRequest(method: .post, target: "/\(i)",
                                                                  body: Array(repeating: 7, count: i * 10_000)))
                            return (i, r.text)
                        }
                    }
                    var out = [String](repeating: "", count: 32)
                    for try await (i, text) in group { out[i] = text }
                    return out
                }
            }
            return (alpn, bodies)
        }
        #expect(alpn == "h2")
        #expect(bodies == (0..<32).map { "vega.test /\($0) \($0 * 10_000)" })
    }
}
#endif
