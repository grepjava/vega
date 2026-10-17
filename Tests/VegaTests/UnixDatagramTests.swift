#if os(Linux) || canImport(Darwin)
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif
import Testing
@testable import Vega

private func buffer(_ bytes: [UInt8]) -> IOBuffer {
    var b = IOBuffer(capacity: max(bytes.count, 1))
    _ = bytes.withUnsafeBytes { b.append($0) }
    return b
}

@Suite("UnixDatagram")
struct UnixDatagramTests {
    @Test func pairCarriesWholeDatagrams() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let got = try rt.block { () async throws(IOError) -> [Int] in
            let pair = try UnixDatagram.pair()
            for n in [1, 500, 0, 3000] {
                try await pair.first.send(buffer([UInt8](repeating: 7, count: n)))
            }
            var sizes: [Int] = []
            var into = IOBuffer(capacity: 4096)
            for _ in 0..<4 {
                into.clear()
                sizes.append(try await pair.second.receive(into: &into))
            }
            return sizes
        }
        #expect(got == [1, 500, 0, 3000])
    }

    /// A bound server answers each sender at the address it came from.
    @Test func boundServerRepliesToSenders() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let dir = "/tmp/vega-ud-\(getpid())-\(Int.random(in: 0..<1_000_000))"
        let serverPath = dir + "-server.sock", clientPath = dir + "-client.sock"
        defer {
            unlink(serverPath)
            unlink(clientPath)
        }
        let (reply, sender) = try rt.block { () async throws(IOError) -> (String, String) in
            let server = try UnixDatagram.bind(path: serverPath)
            rt.spawn(with: server) { server in
                var into = IOBuffer(capacity: 256)
                guard let (n, from) = try? await server.receiveFrom(into: &into) else { return }
                let text = into.withUnsafeBytes { String(decoding: $0[0..<n], as: UTF8.self) }
                let answer = buffer(Array("echo \(text) from \(from.host)".utf8))
                _ = try? await server.send(UnsafeRawBufferPointer(start: answer.base, count: answer.count), to: from)
            }
            let client = try UnixDatagram.bind(path: clientPath)
            try await client.send(buffer(Array("hello".utf8)), to: serverPath)
            var into = IOBuffer(capacity: 256)
            let (n, from) = try await client.receiveFrom(into: &into)
            return (into.withUnsafeBytes { String(decoding: $0[0..<n], as: UTF8.self) }, from.host)
        }
        #expect(reply == "echo hello from \(clientPath)")
        #expect(sender == serverPath)
    }
}
#endif
