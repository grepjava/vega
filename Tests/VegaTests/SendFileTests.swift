#if os(Linux) || canImport(Darwin)
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import Testing
@testable import Vega

@Suite struct SendFileTests {
    /// A temporary file of `bytes`, open for reading; removed on return.
    func withFile<R>(_ bytes: [UInt8], _ body: (Int32) throws -> R) throws -> R {
        var template = Array("/tmp/vega-sendfile-XXXXXX".utf8CString)
        let fd = template.withUnsafeMutableBufferPointer { mkstemp($0.baseAddress!) }
        try #require(fd >= 0)
        let path = String(cString: template)
        defer { close(fd); unlink(path) }
        let written = bytes.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        try #require(written == bytes.count)
        return try body(fd)
    }

    @Test func sendsAFileAndASliceOfIt() throws {
        let content = (0..<(1 << 20)).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ $0 >> 9) }
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (sent, got, past, tail) = try withFile(content) { fd in
            try rt.block { () async throws(IOError) -> (Int, [UInt8], Int, [UInt8]) in
                let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
                let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
                let conn = try await listener.accept()
                // The whole file, then 100 bytes from 1000, then a request
                // reaching past its end.
                let sender = rt.spawn(with: conn) { conn async -> (Int, Int) in
                    let a = (try? await conn.sendFile(fd, count: content.count)) ?? -1
                    _ = try? await conn.sendFile(fd, offset: 1000, count: 100)
                    let b = (try? await conn.sendFile(fd, offset: Int64(content.count - 10), count: 50)) ?? -1
                    return (a, b)
                }
                let total = content.count + 100 + 10
                var buf = IOBuffer(capacity: total)
                try await readExactly(client, total, into: &buf)
                let all = buf.withUnsafeBytes { Array($0) }
                let (a, b) = await sender.value
                return (a, Array(all[0..<content.count + 100]), b, Array(all[(content.count + 100)...]))
            }
        }
        #expect(sent == content.count)
        #expect(got == content + Array(content[1000..<1100]))
        #expect(past == 10)
        #expect(tail == Array(content[(content.count - 10)...]))
    }
}
#endif
