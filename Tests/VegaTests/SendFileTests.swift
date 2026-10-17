#if os(Linux) || canImport(Darwin) || os(Windows)
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif
import CVega
import Testing
@testable import Vega

@Suite struct SendFileTests {
    /// A temporary file of `bytes`, open for reading; removed on return.
    func withFile<R>(_ bytes: [UInt8], _ body: (Int32) throws -> R) throws -> R {
        #if os(Windows)
        // A Win32 handle, as VegaFS opens files there.
        let dir = getenv("TEMP").map { String(cString: $0) } ?? "."
        let path = "\(dir)\\vega-sendfile-\(UInt64.random(in: 0 ... .max)).bin"
        var fd: Int32 = -1
        try #require(cv_file_open(path, CV_FILE_READ | CV_FILE_WRITE | CV_FILE_CREATE | CV_FILE_TRUNC, 0o644, &fd) == 0)
        defer { _ = cv_file_close(fd); _ = _unlink(path) }
        let written = bytes.withUnsafeBytes { cv_file_write(fd, $0.baseAddress, $0.count, 0) }
        try #require(written == bytes.count)
        #else
        var template = Array("/tmp/vega-sendfile-XXXXXX".utf8CString)
        let fd = template.withUnsafeMutableBufferPointer { mkstemp($0.baseAddress!) }
        try #require(fd >= 0)
        let path = String(cString: template)
        defer { close(fd); unlink(path) }
        let written = bytes.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        try #require(written == bytes.count)
        #endif
        return try body(fd)
    }

    /// A runtime whose accepts and reads are overlapped requests too, on
    /// Windows (as VEGA_DRIVER=overlapped makes them).
    static func runtime(overlapped: Bool) -> Runtime {
        let rt = Runtime(workers: 2)
        #if os(Windows)
        if overlapped, let raw = rt.scheduler.driver?.raw {
            cv_driver_set_overlapped(raw, (1 << CV_OVL_TRANSMIT) | (1 << CV_OVL_ACCEPT) | (1 << CV_OVL_RECV))
        }
        #endif
        return rt
    }

    @Test(arguments: [false, true])
    func sendsAFileAndASliceOfIt(overlapped: Bool) throws {
        let content = (0..<(1 << 20)).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ $0 >> 9) }
        let rt = Self.runtime(overlapped: overlapped)
        defer { rt.shutdown() }
        #if os(Windows)
        let transmits = cv_ovl_count(CV_OVL_TRANSMIT), recvs = cv_ovl_count(CV_OVL_RECV)
        #endif
        let (sent, got, past, tail, atEnd) = try withFile(content) { fd in
            try rt.block { () async throws(IOError) -> (Int, [UInt8], Int, [UInt8], Int) in
                let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
                let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
                let conn = try await listener.accept()
                // The whole file, then 100 bytes from 1000, then a request
                // reaching past its end, then one starting at it.
                let sender = rt.spawn(with: conn) { conn async -> (Int, Int, Int) in
                    let a = (try? await conn.sendFile(fd, count: content.count)) ?? -1
                    _ = try? await conn.sendFile(fd, offset: 1000, count: 100)
                    let b = (try? await conn.sendFile(fd, offset: Int64(content.count - 10), count: 50)) ?? -1
                    let c = (try? await conn.sendFile(fd, offset: Int64(content.count), count: 50)) ?? -1
                    return (a, b, c)
                }
                let total = content.count + 100 + 10
                var buf = IOBuffer(capacity: total)
                try await readExactly(client, total, into: &buf)
                let all = buf.withUnsafeBytes { Array($0) }
                let (a, b, c) = await sender.value
                return (a, Array(all[0..<content.count + 100]), b, Array(all[(content.count + 100)...]), c)
            }
        }
        #expect(sent == content.count)
        #expect(got == content + Array(content[1000..<1100]))
        #expect(past == 10)
        #expect(tail == Array(content[(content.count - 10)...]))
        #expect(atEnd == 0)
        #if os(Windows)
        // By TransmitFile, not read and written here.
        #expect(cv_ovl_count(CV_OVL_TRANSMIT) >= transmits + 3)
        if overlapped { #expect(cv_ovl_count(CV_OVL_RECV) > recvs) }
        #endif
    }

    /// A send to a peer that reads nothing gives up at the I/O deadline,
    /// and the stream can still send (not on Windows: cancelling
    /// TransmitFile aborts the connection).
    @Test func aStalledSendTimesOut() throws {
        let content = [UInt8](repeating: 7, count: 64 << 20)
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (error, after) = try withFile(content) { fd in
            rt.block { () async -> (IOError?, Int) in
                do throws(IOError) {
                    let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
                    let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
                    let conn = try await listener.accept()
                    var failure: IOError?
                    do throws(IOError) {
                        _ = try await Runtime.withIODeadline(.milliseconds(200)) { () async throws(IOError) -> Int in
                            try await conn.sendFile(fd, count: content.count)
                        }
                    } catch {
                        failure = error
                    }
                    // Drain what went, then a small send still arrives.
                    let reader = rt.spawn(with: client) { client async -> Int in
                        var total = 0
                        var buf = IOBuffer(capacity: 1 << 20)
                        while let n = try? await client.read(into: &buf), n > 0 {
                            total += n
                            buf.clear()
                        }
                        return total
                    }
                    let n = (try? await conn.sendFile(fd, count: 10)) ?? -1
                    try? conn.shutdownWrite()
                    _ = await reader.value
                    return (failure, n)
                } catch {
                    return (error, -1)
                }
            }
        }
        #expect(error == .timedOut)
        #if os(Windows)
        #expect(after == -1)
        #else
        #expect(after == 10)
        #endif
    }
}
#endif
