#if os(Windows)
import ucrt
import CVega
import Testing
@testable import Vega
import VegaFS

/// Bytes in memory of their own, for writes from a task (a Swift array's
/// storage can't be borrowed across an await); freed by `free()`.
private struct Bytes: @unchecked Sendable {
    let raw: UnsafeMutableRawBufferPointer

    init(_ bytes: [UInt8]) {
        raw = .allocate(byteCount: bytes.count, alignment: 16)
        raw.copyMemory(from: UnsafeRawBufferPointer(start: bytes, count: bytes.count))
    }

    var all: UnsafeRawBufferPointer { UnsafeRawBufferPointer(raw) }

    func free() { raw.deallocate() }
}

/// The iocp backend: every socket operation that would wait is an
/// overlapped request on the runtime's completion port. Each test counts
/// the requests of its kind that finished on its runtime, so a path that
/// quietly fell back to a readiness wait shows; the rest of the suite runs
/// on this backend too (and on `.readiness` with VEGA_DRIVER=afd, as CI
/// does).
@Suite struct IOCPTests {
    /// Requests of `kind` finished on `rt`'s port.
    static func count(_ rt: Runtime, _ kind: Int32) -> UInt64 {
        cv_driver_ovl_count(rt.scheduler.driver!.raw, kind)
    }

    /// A pattern that shows a byte out of place.
    static func pattern(_ count: Int) -> [UInt8] {
        (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ $0 >> 11) }
    }

    @Test func iocpIsTheDefault() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let afd = getenv("VEGA_DRIVER").map { ["afd", "readiness"].contains(String(cString: $0)) } ?? false
        #expect(rt.ioBackend == (afd ? .readiness : .iocp))
        let readiness = Runtime(workers: 1, io: .readiness)
        defer { readiness.shutdown() }
        #expect(readiness.ioBackend == .readiness)
        let iocp = Runtime(workers: 1, io: .iocp)
        defer { iocp.shutdown() }
        #expect(iocp.ioBackend == .iocp)
    }

    /// Connecting is a ConnectEx; the connected socket then knows its peer.
    @Test func connectsWithConnectEx() throws {
        let rt = Runtime(workers: 2, io: .iocp)
        defer { rt.shutdown() }
        let (peer, port, echoed) = try rt.block { () async throws(IOError) -> (SocketAddress, Int, [UInt8]) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(to: try SocketAddress(host: "127.0.0.1", port: listener.localPort))
            let conn = try await listener.accept()
            let three = Bytes([1, 2, 3])
            defer { three.free() }
            try await client.write(three.all)
            var buf = IOBuffer(capacity: 3)
            try await readExactly(conn, 3, into: &buf)
            try client.shutdownWrite() // (needs the connect context)
            return (try client.peerAddress, listener.localPort, buf.withUnsafeBytes { Array($0) })
        }
        #expect(Self.count(rt, CV_OVL_CONNECT) == 1)
        #expect(peer.port == port)
        #expect(echoed == [1, 2, 3])
    }

    /// A refused connection fails with ECONNREFUSED, as connect(2) says it.
    @Test func aRefusedConnectEx() throws {
        let rt = Runtime(workers: 1, io: .iocp)
        defer { rt.shutdown() }
        let port = try rt.block { () throws(IOError) -> Int in
            // A port nobody listens on: bound once, then closed.
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            return listener.localPort
        }
        let error = rt.block { () async -> IOError? in
            do throws(IOError) {
                _ = try await TCPStream.connect(to: try SocketAddress(host: "127.0.0.1", port: port))
                return nil
            } catch {
                return error
            }
        }
        #expect(error == IOError(code: ECONNREFUSED))
    }

    /// Writes the socket has no room for go out as WSASend requests, every
    /// byte in order, while the peer reads late. (Winsock takes a single
    /// send of any size into an empty socket buffer: only the writes after
    /// it find the socket full.)
    @Test func aLargeWriteGoesOutAsWSASend() throws {
        let rt = Runtime(workers: 2, io: .iocp)
        defer { rt.shutdown() }
        let content = Self.pattern(16 << 20)
        let bytes = Bytes(content)
        defer { bytes.free() }
        let got = try rt.block { () async throws(IOError) -> [UInt8] in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let conn = try await listener.accept()
            let writer = rt.spawn(with: client) { client async -> Bool in
                do throws(IOError) {
                    for at in stride(from: 0, to: bytes.all.count, by: 1 << 20) {
                        try await client.write(UnsafeRawBufferPointer(rebasing: bytes.all[at..<at + (1 << 20)]))
                    }
                    return true
                } catch {
                    return false
                }
            }
            try? await Runtime.sleep(for: .milliseconds(50))
            var buf = IOBuffer(capacity: content.count)
            try await readExactly(conn, content.count, into: &buf)
            #expect(await writer.value)
            return buf.withUnsafeBytes { Array($0) }
        }
        #expect(got == content)
        #expect(Self.count(rt, CV_OVL_SEND) > 0)
    }

    /// A gathered write: the same, from many buffers, twice (the second
    /// finds the socket full).
    @Test func aLargeGatheredWrite() throws {
        let rt = Runtime(workers: 2, io: .iocp)
        defer { rt.shutdown() }
        let content = Self.pattern(8 << 20)
        let bytes = Bytes(content)
        defer { bytes.free() }
        // 100 parts of uneven sizes: more than one request's 64.
        var parts: [UnsafeRawBufferPointer] = []
        var at = 0
        for i in 0..<100 {
            let n = i == 99 ? content.count - at : content.count / 100 + (i % 7) * 13 - 39
            parts.append(UnsafeRawBufferPointer(rebasing: bytes.all[at..<at + n]))
            at += n
        }
        let list = UnsafeMutableBufferPointer<UnsafeRawBufferPointer>.allocate(capacity: parts.count)
        _ = list.initialize(from: parts)
        defer { list.deallocate() }
        nonisolated(unsafe) let vectored = UnsafeBufferPointer(list)
        let got = try rt.block { () async throws(IOError) -> [UInt8] in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let conn = try await listener.accept()
            let writer = rt.spawn(with: client) { client async -> Bool in
                let first = (try? await client.write(vectored: vectored)) != nil
                let second = (try? await client.write(vectored: vectored)) != nil
                return first && second
            }
            try? await Runtime.sleep(for: .milliseconds(50))
            var buf = IOBuffer(capacity: 2 * content.count)
            try await readExactly(conn, 2 * content.count, into: &buf)
            #expect(await writer.value)
            return buf.withUnsafeBytes { Array($0) }
        }
        #expect(got == content + content)
        #expect(Self.count(rt, CV_OVL_SEND) > 0)
    }

    /// Cancelling a write whose WSASend waits on a peer that reads nothing
    /// ends it with `.cancelled`; the connection is aborted after it.
    @Test func cancellingAWaitingWSASend() throws {
        let rt = Runtime(workers: 2, io: .iocp)
        defer { rt.shutdown() }
        let chunk = Bytes([UInt8](repeating: 9, count: 1 << 20))
        defer { chunk.free() }
        let (outcome, after) = try rt.block { () async throws(IOError) -> (String, String) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let conn = try await listener.accept()
            let writer = rt.spawn(with: client) { client async -> (String, String) in
                let outcome: String
                do throws(IOError) {
                    // Far more than the sockets hold.
                    for _ in 0..<1024 { try await client.write(chunk.all) }
                    outcome = "sent"
                } catch {
                    outcome = error == .cancelled ? "cancelled" : "\(error)"
                }
                do throws(IOError) {
                    try await client.write(UnsafeRawBufferPointer(rebasing: chunk.all[0..<1]))
                    return (outcome, "wrote")
                } catch {
                    return (outcome, "failed")
                }
            }
            try? await Runtime.sleep(for: .milliseconds(100))
            writer.cancel()
            let result = await writer.value
            _ = conn
            return result
        }
        #expect(outcome == "cancelled")
        #expect(after == "failed")
        #expect(Self.count(rt, CV_OVL_SEND) > 0)
    }

    /// A receive waiting for a datagram is a WSARecvFrom that brings the
    /// sender; one longer than the buffer is cut to it, as recvfrom does.
    /// Sends to a default peer and to an address both work.
    @Test func datagramsAsWSARecvFrom() throws {
        let rt = Runtime(workers: 2, io: .iocp)
        defer { rt.shutdown() }
        let small = Bytes([5, 6, 7]), long = Bytes([UInt8](repeating: 1, count: 1000)), one = Bytes([42])
        defer {
            small.free()
            long.free()
            one.free()
        }
        let (first, from, senderPort, cut, connected) = try rt.block {
            () async throws(IOError) -> ([UInt8], Int?, Int?, Int, [UInt8]) in
            let receiver = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let sender = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let to = try receiver.localAddress
            let senderPort = try sender.localAddress.port
            // Sent once the receives are waiting.
            let late = rt.spawn(with: sender) { sender async -> Bool in
                try? await Runtime.sleep(for: .milliseconds(50))
                let a = (try? await sender.send(small.all, to: to)) == 3
                try? await Runtime.sleep(for: .milliseconds(50))
                let b = (try? await sender.send(long.all, to: to)) == 1000
                return a && b
            }
            var buf = IOBuffer(capacity: 64)
            let (_, from) = try await receiver.receiveFrom(into: &buf)
            let first = buf.withUnsafeBytes { Array($0) }
            var hundred = IOBuffer(capacity: 100)
            let cut = try await receiver.receive(into: &hundred)
            #expect(await late.value)

            // A connected pair: send and receive to the default peer.
            let a = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let b = try UDPSocket.connect(to: try a.localAddress)
            try a.connect(to: try b.localAddress)
            let echo = rt.spawn(with: b) { b async -> Bool in
                try? await Runtime.sleep(for: .milliseconds(50))
                return (try? await b.send(one.all)) == 1
            }
            var got = IOBuffer(capacity: 8)
            _ = try await a.receive(into: &got)
            #expect(await echo.value)
            return (first, from.port, senderPort, cut, got.withUnsafeBytes { Array($0) })
        }
        #expect(first == [5, 6, 7])
        #expect(from == senderPort)
        #expect(cut == 100)
        #expect(connected == [42])
        #expect(Self.count(rt, CV_OVL_RECVFROM) >= 3)
    }

    /// Sends a 1000-byte datagram, then, once it's queued, receives it with
    /// a WSARecvFrom of 100 bytes made directly: [sent, received, the
    /// sender's port as the request saw it, the sender's port].
    fileprivate static func cutShortAtOnce(_ long: Bytes) async throws(IOError) -> [Int] {
        let receiver = try UDPSocket.bind(host: "127.0.0.1", port: 0)
        let sender = try UDPSocket.bind(host: "127.0.0.1", port: 0)
        let to: SocketAddress = try receiver.localAddress
        let sent: Int = try await sender.send(long.all, to: to)
        try? await Runtime.sleep(for: .milliseconds(20)) // queued
        let reg: IORegistration = receiver.reg
        let io: UnsafeMutablePointer<cv_io> = reg.io
        let buf = UnsafeMutableRawPointer.allocate(byteCount: 100, alignment: 16)
        defer { buf.deallocate() }
        let start: (UInt, UnsafeMutablePointer<Int64>) -> Int32 = { waiter, res in
            cv_ovl_recvfrom(io, waiter, buf, 100, res)
        }
        let n: Int64 = await reg.overlapped(CV_IO_READ, start)
        var from = cv_sockaddr()
        cv_ovl_sender(io, &from)
        let fromPort: Int = SocketAddress(raw: from).port ?? -1
        let senderPort: Int = try sender.localAddress.port ?? -2
        return [sent, Int(n), fromPort, senderPort]
    }

    /// A WSARecvFrom that finds a datagram longer than its buffer already
    /// queued fails at once with WSAEMSGSIZE, a warning underneath
    /// (STATUS_BUFFER_OVERFLOW) whose completion is still posted: the
    /// request waits for it (cv_ovl_recvfrom returns 1), and it brings the
    /// bytes that fit and the sender. Made directly, since a receive tries
    /// recvfrom first and meets this only in a race.
    @Test func aDatagramCutShortAtOnceStillCompletes() throws {
        let rt = Runtime(workers: 1, io: .iocp)
        defer { rt.shutdown() }
        let long = Bytes([UInt8](repeating: 3, count: 1000))
        defer { long.free() }
        let result: [Int] = try rt.block { () async throws(IOError) -> [Int] in try await Self.cutShortAtOnce(long) }
        #expect(result == [1000, 100, result[3], result[3]])
    }

    /// Unix streams: accepted through AcceptEx where the AF_UNIX provider
    /// takes it (by readiness where it doesn't), written with WSASend.
    @Test func unixStreams() throws {
        let rt = Runtime(workers: 2, io: .iocp)
        defer { rt.shutdown() }
        let dir = getenv("TEMP").map { String(cString: $0) } ?? "."
        let path = "\(dir)\\vega-iocp-\(UInt64.random(in: 0 ... .max)).sock"
        defer { _ = _unlink(path) }
        let content = Self.pattern(4 << 20)
        let bytes = Bytes(content)
        defer { bytes.free() }
        let got = try rt.block { () async throws(IOError) -> [UInt8] in
            let listener = try UnixListener.bind(path: path)
            // Connects once the accept is waiting, then writes it all.
            let client = rt.spawn { () async -> Bool in
                try? await Runtime.sleep(for: .milliseconds(50))
                guard let stream = try? await UnixStream.connect(path: path) else { return false }
                for at in stride(from: 0, to: bytes.all.count, by: 1 << 20) {
                    if (try? await stream.write(UnsafeRawBufferPointer(rebasing: bytes.all[at..<at + (1 << 20)]))) == nil {
                        return false
                    }
                }
                return true
            }
            let conn = try await listener.accept()
            var buf = IOBuffer(capacity: content.count)
            while buf.count < content.count {
                if try await conn.read(into: &buf) == 0 { break }
            }
            #expect(await client.value)
            return buf.withUnsafeBytes { Array($0) }
        }
        #expect(got == content)
        print("unix accepts by AcceptEx: \(Self.count(rt, CV_OVL_ACCEPT)), sends: \(Self.count(rt, CV_OVL_SEND))")
    }

    /// Writes `bytes` to `path` in 1 MiB pieces at the position, then 4
    /// bytes at offset 100 and 2 more at the position.
    fileprivate static func writeFile(_ path: String, _ bytes: Bytes) async throws(IOError) {
        let file = try await File.create(path)
        var at = 0
        while at < bytes.all.count {
            try await file.write(UnsafeRawBufferPointer(rebasing: bytes.all[at..<at + (1 << 20)]))
            at += 1 << 20
        }
        try await file.write(UnsafeRawBufferPointer(rebasing: bytes.all[0..<4]), at: 100)
        try await file.write(UnsafeRawBufferPointer(rebasing: bytes.all[0..<2]))
        try file.close()
    }

    /// The whole file; 10 bytes at 96; 5 at the position after a seek to 1000.
    static func readFile(_ path: String) async throws(IOError) -> [[UInt8]] {
        let reader = try await File.open(path)
        var all = IOBuffer(capacity: 1 << 16)
        try await reader.readToEnd(into: &all)
        var some = IOBuffer(capacity: 10)
        _ = try await reader.read(into: &some, at: 96)
        try reader.seek(.start(1000))
        var next = IOBuffer(capacity: 5)
        _ = try await reader.read(into: &next) // from 1000, after the positional read
        let a: [UInt8] = all.withUnsafeBytes { Array($0) }
        let b: [UInt8] = some.withUnsafeBytes { Array($0) }
        let c: [UInt8] = next.withUnsafeBytes { Array($0) }
        return [a, b, c]
    }

    /// Two appending opens: three writes of 3 bytes each, read back.
    fileprivate static func appendFile(_ path: String, _ bytes: Bytes) async throws(IOError) -> [UInt8] {
        let a = try await File.open(path, options: .appending)
        try await a.write(UnsafeRawBufferPointer(rebasing: bytes.all[0..<3]))
        try await a.write(UnsafeRawBufferPointer(rebasing: bytes.all[3..<6]))
        try a.close()
        let b = try await File.open(path, options: .appending)
        try await b.write(UnsafeRawBufferPointer(rebasing: bytes.all[6..<9]))
        try b.close()
        return try await FileSystem.read(path)
    }

    /// VegaFS reads and writes are overlapped ReadFile and WriteFile on the
    /// port, through the file's twin handle: at the file's position (which
    /// they move on, as read(2) and write(2) do), at an offset (which they
    /// leave alone), and appending.
    @Test func fileReadsAndWritesAreOverlapped() throws {
        let rt = Runtime(workers: 2, io: .iocp)
        defer { rt.shutdown() }
        let content: [UInt8] = Self.pattern(3 << 20)
        let bytes = Bytes(content)
        defer { bytes.free() }
        let results: [[UInt8]] = try rt.block { () async throws(IOError) -> [[UInt8]] in
            let dir = try await FileSystem.createTemporaryDirectory(prefix: "vega-iocp-")
            try await Self.writeFile(dir + "/data.bin", bytes)
            var got = try await Self.readFile(dir + "/data.bin")
            got.append(try await Self.appendFile(dir + "/log.txt", bytes))
            try await FileSystem.removeDirectory(dir, recursive: true)
            return got
        }
        var expected: [UInt8] = content
        for i in 0..<4 { expected[100 + i] = content[i] }
        expected.append(content[0])
        expected.append(content[1])
        let slice: [UInt8] = Array(expected[96..<106])
        let afterSeek: [UInt8] = Array(expected[1000..<1005])
        let appended: [UInt8] = Array(content[0..<9])
        #expect(results[0].count == expected.count)
        #expect(results[0] == expected)
        #expect(results[1] == slice)
        #expect(results[2] == afterSeek)
        #expect(results[3] == appended)
        #expect(Self.count(rt, CV_OVL_FILE_WRITE) >= 7)
        #expect(Self.count(rt, CV_OVL_FILE_READ) >= 3)
    }

    /// A file a runtime's port has can still be read from another runtime,
    /// through the blocking pool there.
    @Test func aFileOnAnotherRuntimesPort() throws {
        let first = Runtime(workers: 1, io: .iocp)
        defer { first.shutdown() }
        let second = Runtime(workers: 1, io: .iocp)
        defer { second.shutdown() }
        let content = Self.pattern(1 << 16)
        let (dir, path) = try first.block { () async throws -> (String, String) in
            let dir = try await FileSystem.createTemporaryDirectory(prefix: "vega-iocp-")
            try await FileSystem.write(dir + "\\f.bin", contents: content)
            return (dir, dir + "\\f.bin")
        }
        let readsBefore = Self.count(second, CV_OVL_FILE_READ)
        let (a, b) = try first.block { () async throws -> (Int, [UInt8]) in
            let file = try await File.open(path)
            var buf = IOBuffer(capacity: 100)
            let a = try await file.read(into: &buf, at: 0) // the twin, on the first port
            let b = await second.spawn(with: file) { file async -> [UInt8] in
                var buf = IOBuffer(capacity: 100)
                _ = try? await file.read(into: &buf, at: 200)
                return buf.withUnsafeBytes { Array($0) }
            }.value
            return (a, b)
        }
        try first.block { () async throws in try await FileSystem.removeDirectory(dir, recursive: true) }
        #expect(a == 100)
        #expect(b == Array(content[200..<300]))
        #expect(Self.count(second, CV_OVL_FILE_READ) == readsBefore) // by the blocking pool
    }

    /// The readiness backend makes no requests but sendFile's.
    @Test func readinessMakesNoRequests() throws {
        let rt = Runtime(workers: 2, io: .readiness)
        defer { rt.shutdown() }
        let content = Self.pattern(8 << 20)
        let bytes = Bytes(content)
        defer { bytes.free() }
        let got = try rt.block { () async throws(IOError) -> [UInt8] in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let conn = try await listener.accept()
            let writer = rt.spawn(with: client) { client async -> Bool in
                do throws(IOError) {
                    for at in stride(from: 0, to: bytes.all.count, by: 1 << 20) {
                        try await client.write(UnsafeRawBufferPointer(rebasing: bytes.all[at..<at + (1 << 20)]))
                    }
                    return true
                } catch {
                    return false
                }
            }
            try? await Runtime.sleep(for: .milliseconds(50))
            var buf = IOBuffer(capacity: content.count)
            try await readExactly(conn, content.count, into: &buf)
            #expect(await writer.value)
            return buf.withUnsafeBytes { Array($0) }
        }
        #expect(got == content)
        for kind in 0..<CV_OVL_KINDS { #expect(Self.count(rt, kind) == 0, "requests of kind \(kind)") }
    }
}
#endif
