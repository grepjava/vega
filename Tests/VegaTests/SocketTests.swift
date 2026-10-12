#if os(Linux)
import CVega
import Glibc
import Testing
@testable import Vega

/// Read until the peer closes, returning everything.
/// An IOBuffer holding `bytes`.
private func ioBuffer(_ bytes: [UInt8]) -> IOBuffer {
    var b = IOBuffer(capacity: max(bytes.count, 1))
    _ = bytes.withUnsafeBytes { b.append($0) }
    return b
}

private func drain(_ conn: borrowing TCPStream) async -> [UInt8] {
    var out: [UInt8] = []
    var buf = IOBuffer(capacity: 64 * 1024)
    while (try? await conn.read(into: &buf)) ?? 0 > 0 {
        buf.withUnsafeBytes { out.append(contentsOf: $0) }
        buf.clear()
    }
    return out
}

@Suite struct SocketOptionTests {
    @Test func tcpOptionsRoundTrip() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        try rt.block { () async throws(IOError) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let s = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            #expect(try s.option(.noDelay) == 1) // Vega sets it
            #expect(try s.option(.keepAlive) == 0)
            try s.setOption(.keepAlive, to: true)
            try s.setOption(.keepAliveIdle, to: 30)
            try s.setOption(.keepAliveInterval, to: 5)
            try s.setOption(.keepAliveCount, to: 4)
            #expect(try s.option(.keepAlive) == 1)
            #expect(try s.option(.keepAliveIdle) == 30)
            #expect(try s.option(.keepAliveInterval) == 5)
            #expect(try s.option(.keepAliveCount) == 4)
            try s.setOption(.userTimeout, to: 10_000)
            #expect(try s.option(.userTimeout) == 10_000)
            #expect(try s.option(.linger) == -1)
            try s.setOption(.linger, to: 5)
            #expect(try s.option(.linger) == 5)
            try s.setOption(.linger, to: -1)
            #expect(try s.option(.linger) == -1)
            try s.setOption(.receiveBufferSize, to: 256 * 1024)
            #expect(try s.option(.receiveBufferSize) >= 256 * 1024)
            try s.setOption(.typeOfService, to: 0x10)
            #expect(try s.option(.typeOfService) == 0x10)
            #expect(try listener.option(.reuseAddress) == 1)
        }
    }

    @Test func udpOptionsRoundTrip() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        try rt.block { () async throws(IOError) in
            let u = try UDPSocket.bind(host: "0.0.0.0", port: 0)
            try u.setOption(.broadcast, to: true)
            #expect(try u.option(.broadcast) == 1)
            try u.setOption(.timeToLive, to: 7)
            #expect(try u.option(.timeToLive) == 7)
            try u.setOption(.multicastTimeToLive, to: 3)
            #expect(try u.option(.multicastTimeToLive) == 3)
            try u.setOption(.multicastLoop, to: false)
            #expect(try u.option(.multicastLoop) == 0)
            // An IPv6 option on an IPv4 socket is refused, not ignored.
            #expect(throws: IOError.self) { try u.setOption(.hopLimit, to: 9) }
        }
    }
}

@Suite struct VectoredWriteTests {
    /// 2,000 buffers of uneven sizes (some empty), 8 MB in all: many
    /// sendmsg calls end mid-buffer, and each resumes at the right byte.
    @Test func gathersManyBuffersIntact() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let sizes = (0..<2_000).map { i in i % 7 == 0 ? 0 : (i * 7919) % 8_000 + 1 }
        var expected: [UInt8] = []
        var chunks: [[UInt8]] = []
        for (i, n) in sizes.enumerated() {
            let c = (0..<n).map { UInt8(truncatingIfNeeded: $0 &+ i) }
            chunks.append(c)
            expected += c
        }
        let all = chunks
        let received = try rt.block { () async throws(IOError) -> [UInt8] in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let reader = rt.spawn(with: try await listener.accept()) { conn in await drain(conn) }
            let buffers = all.map { c -> UnsafeMutableRawBufferPointer in
                let p = UnsafeMutableRawBufferPointer.allocate(byteCount: max(c.count, 1), alignment: 1)
                p.copyBytes(from: c)
                return p
            }
            defer { buffers.forEach { $0.deallocate() } }
            let parts = UnsafeMutableBufferPointer<UnsafeRawBufferPointer>.allocate(capacity: buffers.count)
            defer { parts.deallocate() }
            for (i, b) in buffers.enumerated() {
                parts[i] = UnsafeRawBufferPointer(start: b.baseAddress, count: all[i].count)
            }
            try await client.write(vectored: UnsafeBufferPointer(parts))
            try client.shutdownWrite()
            return await reader.value
        }
        #expect(received.count == expected.count)
        #expect(received == expected)
    }

    @Test func writesHeadAndBody() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let received = try rt.block { () async throws(IOError) -> String in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let reader = rt.spawn(with: try await listener.accept()) { conn in await drain(conn) }
            var head = IOBuffer(capacity: 64)
            var body = IOBuffer(capacity: 64)
            _ = head.append("HTTP/1.1 200 OK\r\n\r\n")
            _ = body.append("hello")
            try await client.write(head, body)
            try client.shutdownWrite()
            return String(decoding: await reader.value, as: UTF8.self)
        }
        #expect(received == "HTTP/1.1 200 OK\r\n\r\nhello")
    }
}

@Suite struct DatagramBatchTests {
    /// 200 datagrams out in batches, back in batches: each intact, with the
    /// right sender.
    @Test func batchesRoundTrip() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let total = 200
        let (seen, fromClient) = try rt.block { () async throws(IOError) -> ([Bool], Bool) in
            let server = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let client = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let serverAddress = try server.localAddress
            let clientAddress = try client.localAddress

            var out = DatagramBatch(capacity: 50, slotSize: 64)
            var sent = 0
            while sent < total {
                out.removeAll()
                while !out.isFull && sent < total {
                    let i = sent
                    out.append(to: serverAddress) { slot in
                        slot.storeBytes(of: UInt32(i), as: UInt32.self)
                        return 4 + i % 40 // varied lengths
                    }
                    sent += 1
                }
                try await client.send(out)
            }

            var seen = [Bool](repeating: false, count: total)
            var allFromClient = true
            var batch = DatagramBatch(capacity: 32, slotSize: 64)
            var got = 0
            while got < total {
                let n = try await server.receive(&batch)
                for i in 0..<n {
                    let d = batch[i]
                    let index = Int(d.load(as: UInt32.self))
                    #expect(d.count == 4 + index % 40)
                    let truncated = batch.isTruncated(at: i)
                    #expect(!truncated)
                    seen[index] = true
                    if batch.address(at: i) != clientAddress { allFromClient = false }
                }
                got += n
            }
            return (seen, allFromClient)
        }
        #expect(seen.allSatisfy { $0 })
        #expect(fromClient)
    }

    @Test func flagsTruncatedDatagrams() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let (n, truncated, length) = try rt.block { () async throws(IOError) -> (Int, Bool, Int) in
            let server = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let client = try await UDPSocket.connect(host: "127.0.0.1", port: try server.localAddress.port!)
            try await client.send(ioBuffer([UInt8](repeating: 7, count: 100)))
            var batch = DatagramBatch(capacity: 4, slotSize: 10)
            let n = try await server.receive(&batch)
            return (n, batch.isTruncated(at: 0), batch[0].count)
        }
        #expect(n == 1)
        #expect(truncated)
        #expect(length == 10)
    }

    /// One GSO send of 10 × 100 bytes arrives as 10 datagrams, or as one
    /// GRO buffer marked with its segment size.
    @Test func segmentationOffload() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        try rt.block { () async throws(IOError) in
            let server = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let client = try await UDPSocket.connect(host: "127.0.0.1", port: try server.localAddress.port!)
            guard client.supportsSegmentation else { return }
            let payload = ioBuffer((0..<1_000).map { UInt8(truncatingIfNeeded: $0 / 100) })
            let bytes = UnsafeRawBufferPointer(start: payload.base, count: payload.count)

            let sent = try await client.send(segments: bytes, segmentSize: 100)
            #expect(sent == 1_000)
            var batch = DatagramBatch(capacity: 16, slotSize: 2_000)
            var lengths: [Int] = []
            while lengths.count < 10 {
                let n = try await server.receive(&batch)
                for i in 0..<n {
                    lengths.append(batch[i].count)
                    #expect(batch[i].allSatisfy { $0 == batch[i][0] })
                }
            }
            #expect(lengths == [Int](repeating: 100, count: 10))

            // With GRO the same burst may come up in one read.
            try server.setOption(.udpGRO, to: true)
            try await client.send(segments: bytes, segmentSize: 100)
            var buf = IOBuffer(capacity: 65_536)
            var received = 0
            while received < 1_000 {
                let (n, segment, _) = try await server.receiveSegments(into: &buf)
                #expect(segment == 0 || segment == 100)
                received += n
                buf.clear()
            }
            #expect(received == 1_000)
        }
    }

    /// Multicast to ourselves over loopback (skipped where the host has no
    /// multicast route).
    @Test func multicastLoopback() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        try rt.block { () async throws(IOError) in
            let receiver = try UDPSocket.bind(host: "0.0.0.0", port: 0)
            let port = try receiver.localAddress.port!
            let group = try SocketAddress(host: "239.255.77.77", port: port)
            do {
                try receiver.joinMulticastGroup(group)
            } catch {
                return // no multicast-capable interface
            }
            let sender = try UDPSocket.bind(host: "0.0.0.0", port: 0)
            try sender.setOption(.multicastLoop, to: true)
            do {
                try await sender.send(ioBuffer([1, 2, 3]), to: group)
            } catch {
                return // ENETUNREACH: no route for the group
            }
            let got = rt.spawn(with: receiver) { receiver -> Int? in
                var buf = IOBuffer(capacity: 16)
                defer { try? receiver.leaveMulticastGroup(group) }
                return try? await receiver.receive(into: &buf)
            }
            rt.spawn {
                try? await Runtime.sleep(for: .seconds(2))
                got.cancel()
            }
            #expect(await got.value == 3)
        }
    }
}
#endif
