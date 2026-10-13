#if os(Linux) || canImport(Darwin) || os(Windows)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif
import Testing
@testable import Vega

/// Lets short-lived tasks borrow one socket in turn.
private final class SocketBox: Sendable {
    let socket: UDPSocket
    init(_ socket: consuming UDPSocket) { self.socket = socket }
}

private func bytes(_ count: Int) -> [UInt8] { (0..<count).map { UInt8(truncatingIfNeeded: $0) } }

/// An IOBuffer holding `bytes`.
private func ioBuffer(_ bytes: [UInt8]) -> IOBuffer {
    var b = IOBuffer(capacity: max(bytes.count, 1))
    _ = bytes.withUnsafeBytes { b.append($0) }
    return b
}

/// Receive datagrams until `count` have arrived; their lengths and bytes.
private func receiveAll(_ socket: borrowing UDPSocket, count: Int) async throws(IOError) -> [[UInt8]] {
    var batch = DatagramBatch(capacity: 64, slotSize: 2_048)
    var all: [[UInt8]] = []
    while all.count < count {
        let n = try await socket.receive(&batch)
        for i in 0..<n { all.append(Array(batch[i])) }
    }
    return all
}

@Suite struct UDPSegmentTests {
    /// A segmented send arrives as one datagram per segment, the last one
    /// shorter, with GSO or without it (the batch fallback on Darwin).
    @Test func segmentsArriveAsDatagrams() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let payload = bytes(950)
        let got = try rt.block { () async throws(IOError) -> [[UInt8]] in
            let server = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let client = try await UDPSocket.connect(host: "127.0.0.1", port: try server.localAddress.port!)
            let out = ioBuffer(payload)
            let sent = try await client.send(segments: UnsafeRawBufferPointer(start: out.base, count: out.count),
                                             segmentSize: 100)
            #expect(sent == 950)
            return try await receiveAll(server, count: 10)
        }
        #expect(got.map { $0.count } == [Int](repeating: 100, count: 9) + [50])
        #expect(Array(got.joined()) == payload)
    }

    /// The fallback by itself, on every platform: to an address (not a
    /// connected peer), and past one 64-datagram batch.
    @Test func splitSendCrossesBatches() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let payload = bytes(130 * 10 + 3) // 131 datagrams: two full batches and change
        let got = try rt.block { () async throws(IOError) -> [[UInt8]] in
            let server = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            try server.setOption(.receiveBufferSize, to: 1 << 20)
            let sender = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            var to = try server.localAddress.raw
            let sent = payload.withUnsafeBytes { p in
                cv_send_segments_split(sender.reg.fd, p.baseAddress, p.count, 10, &to)
            }
            #expect(sent == payload.count)
            return try await receiveAll(server, count: 131)
        }
        #expect(got.map { $0.count } == [Int](repeating: 10, count: 130) + [3])
        #expect(Array(got.joined()) == payload)
    }

    /// No bytes: one empty datagram, as a plain send would make.
    @Test func emptySegmentedSendIsOneEmptyDatagram() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let got = try rt.block { () async throws(IOError) -> [[UInt8]] in
            let server = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let client = try await UDPSocket.connect(host: "127.0.0.1", port: try server.localAddress.port!)
            let sent = try await client.send(segments: UnsafeRawBufferPointer(start: nil, count: 0), segmentSize: 100)
            #expect(sent == 0)
            return try await receiveAll(server, count: 1)
        }
        #expect(got == [[]])
    }

    /// A datagram longer than the room left is cut short and says so.
    @Test func receiveSegmentsFlagsTruncation() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        try rt.block { () async throws(IOError) in
            let server = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let client = try await UDPSocket.connect(host: "127.0.0.1", port: try server.localAddress.port!)
            var out = IOBuffer(capacity: 100)
            out.append(String(repeating: "x", count: 100))
            try await client.send(out)
            var buf = IOBuffer(capacity: 50)
            let (n, segment, _, truncated) = try await server.receiveSegments(into: &buf)
            #expect(n == 50)
            #expect(segment == 0)
            #expect(truncated)

            try await client.send(out)
            var roomy = IOBuffer(capacity: 1_000)
            let second = try await server.receiveSegments(into: &roomy)
            #expect(second.count == 100)
            #expect(!second.truncated)
        }
    }

    #if os(Linux)
    /// A coalesced GRO burst longer than the buffer loses its tail, and the
    /// receive says so (loopback may or may not coalesce).
    @Test func groBurstLongerThanTheBufferIsFlagged() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        try rt.block { () async throws(IOError) in
            let server = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let client = try await UDPSocket.connect(host: "127.0.0.1", port: try server.localAddress.port!)
            guard client.supportsSegmentation else { return }
            try server.setOption(.udpGRO, to: true)
            let out = ioBuffer(bytes(1_000))
            try await client.send(segments: UnsafeRawBufferPointer(start: out.base, count: out.count),
                                  segmentSize: 100)
            var buf = IOBuffer(capacity: 250)
            let (n, segment, _, truncated) = try await server.receiveSegments(into: &buf)
            if segment != 0 {
                #expect(truncated)
                #expect(n == 250)
            } else {
                #expect(n == 100) // not coalesced: one whole datagram
                #expect(!truncated)
            }
        }
    }
    #endif
}

@Suite struct UDPCancellationTests {
    /// Receivers cancelled at every point of a batch receive (waiting, or
    /// with datagrams arriving around the cancel) lose nothing: every
    /// datagram sent is counted once, by some receiver or the final drain.
    @Test func cancellingABatchReceiveLosesNothing() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let total = 2_000
        let received = try rt.block { () async throws(IOError) -> Int in
            let box = SocketBox(try UDPSocket.bind(host: "127.0.0.1", port: 0))
            try box.socket.setOption(.receiveBufferSize, to: 4 << 20)
            let client = try await UDPSocket.connect(host: "127.0.0.1", port: try box.socket.localAddress.port!)
            // Counts what it receives until a receive throws (cancelled).
            // Once cancelled, each receive still reads what is queued and
            // only gives up when it would have to wait.
            @Sendable func receiver() async -> Int {
                var batch = DatagramBatch(capacity: 8, slotSize: 64)
                var n = 0
                while true {
                    do throws(IOError) {
                        n += try await box.socket.receive(&batch)
                    } catch {
                        #expect(error == .cancelled)
                        return n
                    }
                }
            }
            var out = IOBuffer(capacity: 8)
            out.append("ping")
            var sent = 0, got = 0, round = 0
            while sent < total {
                let task = rt.spawn { await receiver() }
                for _ in 0..<(round % 4) where sent < total {
                    try await client.send(out)
                    sent += 1
                }
                if round % 3 == 0 { await Task.yield() }
                if round % 5 == 0 { try? await Runtime.sleep(for: .microseconds(50)) }
                task.cancel()
                got += await task.value
                round += 1
            }
            // A cancelled receiver drains what is queued. On Linux loopback
            // queues a datagram before send returns; on Darwin the last few
            // can still be on their way, so drain again for a moment while
            // any are missing (a lost one still fails the count).
            for attempt in 0..<20 where attempt == 0 || got < total {
                if attempt > 0 { try? await Runtime.sleep(for: .milliseconds(10)) }
                let drain = rt.spawn { await receiver() }
                drain.cancel()
                got += await drain.value
            }
            return got
        }
        #expect(received == total)
    }
}
#endif
