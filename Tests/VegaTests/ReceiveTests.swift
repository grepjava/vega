#if os(Linux) || canImport(Darwin) || os(Windows)
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif
import Testing
@testable import Vega

/// `receive()` and `tryRead(into:)`: reads that hold no buffer while they
/// wait. Each test runs on every way the platform has of receiving.
@Suite struct ReceiveTests {
    /// A runtime per way to receive: on Linux, the uring driver's multishot,
    /// single-shot and readiness modes, and epoll; elsewhere the default
    /// backend and readiness.
    static func runtimes(workers: Int = 2, buffers: UInt32? = nil) -> [(String, Runtime)] {
        var all: [(String, Runtime)] = []
        #if os(Linux)
        for (name, mode) in [("multishot", ReceiveMode.multishot), ("single", .single), ("uring-readiness", .readiness)] {
            all.append((name, Runtime(scheduler: Scheduler(workers: workers, name: "rx", pin: false, io: .ioUring,
                                                            receive: mode, receiveBuffers: buffers))))
        }
        #else
        all.append(("default", Runtime(workers: workers)))
        #endif
        all.append(("readiness", Runtime(workers: workers, io: .readiness)))
        return all
    }

    /// A connected pair on `rt`'s loopback.
    static func pair() async throws(IOError) -> StreamHalves<TCPStream, TCPStream> {
        let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
        let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
        let conn = try await listener.accept()
        return StreamHalves(reader: conn, writer: client)
    }

    /// Receive until `n` bytes or the end of the stream.
    static func receiveAll(_ stream: borrowing TCPStream, _ n: Int) async throws(IOError) -> [UInt8] {
        var out: [UInt8] = []
        while out.count < n {
            let bytes = try await stream.receive()
            if bytes.isEmpty { break }
            bytes.withUnsafeBytes { out.append(contentsOf: $0) }
        }
        return out
    }

    static func pattern(_ n: Int) -> [UInt8] { (0..<n).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ $0 >> 8) } }

    @Test func receivesWhatWasSentThenTheEnd() throws {
        for (name, rt) in Self.runtimes() {
            defer { rt.shutdown() }
            let (text, end) = try rt.block { () async throws(IOError) -> (String, Bool) in
                let p = try await Self.pair()
                let conn = p.reader, client = p.writer
                try await client.write(IOBuffer(copying: Array("hello".utf8)))
                let bytes = try await conn.receive()
                let text = bytes.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
                _ = consume client
                let end = try await conn.receive()
                return (text, end.isEmpty)
            }
            #expect(text == "hello", "\(name)")
            #expect(end, "\(name)")
        }
    }

    @Test func aBulkTransferArrivesWholeAndInOrder() throws {
        let size = 4 << 20
        for (name, rt) in Self.runtimes() {
            defer { rt.shutdown() }
            let got = try rt.block { () async throws(IOError) -> [UInt8] in
                let p = try await Self.pair()
                let conn = p.reader
                rt.spawn(with: p.writer) { client async in
                    let data = Self.pattern(size)
                    var at = 0
                    while at < data.count {
                        let end = min(at + 100_000, data.count)
                        try? await client.write(IOBuffer(copying: Array(data[at..<end])))
                        at = end
                    }
                }
                return try await Self.receiveAll(conn, size)
            }
            #expect(got == Self.pattern(size), "\(name)")
        }
    }

    @Test func aSlowReaderGetsEverythingInOrder() throws {
        // Many small writes while the reader sleeps: under multishot the
        // receive queues them and pauses, and is armed again as it drains.
        let count = 200
        for (name, rt) in Self.runtimes() {
            defer { rt.shutdown() }
            let got = try rt.block { () async throws(IOError) -> [UInt8] in
                let p = try await Self.pair()
                let conn = p.reader, client = p.writer
                // The first receive arms the multishot one.
                try await client.write(IOBuffer(copying: [0xff]))
                let first = try await conn.receive().count
                for i in 0..<count {
                    try await client.write(IOBuffer(copying: [UInt8(truncatingIfNeeded: i)]))
                    if i % 20 == 0 { try? await Runtime.sleep(for: .milliseconds(1)) }
                }
                _ = consume client
                try? await Runtime.sleep(for: .milliseconds(50))
                var all = try await Self.receiveAll(conn, Int.max)
                all.insert(contentsOf: [UInt8](repeating: 0xff, count: first), at: 0)
                return all
            }
            #expect(got.count == count + 1, "\(name)")
            #expect(Array(got.dropFirst()) == (0..<count).map { UInt8(truncatingIfNeeded: $0) }, "\(name)")
        }
    }

    @Test func readsAndReceivesMixKeepTheOrder() throws {
        for (name, rt) in Self.runtimes() {
            defer { rt.shutdown() }
            let text = try rt.block { () async throws(IOError) -> String in
                let p = try await Self.pair()
                let conn = p.reader, client = p.writer
                var out = ""
                for word in ["one ", "two ", "three ", "four ", "five"] {
                    try await client.write(IOBuffer(copying: Array(word.utf8)))
                    try? await Runtime.sleep(for: .milliseconds(5))
                }
                _ = consume client
                // receive, read, tryRead, readable in turn until the end.
                var turn = 0
                while true {
                    turn += 1
                    switch turn % 3 {
                    case 0:
                        let bytes = try await conn.receive()
                        if bytes.isEmpty { return out }
                        out += bytes.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
                    case 1:
                        var buf = IOBuffer(capacity: 3) // short: leaves the rest queued
                        if try await conn.read(into: &buf) == 0 { return out }
                        out += buf.string
                    default:
                        try await conn.readable()
                        var buf = IOBuffer(capacity: 64)
                        if let n = try conn.tryRead(into: &buf) {
                            if n == 0 { return out }
                            out += buf.string
                        }
                    }
                }
            }
            #expect(text == "one two three four five", "\(name)")
        }
    }

    @Test func tryReadSaysNilUntilBytesCome() throws {
        for (name, rt) in Self.runtimes() {
            defer { rt.shutdown() }
            let (before, after) = try rt.block { () async throws(IOError) -> (Int?, String) in
                let p = try await Self.pair()
                let conn = p.reader, client = p.writer
                var buf = IOBuffer(capacity: 16)
                let before = try conn.tryRead(into: &buf)
                try await client.write(IOBuffer(copying: Array("ok".utf8)))
                while true {
                    try await conn.readable()
                    if let n = try conn.tryRead(into: &buf), n > 0 { break }
                }
                return (before, buf.string)
            }
            #expect(before == nil, "\(name)")
            #expect(after == "ok", "\(name)")
        }
    }

    @Test func aDeadlineEndsTheWaitAndTheStreamGoesOn() throws {
        for (name, rt) in Self.runtimes() {
            defer { rt.shutdown() }
            let (outcome, text) = try rt.block { () async throws(IOError) -> (IOError?, String) in
                let p = try await Self.pair()
                let conn = p.reader, client = p.writer
                var outcome: IOError?
                do throws(IOError) {
                    _ = try await Runtime.withIOTimeout(for: .milliseconds(50)) { () async throws(IOError) -> Int in
                        try await conn.receive().count
                    }
                } catch {
                    outcome = error
                }
                try await client.write(IOBuffer(copying: Array("later".utf8)))
                let bytes = try await conn.receive()
                return (outcome, bytes.withUnsafeBytes { String(decoding: $0, as: UTF8.self) })
            }
            #expect(outcome == .timedOut, "\(name)")
            #expect(text == "later", "\(name)")
        }
    }

    @Test func cancellationEndsTheWait() throws {
        for (name, rt) in Self.runtimes() {
            defer { rt.shutdown() }
            let outcome = try rt.block { () async throws(IOError) -> IOError? in
                let p = try await Self.pair()
                let client = p.writer
                let task = rt.spawn(with: p.reader) { conn async -> IOError? in
                    do throws(IOError) {
                        _ = try await conn.receive()
                        return nil
                    } catch {
                        return error
                    }
                }
                try? await Runtime.sleep(for: .milliseconds(30))
                task.cancel()
                let outcome = await task.value
                _ = consume client
                return outcome
            }
            #expect(outcome == .cancelled, "\(name)")
        }
    }

    @Test func manyConnectionsAcrossWorkers() throws {
        // Echo servers on four workers, the received bytes dropped wherever
        // the task runs then: buffers go back to their rings across threads.
        let conns = 64, messages = 50
        for (name, rt) in Self.runtimes(workers: 4) {
            defer { rt.shutdown() }
            let ok = try rt.block { () async throws(IOError) -> Int in
                let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
                let port = listener.localPort
                let server = rt.spawn(with: listener) { listener async in
                    for _ in 0..<conns {
                        guard let conn = try? await listener.accept() else { return }
                        rt.spawn(with: conn) { conn async in
                            while let bytes = try? await conn.receive(), !bytes.isEmpty {
                                var out = IOBuffer(capacity: bytes.count)
                                out.append(bytes)
                                _ = consume bytes
                                await Task.yield()
                                guard (try? await conn.write(out)) != nil else { return }
                            }
                        }
                    }
                }
                let ok = Locked(0)
                await withTaskGroup(of: Void.self) { group in
                    for c in 0..<conns {
                        group.addTask {
                            guard let client = try? await TCPStream.connect(host: "127.0.0.1", port: port) else { return }
                            for m in 0..<messages {
                                let text = "c\(c)m\(m);"
                                guard (try? await client.write(IOBuffer(copying: Array(text.utf8)))) != nil else { return }
                                var back = IOBuffer(capacity: 64)
                                guard (try? await readExactly(client, text.utf8.count, into: &back)) != nil,
                                      back.string == text else { return }
                            }
                            ok.withLock { $0 += 1 }
                        }
                    }
                }
                await server.value
                return ok.withLock { $0 }
            }
            #expect(ok == conns, "\(name)")
        }
    }

    #if os(Linux)
    @Test func aPoolRunDryFallsBackToReadiness() throws {
        // Two buffers per ring: hold received bytes until it runs out, and
        // the receives go on another way.
        let rt = Runtime(scheduler: Scheduler(workers: 1, name: "rx", pin: false, io: .ioUring,
                                              receive: .multishot, receiveBuffers: 2))
        defer { rt.shutdown() }
        let text = try rt.block { () async throws(IOError) -> String in
            var held: [String] = []
            var keep: [Box] = []
            for i in 0..<6 {
                let p = try await Self.pair()
                let conn = p.reader, client = p.writer
                try await client.write(IOBuffer(copying: Array("m\(i)".utf8)))
                let bytes = try await conn.receive()
                held.append(bytes.withUnsafeBytes { String(decoding: $0, as: UTF8.self) })
                keep.append(Box(bytes))
            }
            return held.joined(separator: ",")
        }
        #expect(text == "m0,m1,m2,m3,m4,m5")
    }

    @Test func aRingRuntimeReceivesOnItsRings() throws {
        let rt = Runtime(scheduler: Scheduler(workers: 1, name: "rx", pin: false, io: .ioUring, receive: .multishot))
        defer { rt.shutdown() }
        guard rt.ioBackend == .ioUring else { return }
        let armed = try rt.block { () async throws(IOError) -> Bool in
            let p = try await Self.pair()
            let conn = p.reader, client = p.writer
            try await client.write(IOBuffer(copying: Array("x".utf8)))
            _ = try await conn.receive()
            return conn.reg.io.pointee.rx != nil
        }
        #expect(armed)
    }
    #endif
}

/// Keeps received bytes alive.
private final class Box: @unchecked Sendable {
    var bytes: ReceivedBytes?
    init(_ bytes: consuming ReceivedBytes) { self.bytes = consume bytes }
}

@Suite struct IOBufferStorageTests {
    @Test func releasedStorageComesBackOnReserve() {
        var buffer = IOBuffer(capacity: ReceivedBytes.blockSize)
        buffer.append("abc")
        buffer.consume(3)
        buffer.releaseStorage()
        #expect(buffer.capacity == 0)
        buffer.reserveCapacity(ReceivedBytes.blockSize)
        #expect(buffer.capacity == ReceivedBytes.blockSize)
        buffer.append("def")
        #expect(buffer.string == "def")
    }

    @Test func receivedBytesFromABuffer() {
        var buffer = IOBuffer(capacity: 8)
        buffer.append("hello")
        var bytes = ReceivedBytes(buffer)
        bytes.removeFirst(1)
        #expect(bytes.withUnsafeBytes { String(decoding: $0, as: UTF8.self) } == "ello")
        var into = IOBuffer(capacity: 2)
        into.append(bytes)
        #expect(into.string == "ello")
    }
}
#endif
