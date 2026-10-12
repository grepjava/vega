#if os(Linux)
import CVega
import Glibc
import Testing
@testable import Vega

/// The uring driver, asked for explicitly (the rest of the suite runs on it
/// with `VEGA_DRIVER=uring`). Skipped where the kernel can't run it.
@Suite(.enabled(if: URing.supported)) struct URingTests {
    @Test func runtimeUsesRings() {
        let rt = Runtime(workers: 2, io: .ioUring)
        defer { rt.shutdown() }
        #expect(rt.ioBackend == .ioUring)
        #expect(Runtime(workers: 1, io: .readiness).ioBackend == .readiness)
    }

    @Test func echoThroughRings() throws {
        let rt = Runtime(workers: 2, io: .ioUring)
        defer { rt.shutdown() }
        let reply = try rt.block { () async throws -> String in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            async let reply = roundTrip(port: port, message: "through the ring")
            let conn = try await listener.accept()
            var buf = IOBuffer(capacity: 256)
            try await readExactly(conn, 16, into: &buf)
            try await conn.write(buf)
            return try await reply
        }
        #expect(reply == "through the ring")
        let m = rt.ioMetrics
        #expect(m.events > 0)
        #expect(m.wakes > 0)
    }

    /// A large transfer: sends complete partially and are resubmitted.
    @Test func bulkTransfer() throws {
        let rt = Runtime(workers: 2, io: .ioUring)
        defer { rt.shutdown() }
        let size = 8 << 20
        let got = try rt.block { () async throws -> Int in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            let sender = rt.spawn { () async throws in
                let client = try await TCPStream.connect(host: "127.0.0.1", port: port)
                var out = IOBuffer(capacity: size)
                out.count = size
                try await client.write(out)
            }
            let conn = try await listener.accept()
            var buf = IOBuffer(capacity: 64 * 1024)
            var total = 0
            while true {
                let n = try await conn.read(into: &buf)
                if n == 0 { break }
                total += n
                buf.clear()
            }
            try await sender.value
            return total
        }
        #expect(got == size)
    }

    /// A read cancelled while its recv is in the kernel: the task waits for
    /// the cancelled completion, then the socket still works.
    @Test func cancelInFlightRecv() throws {
        let rt = Runtime(workers: 2, io: .ioUring)
        defer { rt.shutdown() }
        let (first, text) = try rt.block { () async throws -> (IOError?, String) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let conn = try await listener.accept()
            let reader = rt.spawn(with: conn) { conn -> (IOError?, String) in
                var buf = IOBuffer(capacity: 64)
                var first: IOError? = nil
                do { _ = try await conn.read(into: &buf) } catch { first = error as? IOError }
                // Cancelled for good: each read is cancelled again, so poll
                // until the data arrives in one that completes first.
                while buf.count == 0 {
                    _ = try? await conn.read(into: &buf)
                    await Task.yield()
                }
                return (first, buf.string)
            }
            try await Runtime.sleep(for: .milliseconds(20))
            reader.cancel()
            try await Runtime.sleep(for: .milliseconds(20))
            var out = IOBuffer(capacity: 64)
            out.append("still here")
            try await client.write(out)
            return await reader.value
        }
        #expect(first == .cancelled)
        #expect(text == "still here")
    }

    /// Pending accepts, cancelled one after another.
    @Test func cancelPendingAccepts() throws {
        let rt = Runtime(workers: 4, io: .ioUring)
        defer { rt.shutdown() }
        let cancelled = try rt.block { () async throws -> Int in
            var cancelled = 0
            for _ in 0..<50 {
                let t = rt.spawn { () async -> Bool in
                    do {
                        let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
                        _ = try await listener.accept()
                        return false
                    } catch {
                        return (error as? IOError) == .cancelled
                    }
                }
                try await Runtime.sleep(for: .milliseconds(1))
                t.cancel()
                if await t.value { cancelled += 1 }
            }
            return cancelled
        }
        #expect(cancelled == 50)
    }

    /// A task off the runtime's workers uses a socket of a uring runtime: it
    /// hops onto a worker for each operation.
    @Test func socketUsedFromAnotherExecutor() throws {
        let rt = Runtime(workers: 2, io: .ioUring)
        defer { rt.shutdown() }
        let other = Runtime(workers: 1, io: .readiness)
        defer { other.shutdown() }
        let reply = try rt.block { () async throws -> String in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            let client = try await TCPStream.connect(host: "127.0.0.1", port: port)
            let conn = try await listener.accept()
            // The client is driven from the epoll runtime's worker.
            let clientSide = other.spawn(with: client) { client -> String in
                var out = IOBuffer(capacity: 64)
                out.append("hop")
                try? await client.write(out)
                var back = IOBuffer(capacity: 64)
                try? await readExactly(client, 3, into: &back)
                return back.string
            }
            var buf = IOBuffer(capacity: 64)
            try await readExactly(conn, 3, into: &buf)
            try await conn.write(buf)
            return await clientSide.value
        }
        #expect(reply == "hop")
    }
}
#endif
