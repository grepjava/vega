#if os(Linux) || canImport(Darwin) || os(Windows)
import Synchronization
import Testing
@testable import Vega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

private func bytes(_ s: String) -> IOBuffer {
    var b = IOBuffer(capacity: max(s.utf8.count, 1))
    b.append(s)
    return b
}

/// Echo until the peer closes.
private func echoAll(_ stream: consuming TCPStream) async {
    var buf = IOBuffer(capacity: 4096)
    while let n = try? await stream.read(into: &buf), n > 0 {
        guard (try? await stream.write(buf)) != nil else { return }
        buf.clear()
    }
}

/// Send `text`, read back as many bytes.
private func roundTrip(_ stream: borrowing TCPStream, _ text: String) async throws -> String {
    try await stream.write(bytes(text))
    var buf = IOBuffer(capacity: 256)
    while buf.count < text.utf8.count {
        if try await stream.read(into: &buf) == 0 { break }
    }
    return buf.string
}

@Suite struct ServerTests {
    @Test func servesConcurrentClients() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let replies = try rt.block { () async throws -> [String] in
            let server = try TCPServer.bind(host: "127.0.0.1", port: 0) { await echoAll($0) }
            let port = server.port
            let replies = try await withThrowingTaskGroup(of: String.self) { group in
                for i in 0..<50 {
                    group.addTask {
                        let s = try await TCPStream.connect(to: SocketAddress(host: "127.0.0.1", port: port))
                        return try await roundTrip(s, "hello \(i)")
                    }
                }
                return try await group.reduce(into: []) { $0.append($1) }
            }
            await server.shutdown(gracePeriod: .seconds(1))
            #expect(server.connectionCount == 0)
            return replies
        }
        #expect(Set(replies) == Set((0..<50).map { "hello \($0)" }))
    }

    /// Several accept loops share the port with SO_REUSEPORT.
    @Test func severalAcceptors() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let replies = try rt.block { () async throws -> [String] in
            let server = try TCPServer.bind(host: "127.0.0.1", port: 0,
                                            configuration: .init(acceptors: 3)) { await echoAll($0) }
            var out: [String] = []
            for i in 0..<20 {
                let s = try await TCPStream.connect(to: SocketAddress(host: "127.0.0.1", port: server.port))
                out.append(try await roundTrip(s, "x\(i)"))
            }
            await server.shutdown(gracePeriod: .seconds(1))
            return out
        }
        #expect(replies == (0..<20).map { "x\($0)" })
    }

    /// With maxConnections 2, a third client waits in the backlog until one
    /// of the first two leaves.
    @Test func maxConnectionsHoldsBackTheRest() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let (peak, third) = try rt.block { () async throws -> (Int, String) in
            let peak = Atomic<Int>(0), now = Atomic<Int>(0)
            let server = try TCPServer.bind(host: "127.0.0.1", port: 0,
                                            configuration: .init(maxConnections: 2)) { stream in
                let n = now.add(1, ordering: .relaxed).newValue
                _ = peak.max(n, ordering: .relaxed)
                await echoAll(stream)
                now.subtract(1, ordering: .relaxed)
            }
            let address = try SocketAddress(host: "127.0.0.1", port: server.port)
            let a = try await TCPStream.connect(to: address)
            let b = try await TCPStream.connect(to: address)
            _ = try await roundTrip(a, "a")
            _ = try await roundTrip(b, "b")
            // Connected (the kernel completed the handshake) but not accepted.
            let c = try await TCPStream.connect(to: address)
            try await c.write(bytes("c"))
            try await Runtime.sleep(for: .milliseconds(50))
            #expect(server.connectionCount == 2)
            _ = consume a
            var buf = IOBuffer(capacity: 8)
            _ = try await c.read(into: &buf)
            await server.shutdown(gracePeriod: .zero)
            _ = b
            return (peak.load(ordering: .relaxed), buf.string)
        }
        #expect(peak == 2)
        #expect(third == "c")
    }

    /// Connections that don't finish in the grace period are cancelled, and
    /// shutdown returns once they've ended.
    @Test func shutdownCancelsAfterTheGracePeriod() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (elapsed, eof, refused) = try rt.block { () async throws -> (Duration, Int, Bool) in
            let server = try TCPServer.bind(host: "127.0.0.1", port: 0) { stream in
                // Never ends on its own: reads until cancelled.
                var buf = IOBuffer(capacity: 16)
                while (try? await stream.read(into: &buf)) != nil { buf.clear() }
            }
            let address = try SocketAddress(host: "127.0.0.1", port: server.port)
            let client = try await TCPStream.connect(to: address)
            try await Runtime.sleep(for: .milliseconds(20))
            #expect(server.connectionCount == 1)
            let start = ContinuousClock.now
            await server.shutdown(gracePeriod: .milliseconds(100))
            let elapsed = ContinuousClock.now - start
            var buf = IOBuffer(capacity: 16)
            let eof = try await client.read(into: &buf)
            let refused: Bool
            do {
                _ = try await TCPStream.connect(to: address)
                refused = false
            } catch {
                refused = true
            }
            return (elapsed, eof, refused)
        }
        #expect(elapsed >= .milliseconds(100))
        #expect(elapsed < .seconds(2))
        #expect(eof == 0)
        #expect(refused)
    }

    /// A handler that watches for shutdown finishes its connection cleanly
    /// within the grace period.
    @Test func handlersCanFinishGracefully() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (reply, cancelled) = try rt.block { () async throws -> (String, Bool) in
            let cancelled = Atomic<Bool>(false)
            let holder = Box<TCPServer>()
            let server = try TCPServer.bind(host: "127.0.0.1", port: 0) { stream in
                try? await holder.value!.waitForShutdown()
                if Task.isCancelled { cancelled.store(true, ordering: .relaxed) }
                try? await stream.write(bytes("bye"))
            }
            holder.value = server
            let client = try await TCPStream.connect(to: SocketAddress(host: "127.0.0.1", port: server.port))
            try await Runtime.sleep(for: .milliseconds(20))
            await server.shutdown(gracePeriod: .seconds(5))
            var buf = IOBuffer(capacity: 16)
            while (try? await client.read(into: &buf)).map({ $0 > 0 }) == true {}
            return (buf.string, cancelled.load(ordering: .relaxed))
        }
        #expect(reply == "bye")
        #expect(!cancelled)
    }

    @Test func connectionOptionsAreApplied() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let keepAlive = try rt.block { () async throws -> Int in
            let seen = Atomic<Int>(-1)
            let server = try TCPServer.bind(host: "127.0.0.1", port: 0,
                                            configuration: .init(connectionOptions: [.keepAlive: 1])) { stream in
                seen.store((try? stream.option(.keepAlive)) ?? -2, ordering: .relaxed)
            }
            let client = try await TCPStream.connect(to: SocketAddress(host: "127.0.0.1", port: server.port))
            var buf = IOBuffer(capacity: 4)
            _ = try await client.read(into: &buf)   // the handler returned: end of stream
            await server.shutdown(gracePeriod: .seconds(1))
            return seen.load(ordering: .relaxed)
        }
        #expect(keepAlive != 0 && keepAlive > 0)
    }

    @Test func clientAppliesOptionsAndUsesTheResolver() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (reply, keepAlive) = try rt.block { () async throws -> (String, Int) in
            let server = try TCPServer.bind(host: "127.0.0.1", port: 0) { await echoAll($0) }
            let path = "\(testTempDirectory())/vega-\(getpid())-client-hosts"
            let file = fopen(path, "w")!
            fputs("127.0.0.1 echo.internal\n", file)
            fclose(file)
            defer { unlink(path) }
            let client = TCPClient(connectTimeout: .seconds(2),
                                   resolver: Resolver(config: ResolverConfig(nameservers: ["127.0.0.1"]),
                                                      hostsPath: path),
                                   options: [.keepAlive: 1])
            let s = try await client.connect(host: "echo.internal", port: server.port)
            let reply = try await roundTrip(s, "ping")
            let keepAlive = try s.option(.keepAlive)
            _ = consume s
            await server.shutdown(gracePeriod: .seconds(1))
            return (reply, keepAlive)
        }
        #expect(reply == "ping")
        #expect(keepAlive > 0)
    }

    /// A connect that can't complete in time ends with ETIMEDOUT (or the
    /// network's own refusal, where 192.0.2.1 is unreachable at once).
    @Test func clientConnectTimeout() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (error, elapsed) = try rt.block { () async throws -> (IOError?, Duration) in
            let client = TCPClient(connectTimeout: .milliseconds(100))
            let start = ContinuousClock.now
            do throws(IOError) {
                _ = try await client.connect(to: [SocketAddress(host: "192.0.2.1", port: 9)])
                return (nil, ContinuousClock.now - start)
            } catch {
                return (error, ContinuousClock.now - start)
            }
        }
        #expect(error != nil)
        #expect(elapsed < .seconds(2))
    }

    @Test func bindingABusyPortFails() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let failed = try rt.block { () async throws -> Bool in
            let server = try TCPServer.bind(host: "127.0.0.1", port: 0) { _ in }
            let failed: Bool
            do {
                _ = try TCPServer.bind(host: "127.0.0.1", port: server.port) { _ in }
                failed = false
            } catch {
                failed = true
            }
            await server.shutdown(gracePeriod: .zero)
            return failed
        }
        #expect(failed)
    }
}

private final class Box<T: Sendable>: @unchecked Sendable {
    private let lock = RawLock()
    private var stored: T?

    deinit { lock.destroy() }

    var value: T? {
        get { lock.withLock { stored } }
        set { lock.withLock { stored = newValue } }
    }
}
#endif
