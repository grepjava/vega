#if os(Linux)
import Glibc
import Testing
@testable import Vega

/// Read until `n` bytes are in `buf` or the peer closes.
func readExactly(_ stream: borrowing TCPStream, _ n: Int, into buf: inout IOBuffer) async throws(IOError) {
    while buf.count < n {
        if try await stream.read(into: &buf) == 0 { return }
    }
}

func roundTrip(port: Int, message: String) async throws(IOError) -> String {
    let client = try await TCPStream.connect(host: "127.0.0.1", port: port)
    var out = IOBuffer(capacity: 256)
    out.append(message)
    try await client.write(out)
    var back = IOBuffer(capacity: 256)
    try await readExactly(client, message.utf8.count, into: &back)
    return back.string
}

@Suite struct TCPTests {
    @Test func echoRoundTrip() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let reply = try rt.block { () async throws -> String in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            async let reply = roundTrip(port: port, message: "hello vega")
            let conn = try await listener.accept()
            var buf = IOBuffer(capacity: 256)
            try await readExactly(conn, 10, into: &buf)
            try await conn.write(buf)
            return try await reply
        }
        #expect(reply == "hello vega")
    }

    @Test func manyConnectionsEachServedByOwnTask() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let n = 200
        let replies = try rt.block { () async throws(IOError) -> [String] in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            // Clients, one task each.
            let clients = Task(executorPreference: rt.executor) { () async throws -> [String] in
                try await withThrowingTaskGroup(of: String.self) { g in
                    for i in 0..<n {
                        g.addTask { try await roundTrip(port: port, message: "message \(i)") }
                    }
                    return try await g.reduce(into: []) { $0.append($1) }
                }
            }
            // Server: one task per connection, echoing until the client closes.
            for _ in 0..<n {
                let conn = try await listener.accept()
                rt.spawn(with: conn) { conn in
                    var buf = IOBuffer(capacity: 256)
                    while (try? await conn.read(into: &buf)) ?? 0 > 0 {
                        try? await conn.write(buf)
                        buf.clear()
                    }
                }
            }
            do { return try await clients.value } catch { throw error as! IOError }
        }
        #expect(Set(replies) == Set((0..<n).map { "message \($0)" }))
    }

    @Test func readReturnsZeroAtEndOfStream() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let n = try rt.block { () async throws(IOError) -> Int in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let conn = try await listener.accept()
            try client.shutdownWrite()
            var buf = IOBuffer(capacity: 16)
            return try await conn.read(into: &buf)
        }
        #expect(n == 0)
    }

    @Test func connectToClosedPortIsRefused() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let error = rt.block { () async -> IOError? in
            // Bind and drop, so the port is known to be free.
            var port = 1
            if let l = try? TCPListener.bind(host: "127.0.0.1", port: 0) { port = l.localPort }
            do throws(IOError) {
                _ = try await TCPStream.connect(host: "127.0.0.1", port: port)
                return nil
            } catch {
                return error
            }
        }
        #expect(error == .connectionRefused)
    }

    /// Cancelling a task blocked in `read` abandons that read only: the task
    /// gets `.cancelled`, and the same socket still works.
    @Test func cancellingAPendingReadLeavesTheSocketUsable() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (outcome, after) = try rt.block { () async throws(IOError) -> (IOError?, String) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let conn = try await listener.accept()
            let reader = rt.spawn(with: conn) { conn -> Void in
                var buf = IOBuffer(capacity: 16)
                do throws(IOError) {
                    _ = try await conn.read(into: &buf) // the client never sends
                    Outcome.set(nil)
                } catch {
                    Outcome.set(error)
                }
                // Cancelled, but the socket is fine: writing still works.
                buf.append("still here")
                try? await conn.write(buf)
            }
            try? await Runtime.sleep(for: .milliseconds(20))
            reader.cancel()
            await reader.value
            var back = IOBuffer(capacity: 64)
            try await readExactly(client, 10, into: &back)
            return (Outcome.get(), back.string)
        }
        #expect(outcome == .cancelled)
        #expect(after == "still here")
    }
}

/// One test's result slot (the tests that use it don't run concurrently with
/// each other's slot use: it is set and read within one test).
private enum Outcome {
    nonisolated(unsafe) static var value: IOError??
    static func set(_ e: IOError?) { value = .some(e) }
    static func get() -> IOError? { value ?? nil }
}
#endif
