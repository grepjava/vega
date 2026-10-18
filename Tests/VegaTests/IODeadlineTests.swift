import CVega
import Testing
@testable import Vega

private let ms: UInt64 = 1_000_000

/// A connected client and server on loopback.
private struct Pair: ~Copyable {
    var client: TCPStream
    var server: TCPStream
}

private func connectedPair() async throws(IOError) -> Pair {
    let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
    let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
    let server = try await listener.accept()
    return Pair(client: client, server: server)
}

private func byte(_ value: UInt8) -> IOBuffer {
    var buffer = IOBuffer(capacity: 1)
    buffer.withUnsafeSpareCapacity { room in
        room.storeBytes(of: value, as: UInt8.self)
        return 1
    }
    return buffer
}

@Suite("Runtime.withIOTimeout")
struct IODeadlineTests {
    /// A read with nothing to read gives up at the deadline. The task is not
    /// cancelled, and the stream still works.
    @Test func aWaitGivesUpAtTheDeadline() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let start = cv_now_ns()
        let (outcome, cancelled, after, left) = try rt.block { () async throws(IOError) -> (String, Bool, Int, Int) in
            let pair = try await connectedPair()
            let client = pair.client, server = pair.server
            var buffer = IOBuffer(capacity: 8)
            let outcome: String
            do throws(IOError) {
                let n = try await Runtime.withIOTimeout(for: .milliseconds(20)) { () async throws(IOError) -> Int in
                    try await client.read(into: &buffer)
                }
                outcome = "read \(n)"
            } catch {
                outcome = error == .timedOut ? "timedOut" : "\(error)"
            }
            let cancelled = Task.isCancelled
            try await server.write(byte(7))
            let after = try await client.read(into: &buffer)
            return (outcome, cancelled, after, rt.scheduler.timers.count)
        }
        let elapsed = (cv_now_ns() - start) / ms
        #expect(outcome == "timedOut")
        #expect(!cancelled, "the deadline interrupts the wait, not the task")
        #expect(after == 1, "the stream outlives a wait given up")
        #expect(left == 0)
        #expect(elapsed >= 20 && elapsed < 1_000, "took \(elapsed) ms")
    }

    /// Finishing in time returns the value and unlinks the timer.
    @Test func finishingInTimeUnlinksTheTimer() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (n, left) = try rt.block { () async throws(IOError) -> (Int, Int) in
            let pair = try await connectedPair()
            let client = pair.client, server = pair.server
            let n = try await Runtime.withIOTimeout(for: .seconds(10)) { () async throws(IOError) -> Int in
                try await server.write(byte(1))
                var buffer = IOBuffer(capacity: 8)
                return try await client.read(into: &buffer)
            }
            return (n, rt.scheduler.timers.count)
        }
        #expect(n == 1)
        #expect(left == 0, "the deadline's timer outlived it")
    }

    /// Past the deadline, a wait fails at once.
    @Test func aPassedDeadlineFailsAWaitAtOnce() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let start = cv_now_ns()
        let error = try rt.block { () async throws(IOError) -> IOError? in
            let pair = try await connectedPair()
            let client = pair.client, server = pair.server
            // Kept open to the end, so the read has nothing to see.
            defer { _ = try? server.localAddress }
            do throws(IOError) {
                try await Runtime.withIOTimeout(for: .zero) { () async throws(IOError) in
                    var buffer = IOBuffer(capacity: 8)
                    _ = try await client.read(into: &buffer)
                }
                return nil
            } catch {
                return error
            }
        }
        #expect(error == .timedOut)
        #expect((cv_now_ns() - start) / ms < 1_000)
    }

    /// The deadline is the task's that set it: a child task's wait runs on.
    @Test func aChildTasksWaitIsNotBounded() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let n = try rt.block { () async throws(IOError) -> Int in
            try await Runtime.withIOTimeout(for: .milliseconds(30)) { () async throws(IOError) -> Int in
                // The setup and the write aren't what's tested: each gets a
                // deadline of its own. A loaded Network.framework connect can
                // outlast 30 ms, and by the write this task's deadline has
                // passed (a write the socket takes at once doesn't wait on
                // readiness drivers, but a Network.framework send does).
                let pair = try await Runtime.withIOTimeout(for: .seconds(5)) { () async throws(IOError) -> Pair in
                    try await connectedPair()
                }
                let client = pair.client, server = pair.server
                // Inherits the task-local deadline, and is not bound by it.
                let reader = rt.spawn(with: client) { client -> Int in
                    var buffer = IOBuffer(capacity: 8)
                    return (try? await client.read(into: &buffer)) ?? -1
                }
                try? await Runtime.sleep(for: .milliseconds(90))
                try await Runtime.withIOTimeout(for: .seconds(5)) { () async throws(IOError) in
                    try await server.write(byte(1))
                }
                return await reader.value
            }
        }
        #expect(n == 1)
    }

    /// Cancelling the task is a cancellation, not a timeout.
    @Test func cancellationIsNotATimeout() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let error = try rt.block { () async throws(IOError) -> IOError? in
            let pair = try await connectedPair()
            let client = pair.client, server = pair.server
            defer { _ = try? server.localAddress }
            let reader = rt.spawn(with: client) { client -> IOError? in
                do throws(IOError) {
                    try await Runtime.withIOTimeout(for: .seconds(60)) { () async throws(IOError) in
                        var buffer = IOBuffer(capacity: 8)
                        _ = try await client.read(into: &buffer)
                    }
                    return nil
                } catch {
                    return error
                }
            }
            try? await Runtime.sleep(for: .milliseconds(20))
            reader.cancel()
            return await reader.value
        }
        #expect(error == .cancelled)
    }

    @Test func rethrowsTheBodysOwnError() {
        struct Boom: Error {}
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let isBoom = rt.block { () async -> Bool in
            do throws(Boom) {
                try await Runtime.withIOTimeout(for: .seconds(10)) { () async throws(Boom) in throw Boom() }
                return false
            } catch {
                return true
            }
        }
        #expect(isBoom)
    }
}
