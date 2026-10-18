import CVega
import Testing
@testable import Vega

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

@Suite("IOTimeoutTrigger")
struct IOTimeoutTriggerTests {
    /// Fired from another task, the trigger ends a read long before its
    /// deadline, as the deadline would, and the stream still works.
    @Test func aTriggerEndsAReadEarly() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let start = cv_now_ns()
        let (outcome, after) = try rt.block { () async throws(IOError) -> (String, Int) in
            let pair = try await connectedPair()
            let client = pair.client, server = pair.server
            let trigger = IOTimeoutTrigger()
            rt.spawn {
                try? await Runtime.sleep(for: .milliseconds(20))
                trigger.fire()
            }
            var buffer = IOBuffer(capacity: 8)
            let outcome: String
            do throws(IOError) {
                let n = try await Runtime.withIOTimeout(for: .seconds(30), trigger: trigger) { () async throws(IOError) -> Int in
                    try await client.read(into: &buffer)
                }
                outcome = "read \(n)"
            } catch {
                outcome = error == .timedOut ? "timedOut" : "\(error)"
            }
            try await server.write(byte(7))
            let after = try await Runtime.withIOTimeout(for: .seconds(5), trigger: trigger) { () async throws(IOError) -> Int in
                try await client.read(into: &buffer)
            }
            return (outcome, after)
        }
        let elapsed = (cv_now_ns() - start) / 1_000_000
        #expect(outcome == "timedOut")
        #expect(after == 1, "the trigger is spent, and the stream outlives the wait")
        #expect(elapsed < 5_000, "took \(elapsed) ms")
    }

    /// Fired while no scope holds it, the trigger fires the next one.
    @Test func aTriggerFiredBetweenScopesFiresTheNext() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let outcome = try rt.block { () async throws(IOError) -> String in
            let pair = try await connectedPair()
            let client = pair.client
            _ = pair.server
            let trigger = IOTimeoutTrigger()
            trigger.fire()
            var buffer = IOBuffer(capacity: 8)
            do throws(IOError) {
                let n = try await Runtime.withIOTimeout(for: .seconds(30), trigger: trigger) { () async throws(IOError) -> Int in
                    try await client.read(into: &buffer)
                }
                return "read \(n)"
            } catch {
                return error == .timedOut ? "timedOut" : "\(error)"
            }
        }
        #expect(outcome == "timedOut")
    }
}
