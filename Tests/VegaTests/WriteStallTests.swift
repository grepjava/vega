#if os(Linux) || canImport(Darwin) || os(Windows)
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

/// `count` bytes to write.
private func filled(_ count: Int) -> IOBuffer {
    var buffer = IOBuffer(capacity: count)
    _ = [UInt8](repeating: 7, count: count).withUnsafeBytes { buffer.append($0) }
    return buffer
}

@Suite("Runtime.withWriteStallTimeout")
struct WriteStallTests {
    /// Writing to a peer that reads nothing gives up once the socket has
    /// been full for the limit, without a deadline on the scope as a whole.
    @Test func aStalledWriteGivesUp() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let start = cv_now_ns()
        let (outcome, left) = try rt.block { () async throws(IOError) -> (String, Int) in
            let pair = try await connectedPair()
            let server = pair.server
            let chunk = filled(1 << 20)
            var sent = 0
            let outcome: String
            do throws(IOError) {
                try await Runtime.withWriteStallTimeout(.milliseconds(100)) { () async throws(IOError) in
                    // Far more than the two sockets' buffers hold.
                    while sent < 256 << 20 {
                        try await server.write(chunk)
                        sent += chunk.count
                    }
                }
                outcome = "sent \(sent)"
            } catch {
                outcome = error == .timedOut ? "timedOut" : "\(error)"
            }
            _ = pair.client
            return (outcome, rt.scheduler.timers.count)
        }
        let elapsed = (cv_now_ns() - start) / 1_000_000
        #expect(outcome == "timedOut")
        #expect(left == 0, "the stalled wait's timer outlived it")
        #expect(elapsed >= 100 && elapsed < 5_000, "took \(elapsed) ms")
    }

    /// A peer that keeps reading keeps the write going past the limit. The
    /// writer goes on for several times the limit rather than for a fixed
    /// size: Windows' loopback buffers tens of megabytes, enough to take any
    /// one write whole before the limit is up.
    @Test func aSlowReaderIsNotAStall() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (outcome, sent, got) = try rt.block { () async throws(IOError) -> (String, Int, Int) in
            let pair = try await connectedPair()
            let reader = rt.spawn(with: pair.client) { client in
                var buffer = IOBuffer(capacity: 1 << 20)
                var got = 0
                while true {
                    buffer.clear()
                    guard let n = try? await client.read(into: &buffer), n > 0 else { break }
                    got += n
                    // Slow, but never stopped for as long as the limit.
                    try? await Runtime.sleep(for: .milliseconds(5))
                }
                return got
            }
            let server = pair.server
            let chunk = filled(1 << 20)
            let started = cv_now_ns()
            var sent = 0
            let outcome: String
            do throws(IOError) {
                try await Runtime.withWriteStallTimeout(.milliseconds(60)) { () async throws(IOError) in
                    while (cv_now_ns() - started) / 1_000_000 < 300 && sent < 1 << 30 {
                        try await server.write(chunk)
                        sent += chunk.count
                    }
                }
                outcome = "sent past the limit"
            } catch {
                outcome = "\(error)"
            }
            try? server.shutdownWrite()
            return (outcome, sent, await reader.value)
        }
        #expect(outcome == "sent past the limit")
        #expect(got == sent)
    }
}
#endif
