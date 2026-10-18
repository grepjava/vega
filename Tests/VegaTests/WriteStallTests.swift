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
    /// one write whole before the limit is up. The limit leaves room for
    /// a loaded machine: on Network.framework (iOS) a write goes in 64 KiB
    /// slices, which an idle simulator took up to 125 ms over. A machine
    /// busy enough can still stop the reader itself for the limit (the full
    /// iOS suite in parallel did, past 500 ms), and then the write giving up
    /// is right: that passes only when the reader did go the limit without
    /// a read.
    @Test func aSlowReaderIsNotAStall() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let limit = 500
        let (outcome, sent, (got, gap)) = try rt.block { () async throws(IOError) -> (String, Int, (Int, Int)) in
            let pair = try await connectedPair()
            let reader = rt.spawn(with: pair.client) { client in
                var buffer = IOBuffer(capacity: 1 << 20)
                var got = 0
                // The longest the reader went between reads, in ms.
                var gap = 0, last = cv_now_ns()
                while true {
                    buffer.clear()
                    guard let n = try? await client.read(into: &buffer), n > 0 else { break }
                    got += n
                    let now = cv_now_ns()
                    gap = max(gap, Int((now - last) / 1_000_000))
                    last = now
                    // Slow, but never stopped for as long as the limit.
                    try? await Runtime.sleep(for: .milliseconds(5))
                }
                return (got, gap)
            }
            let server = pair.server
            let chunk = filled(1 << 20)
            let started = cv_now_ns()
            var sent = 0
            let outcome: String
            do throws(IOError) {
                try await Runtime.withWriteStallTimeout(.milliseconds(limit)) { () async throws(IOError) in
                    while (cv_now_ns() - started) / 1_000_000 < 2000 && sent < 1 << 30 {
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
        if outcome == "sent past the limit" {
            #expect(got == sent)
        } else {
            // Given up on: only fair if the reader really stopped that long.
            #expect(gap >= limit, "write gave up (\(outcome)) though the reader's longest gap was \(gap) ms")
            #expect(got >= sent)
        }
    }
}
#endif
