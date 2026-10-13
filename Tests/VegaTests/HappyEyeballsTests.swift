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

private func ms(since start: UInt64) -> UInt64 { (cv_now_ns() - start) / 1_000_000 }

/// Wait (up to a second) for the open-socket count to come back to `n`:
/// cancelled attempts close their fds as they unwind.
private func settle(to n: Int) async throws(IOError) -> Int {
    for _ in 0..<100 where try registered() != n { try? await Runtime.sleep(for: .milliseconds(10)) }
    return try registered()
}

@Suite struct HappyEyeballsTests {
    @Test func interleavesFamiliesIPv6First() throws {
        func a(_ h: String) throws(IOError) -> SocketAddress { try SocketAddress(host: h, port: 1) }
        let input = [try a("10.0.0.1"), try a("10.0.0.2"), try a("::1"), try a("::2"), try a("10.0.0.3")]
        let order = HappyEyeballs.interleave(input).map { $0.description }
        #expect(order == [input[2], input[0], input[3], input[1], input[4]].map { $0.description })
    }

    /// A listener on IPv4 only, IPv6 tried first: ::1 refuses at once, so
    /// IPv4 follows without waiting out the delay.
    @Test func fallsBackFromIPv6Quickly() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (elapsed, family, leaked) = try rt.block { () async throws(IOError) -> (UInt64, Bool, Int) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            let before = try registered()
            let start = cv_now_ns()
            let stream = try await TCPStream.connect(
                to: [try SocketAddress(host: "127.0.0.1", port: port), try SocketAddress(host: "::1", port: port)],
                attemptDelay: .seconds(2))
            let elapsed = ms(since: start)
            return (elapsed, try stream.peerAddress.isIPv6, try await settle(to: before + 1) - (before + 1))
        }
        #expect(!family) // connected over IPv4
        #if os(Windows)
        // Windows retries a SYN that met a reset for about 2 s before it
        // calls the port refused; the delay (2 s) runs out about then too.
        #expect(elapsed < 3000, "took \(elapsed) ms")
        #else
        #expect(elapsed < 500, "took \(elapsed) ms")
        #endif
        #expect(leaked == 0)
    }

    /// The first address never answers (TEST-NET-1 is unroutable): the
    /// second starts after the attempt delay and wins, long before a
    /// kernel connect timeout, and the stuck attempt is cancelled.
    @Test func blackHoledAddressLosesAfterTheDelay() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (elapsed, leaked) = try rt.block { () async throws(IOError) -> (UInt64, Int) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            let before = try registered()
            let start = cv_now_ns()
            // Same family, so the order given is the order tried.
            let stream = try await TCPStream.connect(
                to: [try SocketAddress(host: "192.0.2.1", port: port), try SocketAddress(host: "127.0.0.1", port: port)],
                attemptDelay: .milliseconds(150))
            let elapsed = ms(since: start)
            #expect(try stream.peerAddress.port == port)
            return (elapsed, try await settle(to: before + 1) - (before + 1))
        }
        // Without a route the first fails at once and the second wins
        // sooner; either way well inside a second.
        #expect(elapsed < 1_000, "took \(elapsed) ms")
        #expect(leaked == 0)
    }

    /// Cancelling the caller cancels every attempt, and none leaks.
    @Test func cancellingTheCallerCancelsEveryAttempt() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (outcome, elapsed, leaked) = try rt.block { () async throws(IOError) -> (IOError?, UInt64, Int) in
            let before = try registered()
            let blackHoles = [try SocketAddress(host: "192.0.2.1", port: 9), try SocketAddress(host: "192.0.2.2", port: 9),
                              try SocketAddress(host: "192.0.2.3", port: 9)]
            let start = cv_now_ns()
            let attempt = rt.spawn { () async -> IOError? in
                do throws(IOError) {
                    _ = try await TCPStream.connect(to: blackHoles, attemptDelay: .milliseconds(100))
                    return nil
                } catch {
                    return error
                }
            }
            try? await Runtime.sleep(for: .milliseconds(250)) // two or three attempts in flight
            attempt.cancel()
            let outcome = await attempt.value
            let elapsed = ms(since: start)
            return (outcome, elapsed, try await settle(to: before) - before)
        }
        // Without a route every attempt fails at once instead: then the
        // last failure is the outcome, and there is nothing to cancel.
        if let outcome, outcome != .cancelled {
            #expect(outcome.code == ENETUNREACH || outcome.code == EHOSTUNREACH, "\(outcome)")
        } else {
            #expect(outcome == .cancelled)
        }
        #expect(elapsed < 1_000, "took \(elapsed) ms")
        #expect(leaked == 0)
    }

    /// Every address refuses: the last failure is thrown.
    @Test func allFailingThrowsTheLastError() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let error = try rt.block { () async throws(IOError) -> IOError? in
            // A port nothing listens on: bind one, note it, close it.
            let port = try TCPListener.bind(host: "127.0.0.1", port: 0).localPort
            do throws(IOError) {
                _ = try await TCPStream.connect(
                    to: [try SocketAddress(host: "127.0.0.1", port: port), try SocketAddress(host: "::1", port: port)])
                return nil
            } catch {
                return error
            }
        }
        #expect(error == .connectionRefused)
    }

    /// One address: a plain connect, as before.
    @Test func hostNameStillConnects() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let ok = try rt.block { () async throws(IOError) -> Bool in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let stream = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            return try stream.peerAddress.port == listener.localPort
        }
        #expect(ok)
    }
}
#endif
