#if os(Linux) || canImport(Darwin)
import CVega
import Testing
@testable import Vega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

private func wallMicros() -> UInt64 {
    var ts = timespec()
    clock_gettime(CLOCK_REALTIME, &ts)
    return UInt64(ts.tv_sec) * 1_000_000 + UInt64(ts.tv_nsec) / 1_000
}

@Suite("TCPStream.read(into:arrival:)")
struct ArrivalTests {
    /// Bytes read late say when they arrived, not when they were read; and
    /// without stamps on the socket a read says nothing.
    @Test(arguments: [IOBackend.readiness, .automatic])
    func aLateReadSaysWhenItsBytesArrived(_ io: IOBackend) throws {
        let rt = Runtime(workers: 2, io: io)
        defer { rt.shutdown() }
        let (sent, stamped, n, unstamped) = try rt.block {
            () async throws(IOError) -> (UInt64, UInt64?, Int, UInt64?) in
            let arrival = UnsafeMutablePointer<ReadArrival>.allocate(capacity: 1)
            arrival.initialize(to: ReadArrival())
            defer { arrival.deallocate() }
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            try listener.setOption(.receiveTimestamps, to: true)
            // The first socket in the system to ask for stamps turns them on
            // from a kernel work item, a moment later: what arrives before
            // that has none.
            try? await Runtime.sleep(for: .milliseconds(50))
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let server = try await listener.accept()
            var out = IOBuffer(capacity: 4)
            _ = out.append("ping")
            let sent = wallMicros()
            try await client.write(out)
            try? await Runtime.sleep(for: .milliseconds(150))
            var buffer = IOBuffer(capacity: 64)
            let n = try await server.read(into: &buffer, arrival: arrival)
            let stamped = arrival.pointee.microseconds

            // The other way, on a socket with no stamps: nothing to say.
            try await server.write(out)
            buffer.clear()
            _ = try await client.read(into: &buffer, arrival: arrival)
            return (sent, stamped, n, arrival.pointee.microseconds)
        }
        #expect(n == 4)
        let stamp = try #require(stamped)
        #expect(stamp + 2_000 >= sent && stamp < sent + 100_000,
                "stamped \(Int64(stamp) - Int64(sent)) µs after it was sent")
        #expect(unstamped == nil)
    }
}
#endif
