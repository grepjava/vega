#if os(Linux) || canImport(Darwin)
import CVega
import Testing
@testable import Vega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// Whether this process may open the socket: ping sockets need a group in
/// net.ipv4.ping_group_range on Linux, raw ones CAP_NET_RAW.
private func canOpen(ping: Bool) -> Bool {
    var err: Int32 = 0
    let fd = cv_raw_socket(0, ping ? 1 : 0, 1, &err)
    guard fd >= 0 else { return false }
    close(fd)
    return true
}

private let pingAllowed = canOpen(ping: true)
private let rawAllowed = canOpen(ping: false)

/// An ICMP echo request: type 8, code 0, checksum, identifier, sequence,
/// then `payload`.
private func echoRequest(id: UInt16, sequence: UInt16, payload: [UInt8]) -> IOBuffer {
    var packet: [UInt8] = [8, 0, 0, 0, UInt8(id >> 8), UInt8(id & 0xFF),
                           UInt8(sequence >> 8), UInt8(sequence & 0xFF)] + payload
    var sum: UInt32 = 0
    var i = 0
    while i < packet.count {
        sum += UInt32(packet[i]) << 8 | (i + 1 < packet.count ? UInt32(packet[i + 1]) : 0)
        i += 2
    }
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
    let check = ~UInt16(sum)
    packet[2] = UInt8(check >> 8)
    packet[3] = UInt8(check & 0xFF)
    var b = IOBuffer(capacity: packet.count)
    _ = packet.withUnsafeBytes { b.append($0) }
    return b
}

/// The ICMP message in a received packet: past the IPv4 header where there
/// is one (a raw socket's, or a Darwin ping socket's).
private func icmpMessage(_ packet: [UInt8]) -> ArraySlice<UInt8> {
    guard let first = packet.first, first >> 4 == 4 else { return packet[...] }
    let headerLength = Int(first & 0x0F) * 4
    return packet[headerLength...]
}

/// Send one echo request to 127.0.0.1 and wait for its reply: the reply's
/// payload. Other ICMP (a raw socket sees our own request go by) is passed
/// over.
private func ping(_ socket: borrowing RawSocket, payload: [UInt8]) async throws(IOError) -> [UInt8] {
    let to = SocketAddress(numericHost: "127.0.0.1", port: 0)!
    try await socket.send(echoRequest(id: 0x5645, sequence: 1, payload: payload), to: to)
    return try await Runtime.withIOTimeout(for: .seconds(10)) { () async throws(IOError) -> [UInt8] in
        var into = IOBuffer(capacity: 1500)
        while true {
            into.clear()
            let (n, from) = try await socket.receiveFrom(into: &into)
            let message = icmpMessage(into.withUnsafeBytes { Array($0[0..<n]) })
            // Type 0 is an echo reply.
            if message.count >= 8, message.first == 0, from.host == "127.0.0.1" {
                return Array(message.dropFirst(8))
            }
        }
    }
}

@Suite("RawSocket")
struct RawSocketTests {
    /// The unprivileged ICMP socket: an echo to 127.0.0.1 is answered.
    @Test(.enabled(if: pingAllowed, "ping sockets not allowed here (net.ipv4.ping_group_range)"))
    func pingSocketGetsAnEchoReply() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let payload = Array("vega ping".utf8)
        let reply = try rt.block { () async throws(IOError) -> [UInt8] in
            let socket = try RawSocket.ping(.ipv4)
            return try await ping(socket, payload: payload)
        }
        #expect(reply == payload)
    }

    /// Without CAP_NET_RAW, opening SOCK_RAW is an error to handle, not a
    /// crash; with it, the socket opens.
    @Test func rawOpenFailsCleanlyWithoutPrivilege() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let failure = try rt.block { () async throws(IOError) -> IOError? in
            do throws(IOError) {
                _ = try RawSocket.open(.ipv4, protocol: 1)
                return nil
            } catch {
                return error
            }
        }
        if rawAllowed {
            #expect(failure == nil)
        } else {
            #expect(failure?.code == EPERM || failure?.code == EACCES)
        }
    }

    /// A SOCK_RAW ICMP socket: the echo reply comes back with its IPv4
    /// header, and IP_HDRINCL can be set.
    @Test(.enabled(if: rawAllowed, "SOCK_RAW needs root or CAP_NET_RAW"))
    func rawSocketGetsAnEchoReply() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let payload = Array("vega raw".utf8)
        let (reply, headerIncluded) = try rt.block { () async throws(IOError) -> ([UInt8], Int) in
            let socket = try RawSocket.open(.ipv4, protocol: 1)
            let reply = try await ping(socket, payload: payload)
            let probe = try RawSocket.open(.ipv4, protocol: 255)
            try probe.setOption(.headerIncluded, to: true)
            return (reply, try probe.option(.headerIncluded))
        }
        #expect(reply == payload)
        #expect(headerIncluded == 1)
    }
}
#endif
