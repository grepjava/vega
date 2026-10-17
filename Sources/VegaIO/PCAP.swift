import Synchronization
import Vega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// Traffic on a stream recorded in pcap format for Wireshark, as NIOExtras'
/// `NIOWritePCAPHandler`: each read and write becomes a TCP segment between
/// two made-up endpoints, so a TLS stream's plaintext, or an in-memory
/// one, can be looked at with the usual tools.
///
/// ```swift
/// let recorder = PCAPRecorder()
/// let stream = PCAPStream(tcp, recorder: recorder)
/// ... use stream ...
/// try await file.write(recorder.take())     // a .pcap file
/// ```
///
/// The capture is raw IPv4 (LINKTYPE_RAW). Segments carry sequence and
/// acknowledgement numbers that follow the bytes, and the IPv4 checksum;
/// the TCP checksum is left 0, which Wireshark accepts unless told to check.
public final class PCAPRecorder: Sendable {
    struct State {
        var bytes: [UInt8]
        /// Bytes so far each way: our sequence number, and the peer's.
        var sent: UInt32 = 1
        var received: UInt32 = 1
    }

    /// The two ends: `local` is the stream's side, `remote` the peer's.
    public let local: (ip: [UInt8], port: UInt16)
    public let remote: (ip: [UInt8], port: UInt16)
    private let state: Mutex<State>

    public init(local: (ip: [UInt8], port: UInt16) = ([10, 0, 0, 1], 50_000),
                remote: (ip: [UInt8], port: UInt16) = ([10, 0, 0, 2], 443)) {
        precondition(local.ip.count == 4 && remote.ip.count == 4, "PCAPRecorder: IPv4 addresses")
        self.local = local
        self.remote = remote
        // The file header: magic, version 2.4, no zone, no accuracy, a
        // 64 KiB snapshot, LINKTYPE_RAW (101).
        var header: [UInt8] = []
        PCAPRecorder.le32(0xA1B2_C3D4, &header)
        PCAPRecorder.le16(2, &header)
        PCAPRecorder.le16(4, &header)
        PCAPRecorder.le32(0, &header)
        PCAPRecorder.le32(0, &header)
        PCAPRecorder.le32(65_535, &header)
        PCAPRecorder.le32(101, &header)
        state = Mutex(State(bytes: header))
    }

    /// The capture so far, file header included, and a fresh one begun
    /// (with its own header) for what comes next.
    public func take() -> [UInt8] {
        state.withLock { s in
            let out = s.bytes
            s.bytes = Array(out.prefix(24))
            return out
        }
    }

    /// The capture so far, left in place.
    public var bytes: [UInt8] { state.withLock { $0.bytes } }

    /// Record `payload` going out (`outbound`) or coming in.
    public func record(_ payload: UnsafeRawBufferPointer, outbound: Bool) {
        // A segment carries at most 64 KiB less its headers: longer ones split.
        var at = 0
        repeat {
            let n = min(payload.count - at, 65_535 - 40)
            segment(UnsafeRawBufferPointer(rebasing: payload[at..<(at + n)]), outbound: outbound)
            at += n
        } while at < payload.count
    }

    private func segment(_ payload: UnsafeRawBufferPointer, outbound: Bool) {
        let wall = Self.wallClock()
        state.withLock { s in
            let (from, to) = outbound ? (local, remote) : (remote, local)
            let seq = outbound ? s.sent : s.received
            let ack = outbound ? s.received : s.sent
            if outbound { s.sent &+= UInt32(payload.count) } else { s.received &+= UInt32(payload.count) }
            let length = 40 + payload.count
            // Record header.
            Self.le32(UInt32(truncatingIfNeeded: wall.seconds), &s.bytes)
            Self.le32(UInt32(truncatingIfNeeded: wall.micros), &s.bytes)
            Self.le32(UInt32(length), &s.bytes)
            Self.le32(UInt32(length), &s.bytes)
            // IPv4.
            var ip: [UInt8] = [0x45, 0, UInt8(length >> 8), UInt8(truncatingIfNeeded: length), 0, 0, 0x40, 0, 64, 6, 0, 0]
            ip += from.ip + to.ip
            let sum = Self.checksum(ip)
            ip[10] = UInt8(sum >> 8)
            ip[11] = UInt8(truncatingIfNeeded: sum)
            s.bytes += ip
            // TCP: ports, sequence, acknowledgement, a 20-byte header with
            // ACK and PSH set, a window, no checksum.
            Self.be16(from.port, &s.bytes)
            Self.be16(to.port, &s.bytes)
            Self.be32(seq, &s.bytes)
            Self.be32(ack, &s.bytes)
            s.bytes += [0x50, 0x18, 0xFF, 0xFF, 0, 0, 0, 0]
            s.bytes += payload
        }
    }

    static func checksum(_ header: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        for i in stride(from: 0, to: header.count, by: 2) { sum += UInt32(header[i]) << 8 | UInt32(header[i + 1]) }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        return ~UInt16(sum)
    }

    /// The time of day, for the records' timestamps.
    static func wallClock() -> (seconds: Int, micros: Int) {
        var ts = timespec()
        _ = timespec_get(&ts, TIME_UTC)
        return (Int(ts.tv_sec), Int(ts.tv_nsec) / 1000)
    }

    static func le16(_ v: UInt16, _ out: inout [UInt8]) { out += [UInt8(truncatingIfNeeded: v), UInt8(v >> 8)] }
    static func le32(_ v: UInt32, _ out: inout [UInt8]) {
        out += [UInt8(truncatingIfNeeded: v), UInt8(truncatingIfNeeded: v >> 8),
                UInt8(truncatingIfNeeded: v >> 16), UInt8(v >> 24)]
    }
    static func be16(_ v: UInt16, _ out: inout [UInt8]) { out += [UInt8(v >> 8), UInt8(truncatingIfNeeded: v)] }
    static func be32(_ v: UInt32, _ out: inout [UInt8]) {
        out += [UInt8(v >> 24), UInt8(truncatingIfNeeded: v >> 16),
                UInt8(truncatingIfNeeded: v >> 8), UInt8(truncatingIfNeeded: v)]
    }
}

/// A stream whose reads and writes a `PCAPRecorder` records.
public struct PCAPStream<Stream: AsyncReader & AsyncWriter & ~Copyable>: ~Copyable, AsyncReader, AsyncWriter {
    public let stream: Stream
    public let recorder: PCAPRecorder

    public init(_ stream: consuming Stream, recorder: PCAPRecorder) {
        self.stream = stream
        self.recorder = recorder
    }

    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        let before = buffer.count
        let n = try await stream.read(into: &buffer)
        if n > 0 {
            buffer.withUnsafeBytes { recorder.record(UnsafeRawBufferPointer(rebasing: $0[before..<(before + n)]), outbound: false) }
        }
        return n
    }

    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        try await stream.write(bytes)
        if bytes.count > 0 { recorder.record(bytes, outbound: true) }
    }

    public consuming func intoStream() -> Stream {
        stream
    }
}

extension PCAPStream: Sendable where Stream: Sendable & ~Copyable {}
