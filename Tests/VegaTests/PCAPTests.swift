import Testing
@testable import Vega
@testable import VegaIO
import VegaTest

@Suite("PCAPStream")
struct PCAPTests {
    /// A request and its answer, recorded: the file header, then one
    /// record per read or write, each an IPv4 + TCP segment whose sequence
    /// numbers follow the bytes.
    @Test func recordsBothDirections() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let recorder = PCAPRecorder()
        try rt.block { () async throws(IOError) in
            let pair = duplex()
            let stream = PCAPStream(pair.first, recorder: recorder)
            var out = IOBuffer(capacity: 64)
            _ = out.append("GET / HTTP/1.1\r\n\r\n")
            try await stream.write(out)
            var reply = IOBuffer(capacity: 64)
            _ = reply.append("HTTP/1.1 204 No Content\r\n\r\n")
            try await pair.second.write(reply)
            var into = IOBuffer(capacity: 64)
            _ = try await stream.read(into: &into)
        }
        let file = recorder.bytes
        #expect(Array(file.prefix(4)) == [0xD4, 0xC3, 0xB2, 0xA1])   // magic, little-endian
        #expect(file[20] == 101)                                       // LINKTYPE_RAW
        // First record: 16-byte header, then IPv4 from 10.0.0.1 to 10.0.0.2.
        let first = 24
        let length = Int(file[first + 8]) | Int(file[first + 9]) << 8
        #expect(length == 40 + 18)
        let ip = first + 16
        #expect(file[ip] == 0x45 && file[ip + 9] == 6)
        #expect(Array(file[(ip + 12)..<(ip + 20)]) == [10, 0, 0, 1, 10, 0, 0, 2])
        #expect(PCAPRecorder.checksum(Array(file[ip..<(ip + 20)])) == 0)   // a valid header sums to 0
        // Second record: the answer, the other way, acknowledging the 18 bytes.
        let second = ip + length
        let ip2 = second + 16
        #expect(Array(file[(ip2 + 12)..<(ip2 + 20)]) == [10, 0, 0, 2, 10, 0, 0, 1])
        let ack = file[(ip2 + 28)..<(ip2 + 32)].reduce(0) { $0 << 8 | UInt32($1) }
        #expect(ack == 1 + 18)
        #expect(file.count == second + 16 + 40 + 27)
    }
}
