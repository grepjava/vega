import Synchronization
import Testing
@testable import Vega
import VegaIO
import VegaTest

private final class Events: Sendable {
    let all = Mutex<[String]>([])
}

@Suite("DebugStream")
struct DebugStreamTests {
    @Test func reportsReadsWritesAndTheEnd() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let events = Events()
        try rt.block { () async throws(IOError) in
            let pair = duplex()
            let stream = DebugStream(pair.first) { e in events.all.withLock { $0.append("\(e)") } }
            var out = IOBuffer(capacity: 32)
            _ = out.append("ping\r\n")
            try await stream.write(out)
            var reply = IOBuffer(capacity: 32)
            _ = reply.append("po\u{1}ng")
            try await pair.second.write(reply)
            pair.second.shutdownWrite()
            var into = IOBuffer(capacity: 32)
            _ = try await stream.read(into: &into)
            into.clear()
            _ = try await stream.read(into: &into)
        }
        #expect(events.all.withLock { $0 } == ["wrote 6 bytes: ping\\r\\n", "read 5 bytes: po\\x01ng", "end of stream"])
    }
}
