import Testing
@testable import Vega

/// A RawLock, not a Mutex: ThreadSanitizer doesn't see Mutex on Linux.
private final class Graces: @unchecked Sendable {
    private let lock = RawLock()
    private var list: [Duration] = []

    deinit { lock.destroy() }

    func append(_ grace: Duration) { lock.withLock { list.append(grace) } }
    var all: [Duration] { lock.withLock { list } }
}

@Suite("Quiesce")
struct QuiesceTests {
    /// trigger() shuts everything down at once, with the one grace period,
    /// and run() returns when all have finished.
    @Test func triggerShutsEverythingDown() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let graces = Graces()
        let (seen, accepting) = try rt.block { () async throws -> ([Duration], Bool) in
            let server = try TCPServer.bind(host: "127.0.0.1", port: 0, handler: { _ in })
            let quiesce = Quiesce(gracePeriod: .milliseconds(300), signals: [])
            quiesce.add(server)
            for _ in 0..<2 {
                quiesce.add { grace in
                    try? await Runtime.sleep(for: .milliseconds(20))
                    graces.append(grace)
                }
            }
            let running = rt.spawn { try? await quiesce.run() }
            try? await Runtime.sleep(for: .milliseconds(20))
            quiesce.trigger()
            await running.value
            // Nothing listens on the port any more.
            let accepting = (try? await TCPStream.connect(host: "127.0.0.1", port: server.port)) != nil
            return (graces.all, accepting)
        }
        #expect(seen == [.milliseconds(300), .milliseconds(300)])
        #expect(!accepting)
    }
}
