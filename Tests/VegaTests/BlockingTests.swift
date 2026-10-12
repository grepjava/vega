#if os(Linux)
import Glibc
import Synchronization
import Testing
@testable import Vega

private struct Boom: Error, Equatable {}

private final class PoolLog: Sendable {
    let lines = Mutex<[String]>([])
    func append(_ s: String) { lines.withLock { $0.append(s) } }
}

private final class PoolGauge: Sendable {
    let running = Atomic<Int>(0)
    let peak = Atomic<Int>(0)
}

@Suite struct BlockingTests {
    /// The body runs on a pool thread, not a worker, and its result comes back.
    @Test func returnsTheResultOffTheWorkers() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (value, worker) = rt.block {
            await Runtime.blocking { (21 * 2, Runtime.currentWorker) }
        }
        #expect(value == 42)
        #expect(worker == nil)
    }

    @Test func rethrowsTheBodysError() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        #expect(throws: Boom.self) {
            try rt.block { () async throws -> Int in
                try await Runtime.blocking { () throws(Boom) -> Int in throw Boom() }
            }
        }
    }

    /// A blocked pool thread leaves the only worker free for other tasks.
    @Test func blockingDoesNotStallTheWorker() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let order = rt.block { () async -> [String] in
            let log = PoolLog()
            async let slow: Void = Runtime.blocking {
                usleep(200_000)
                log.append("blocking")
            }
            // Runs on the same single worker while the pool thread sleeps.
            await rt.spawn { log.append("task") }.value
            await slow
            return log.lines.withLock { $0 }
        }
        #expect(order == ["task", "blocking"])
    }

    /// Jobs run side by side: 32 sleeps of 100 ms take far less than 3.2 s.
    @Test func runsJobsInParallel() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let start = ContinuousClock.now
        let sum = rt.block { () async -> Int in
            await withTaskGroup(of: Int.self) { group in
                for i in 0..<32 {
                    group.addTask { await Runtime.blocking { usleep(100_000); return i } }
                }
                return await group.reduce(0, +)
            }
        }
        #expect(sum == (0..<32).reduce(0, +))
        #expect(ContinuousClock.now - start < .seconds(1))
        #expect(rt.scheduler.blocking.threadCount <= 32)
    }

    /// With a cap of 2, jobs queue and all still run.
    @Test func queuesBeyondTheThreadCap() {
        let rt = Runtime(workers: 2, blockingThreads: 2)
        defer { rt.shutdown() }
        let g = PoolGauge()
        let done = rt.block { () async -> Int in
            await withTaskGroup(of: Int.self) { group in
                for _ in 0..<40 {
                    group.addTask {
                        await Runtime.blocking {
                            let now = g.running.add(1, ordering: .relaxed).newValue
                            g.peak.max(now, ordering: .relaxed)
                            usleep(1_000)
                            g.running.subtract(1, ordering: .relaxed)
                            return 1
                        }
                    }
                }
                return await group.reduce(0, +)
            }
        }
        #expect(done == 40)
        #expect(g.peak.load(ordering: .relaxed) <= 2)
        #expect(rt.scheduler.blocking.threadCount <= 2)
    }

    /// Idle threads exit after the keep-alive.
    @Test func idleThreadsExit() {
        let rt = Runtime(workers: 1, blockingKeepAlive: .milliseconds(50))
        defer { rt.shutdown() }
        rt.block {
            await withTaskGroup(of: Void.self) { group in
                for _ in 0..<4 { group.addTask { _ = await Runtime.blocking { usleep(20_000) } } }
            }
        }
        #expect(rt.scheduler.blocking.threadCount >= 1)
        let deadline = ContinuousClock.now + .seconds(5)
        while rt.scheduler.blocking.threadCount > 0 && ContinuousClock.now < deadline {
            usleep(10_000)
        }
        #expect(rt.scheduler.blocking.threadCount == 0)
        // And a later job starts a thread again.
        #expect(rt.block { await Runtime.blocking { 7 } } == 7)
    }

    /// Many short jobs from many tasks: every continuation resumes once.
    @Test func manyShortJobs() {
        let rt = Runtime(workers: 4, blockingThreads: 8)
        defer { rt.shutdown() }
        let sum = rt.block { () async -> Int in
            await withTaskGroup(of: Int.self) { group in
                for i in 0..<5_000 { group.addTask { await Runtime.blocking { i } } }
                return await group.reduce(0, +)
            }
        }
        #expect(sum == (0..<5_000).reduce(0, +))
    }

    @Test func worksOffTheRuntime() async {
        #expect(await Runtime.blocking { 5 } == 5)
    }

    /// Numeric hosts are parsed in place; names go through the pool.
    @Test func lookupResolvesNamesOnThePool() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let numeric = try rt.block { () async throws(IOError) -> [SocketAddress] in
            try await SocketAddress.lookup(host: "127.0.0.1", port: 80)
        }
        #expect(numeric.map(\.description) == ["127.0.0.1:80"])
        #expect(rt.scheduler.blocking.threadCount == 0)

        let named = try rt.block { () async throws(IOError) -> [SocketAddress] in
            try await SocketAddress.lookup(host: "localhost", port: 80)
        }
        #expect(!named.isEmpty)
        #expect(named.allSatisfy { $0.port == 80 })
        #expect(rt.scheduler.blocking.threadCount >= 1)
    }

    @Test func lookupOfAnUnknownNameFails() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        #expect(throws: IOError.self) {
            try rt.block { () async throws(IOError) -> [SocketAddress] in
                try await SocketAddress.lookup(host: "no-such-host.invalid", port: 80)
            }
        }
    }

    /// `connect(host:)` with a name resolves it off the workers and connects.
    @Test func connectsByName() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let echoed = try rt.block { () async throws(IOError) -> Int in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            rt.spawn(with: listener) { listener in
                guard let s = try? await listener.accept() else { return }
                var buf = IOBuffer(capacity: 8)
                _ = try? await s.read(into: &buf)
                try? await s.write(buf)
            }
            let client = try await TCPStream.connect(host: "localhost", port: port)
            var out = IOBuffer(capacity: 1)
            out.withUnsafeSpareCapacity { room in
                room.storeBytes(of: 9 as UInt8, as: UInt8.self)
                return 1
            }
            try await client.write(out)
            var buf = IOBuffer(capacity: 8)
            _ = try await client.read(into: &buf)
            return buf.count
        }
        #expect(echoed == 1)
    }
}
#endif
