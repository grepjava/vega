#if os(Linux) || canImport(Darwin)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import Testing
@testable import Vega

/// The supervisor itself is checked end to end by Benchmarks'
/// vega-shard-check (a test process has threads, so it can't fork shards).
@Suite struct ShardLayoutTests {
    @Test func parsesCPULists() {
        #expect(Topology.parseList("0-3,8,10-11") == [0, 1, 2, 3, 8, 10, 11])
        #expect(Topology.parseList("5") == [5])
        #expect(Topology.parseList(" 0-1 \n") == [0, 1])
        #expect(Topology.parseList("") == [])
        #expect(Topology.parseList("3-1") == [])
    }

    @Test func layoutCoversTheCPUs() {
        let all = Topology.cacheDomains().flatMap { $0 }
        #expect(!all.isEmpty)
        #expect(Set(all).count == all.count)
        for shards in 1...max(all.count, 1) {
            let layout = Topology.layout(shards: shards, workersPerShard: nil)
            #expect(layout.count == shards)
            #expect(layout.allSatisfy { !$0.isEmpty })
            #expect(layout.flatMap { $0 }.sorted() == all.sorted())
            let sizes = layout.map(\.count)
            #expect(sizes.max()! - sizes.min()! <= 1 || shards == Topology.cacheDomains().count)
        }
        // More shards than CPUs: they share, one CPU each.
        let many = Topology.layout(shards: all.count + 2, workersPerShard: nil)
        #expect(many.count == all.count + 2)
        #expect(many.allSatisfy { $0.count == 1 })
    }

    @Test func defaultIsOneShardPerCacheDomain() {
        #expect(Topology.layout(shards: nil, workersPerShard: nil) == Topology.cacheDomains())
    }

    #if os(Linux)
    /// Under `taskset`, the layout, the CPU count and default pinning keep
    /// to the CPUs it allows. Checked in a child, on a thread pinned to the
    /// last allowed CPU (any one but the first): the mask is per thread, and
    /// a forked child's only thread is the one `taskset` would have set.
    /// Not under ThreadSanitizer, which a fork of a threaded process
    /// upsets: the child exits with TSan's code, 66.
    @Test(.enabled(if: cv_tsan_enabled() == 0)) func keepsToTheAffinityMask() {
        guard let mask = Topology.affinity(), mask.count > 1 else { return }
        let only = mask.last!
        let pid = fork()
        if pid == 0 {
            let rc = cv_thread_spawn({ raw in
                let only = Int(bitPattern: raw) - 1
                let ok = Topology.affinity() == [only] && cv_cpu_count() == 1
                    && Topology.cacheDomains() == [[only]] && Scheduler.allowedCPUs() == [only]
                    && Topology.layout(shards: 2, workersPerShard: nil) == [[only], [only]]
                _exit(ok ? 0 : 1)
            }, UnsafeMutableRawPointer(bitPattern: only + 1), "affinity", Int32(only))
            guard rc == 0 else { _exit(2) }
            while true { pause() }
        }
        var status: Int32 = 0
        waitpid(pid, &status, 0)
        #expect(status == 0)
    }
    #endif

    /// What `Runtime.sharded`'s "no threads yet" check reads: known on Linux
    /// and Darwin, and more than one in a test process.
    @Test func countsThreads() {
        #expect(cv_thread_count() > 1)
    }

    #if os(Linux) || os(macOS) // sharding is unavailable on iOS and the rest
    @Test func readsTheShardCountFromTheEnvironment() {
        unsetenv("VEGA_SHARDS")
        #expect(Runtime.shardsFromEnvironment() == nil)
        setenv("VEGA_SHARDS", "0", 1)
        #expect(Runtime.shardsFromEnvironment() == 0)
        setenv("VEGA_SHARDS", "4", 1)
        #expect(Runtime.shardsFromEnvironment() == 4)
        unsetenv("VEGA_SHARDS")
    }
    #endif
}

#if os(Linux) || os(macOS)
/// `ShardWatchAction.restartSupervisor`'s trial run and record; the restart
/// itself is checked end to end by Garuda's reload tests.
@Suite(.serialized) struct SupervisorRestartTests {
    @Test func aTrialRunMustExitZero() {
        #expect(SupervisorRestart.probe("/usr/bin/true") == nil)
        #expect(SupervisorRestart.probe("/usr/bin/false")?.contains("exited 1") == true)
        #expect(SupervisorRestart.probe("/nonexistent/vega")?.contains("cannot run") == true)
    }

    @Test func aRecordThatDoesNotFitIsLetGo() {
        var options = ShardConfiguration(shards: 2)
        options.listeners = [.tcp(port: 0)]
        setenv("VEGA_SUPERVISOR_FDS", "-1:8080", 1)
        setenv("VEGA_SUPERVISOR_REGIONS", "", 1)
        setenv("VEGA_SUPERVISOR_SHARDS", "0,0,0", 1)
        #expect(SupervisorRestart.fromEnvironment(options, shards: 2) == nil)
        #expect(getenv("VEGA_SUPERVISOR_SHARDS") == nil && getenv("VEGA_SUPERVISOR_FDS") == nil)

        setenv("VEGA_SUPERVISOR_FDS", "-1:8080", 1)
        setenv("VEGA_SUPERVISOR_REGIONS", "", 1)
        setenv("VEGA_SUPERVISOR_SHARDS", "0,0", 1)
        let fits = SupervisorRestart.fromEnvironment(options, shards: 2)
        #expect(fits?.shards == [0, 0])
        #expect(fits?.listeners.map(\.port) == [8080])
        #expect(SupervisorRestart.fromEnvironment(options, shards: 2) == nil)
    }
}

/// `shards` 0: the sharded body runs here, with threads already running,
/// and its listeners work as in a shard. One at a time: each maps its shared
/// regions into the process-wide table a shard reads them from.
@Suite(.serialized) struct InProcessShardTests {
    @Test func runsTheBodyOnceInThisProcess() throws {
        var options = ShardConfiguration(shards: 0, workersPerShard: 2)
        options.listeners = [.tcp(host: "127.0.0.1", port: 0)]
        var runs = 0
        var replies: [String] = []
        var layout: (index: Int, count: Int, workers: Int) = (-1, -1, -1)
        Runtime.runInProcess(options) { shard in
            runs += 1
            layout = (shard.index, shard.count, shard.runtime.workerCount)
            let port = shard.port()
            replies = (try? shard.runtime.block { () async throws(IOError) -> [String] in
                // Two accept loops on the one listener, as a shard may have.
                var servers: [TCPServer] = []
                for name in ["a", "b"] {
                    servers.append(try TCPServer.serve(try shard.listener()) { conn in
                        var out = IOBuffer(capacity: 8)
                        out.append(name)
                        try? await conn.write(out)
                    })
                }
                var got: [String] = []
                for _ in 0..<4 {
                    let conn = try await TCPStream.connect(to: SocketAddress(host: "127.0.0.1", port: port))
                    var buf = IOBuffer(capacity: 8)
                    while try await conn.read(into: &buf) > 0 {}
                    got.append(buf.string)
                }
                for server in servers { await server.shutdown(gracePeriod: .seconds(1)) }
                return got
            }) ?? []
        }
        #expect(runs == 1)
        #expect(layout.index == 0 && layout.count == 1 && layout.workers == 2)
        #expect(replies.count == 4)
        #expect(replies.allSatisfy { $0 == "a" || $0 == "b" })
    }

    @Test func servesAUnixListener() throws {
        let path = "/tmp/vega-shard-\(getpid()).sock"
        // A socket an earlier run left behind is replaced.
        var err: Int32 = 0
        let stale = cv_unix_listen(path, 1, &err)
        if stale >= 0 { close(stale) }
        defer { unlink(path) }
        var options = ShardConfiguration(shards: 0, workersPerShard: 2)
        options.listeners = [.tcp(host: "127.0.0.1", port: 0), .unix(path: path)]
        var replies: [String] = []
        Runtime.runInProcess(options) { shard in
            replies = (try? shard.runtime.block { () async throws(IOError) -> [String] in
                let listener = try shard.unixListener(1)
                let accepting = shard.runtime.spawn(with: listener) { listener async -> Void in
                    for _ in 0..<2 {
                        guard let conn = try? await listener.accept() else { return }
                        var out = IOBuffer(capacity: 8)
                        out.append("unix")
                        try? await conn.write(out)
                    }
                }
                var got: [String] = []
                for _ in 0..<2 {
                    let conn = try await UnixStream.connect(path: path)
                    var buf = IOBuffer(capacity: 8)
                    while try await conn.read(into: &buf) > 0 {}
                    got.append(buf.string)
                }
                await accepting.value
                return got
            }) ?? []
        }
        #expect(replies == ["unix", "unix"])
    }

    @Test func aUnixListenerServesAsATCPListener() throws {
        let path = "/tmp/vega-shard-tcp-\(getpid()).sock"
        defer { unlink(path) }
        var options = ShardConfiguration(shards: 0, workersPerShard: 2)
        options.listeners = [.unix(path: path)]
        var reply = ""
        Runtime.runInProcess(options) { shard in
            reply = (try? shard.runtime.block { () async throws(IOError) -> String in
                // TCPServer, as a server written for TCP serves it.
                let server = try TCPServer.serve(try shard.listener(0)) { stream in
                    var out = IOBuffer(capacity: 8)
                    out.append("tcp")
                    try? await stream.write(out)
                }
                let conn = try await UnixStream.connect(path: path)
                var buf = IOBuffer(capacity: 8)
                while try await conn.read(into: &buf) > 0 {}
                await server.shutdown(gracePeriod: .seconds(1))
                return buf.string
            }) ?? ""
        }
        #expect(reply == "tcp")
    }

    @Test func shardsHaveTheBlockingPoolTheyAreGiven() {
        var options = ShardConfiguration(shards: 0, workersPerShard: 1)
        options.blockingThreads = 3
        var threads = 0
        Runtime.runInProcess(options) { shard in threads = shard.runtime.scheduler.blocking.maxThreads }
        #expect(threads == 3)
    }

    @Test func sharedRegionsAreZeroedAndSharedWithChildren() {
        var options = ShardConfiguration(shards: 0, workersPerShard: 1)
        options.sharedRegions = [4096, 3 * 65536]
        var sizes: [Int] = []
        var zeroed = false
        var fromChild: UInt64 = 0
        Runtime.runInProcess(options) { shard in
            let a = shard.sharedRegion(0), b = shard.sharedRegion(1)
            sizes = [a.count, b.count]
            zeroed = b.allSatisfy { $0 == 0 }
            // A process forked from here, as a shard is (Darwin's Swift
            // overlay has no fork()), writes; this one sees it.
            let slot = b.baseAddress!.advanced(by: 65536).assumingMemoryBound(to: UInt64.self)
            let pid = cv_supervisor_fork()
            guard pid >= 0 else { return }
            if pid == 0 {
                slot.pointee = 0x5EED
                _exit(0)
            }
            var status: Int32 = 0
            waitpid(pid, &status, 0)
            fromChild = slot.pointee
        }
        #expect(sizes == [4096, 3 * 65536])
        #expect(zeroed)
        #expect(fromChild == 0x5EED)
    }
}
#endif
#endif
