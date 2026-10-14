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
/// `shards` 0: the sharded body runs here, with threads already running,
/// and its listeners work as in a shard.
@Suite struct InProcessShardTests {
    @Test func runsTheBodyOnceInThisProcess() throws {
        var options = ShardOptions(shards: 0, workersPerShard: 2)
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
        var options = ShardOptions(shards: 0, workersPerShard: 2)
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
}
#endif
#endif
