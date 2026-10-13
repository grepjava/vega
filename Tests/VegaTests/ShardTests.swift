#if os(Linux) || canImport(Darwin)
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
}
#endif
