#if os(Linux) || canImport(Darwin)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// One shard of a sharded server: a process with its own runtime, pinned
/// to its share of the CPUs. See `Runtime.sharded(_:_:)`.
public struct Shard: Sendable {
    /// 0 ..< `count`; the same index across restarts.
    public let index: Int
    public let count: Int
    /// The CPUs its workers are pinned to (or would be, without pinning).
    public let cpus: [Int]
    /// The shard's runtime, started for this process.
    public let runtime: Runtime
}

/// What the supervisor saw, for logging.
public enum ShardEvent: Sendable, Equatable {
    case started(shard: Int, pid: Int32)
    /// A shard process ended: with an exit code, or killed by a signal.
    case exited(shard: Int, pid: Int32, code: Int32?, signal: Int32?)
    /// A crashed shard starts again after `after` (backing off while it
    /// keeps crashing at start).
    case restarting(shard: Int, after: Duration)
    /// SIGTERM or SIGINT: the shards are told to stop.
    case stopping(signal: Int32)
    /// SIGHUP: shards restart one at a time.
    case reloading
}

/// How `Runtime.sharded` lays out and supervises its shards.
public struct ShardOptions: Sendable {
    /// Shard processes; nil: one per last-level cache domain (L3, read from
    /// sysfs on Linux), else one.
    public var shards: Int?
    /// Workers in each shard; nil: as many as the shard has CPUs.
    public var workersPerShard: Int?
    /// Pin each shard's workers to its CPUs, so shards don't share cores.
    public var pinThreads = true
    /// Start a shard again when it crashes (dies by a signal, or exits
    /// non-zero). A shard that exits 0 has finished and isn't restarted.
    public var restartCrashed = true
    /// After SIGTERM or SIGINT, how long shards get to finish before
    /// SIGKILL. A second SIGTERM or SIGINT doesn't wait.
    public var shutdownGracePeriod: Duration = .seconds(30)
    /// Thread name prefix; shard i's runtime is "\(name)\(i)".
    public var name = "vega-s"
    /// Called in the supervisor for each event (synchronously: keep it
    /// short, and don't start tasks or threads there).
    public var onEvent: (@Sendable (ShardEvent) -> Void)?

    public init(shards: Int? = nil, workersPerShard: Int? = nil) {
        self.shards = shards
        self.workersPerShard = workersPerShard
    }
}

extension Runtime {
    /// Run a server as K shard processes, each with its own multi-threaded
    /// runtime on its own CPUs, under a supervisor (the hybrid fault model:
    /// a trap in one shard takes down 1/K of the connections, and the
    /// shard comes back). Each shard binds its own listeners with
    /// `reusePort` so the kernel spreads connections across them.
    ///
    /// ```swift
    /// @main struct Server {
    ///     static func main() {
    ///         Runtime.sharded(ShardOptions(shards: 4)) { shard in
    ///             try! shard.runtime.block {
    ///                 var config = TCPServer.Configuration()
    ///                 config.reusePort = true
    ///                 let server = try TCPServer.bind(port: 8080, configuration: config) { serve($0) }
    ///                 await server.wait()
    ///             }
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// Call it first thing in a synchronous `main`, before any thread or
    /// task exists: shards are forked, and a fork copies only the calling
    /// thread. (On Linux this is checked.) The calling process becomes the
    /// supervisor and never runs `body`: it starts the shards, restarts the
    /// ones that crash, passes SIGTERM or SIGINT on to them (then SIGKILL
    /// after `shutdownGracePeriod`), restarts them one by one on SIGHUP, and
    /// exits when they're all gone: 0 after a signal or when every shard
    /// finished cleanly, 1 when one crashed and isn't restarted.
    ///
    /// In a shard, `body` runs on the process's main thread with the
    /// shard's runtime; when it returns, the shard exits 0. On Linux a
    /// shard gets SIGTERM if the supervisor dies.
    public static func sharded(_ options: ShardOptions = ShardOptions(),
                               _ body: @escaping (Shard) -> Void) -> Never {
        let threads = cv_thread_count()
        precondition(threads <= 1, "Runtime.sharded must run before any thread starts (\(threads) running)")
        let layout = Topology.layout(shards: options.shards, workersPerShard: options.workersPerShard)
        let rc = cv_supervisor_init()
        precondition(rc == 0, "vega: cannot set up the shard supervisor (errno \(rc))")
        var supervisor = Supervisor(options: options, layout: layout, body: body)
        supervisor.run()
    }
}

/// The supervisor's loop. Single-threaded, synchronous: it must never
/// start a thread, or later forks would copy a process in an unknown state.
private struct Supervisor {
    let options: ShardOptions
    let layout: [[Int]]
    let body: (Shard) -> Void

    /// Running shards by pid.
    var running: [Int32: Int] = [:]
    var pids: [Int32?]
    var startedAt: [UInt64]
    /// Crashes in a row that came soon after start, per shard.
    var quickCrashes: [Int]
    /// Shards waiting to restart, and when (cv_now_ns).
    var pending: [Int: UInt64] = [:]
    var stopping = false
    var killAt: UInt64?
    var crashed = false
    /// Rolling restart (SIGHUP): the shard being replaced, and what's left.
    var reloading: Int?
    var reloadQueue: [Int] = []

    init(options: ShardOptions, layout: [[Int]], body: @escaping (Shard) -> Void) {
        self.options = options
        self.layout = layout
        self.body = body
        pids = Array(repeating: nil, count: layout.count)
        startedAt = Array(repeating: 0, count: layout.count)
        quickCrashes = Array(repeating: 0, count: layout.count)
    }

    mutating func run() -> Never {
        for i in layout.indices { start(i) }
        while true {
            if running.isEmpty && pending.isEmpty {
                exit(stopping || !crashed ? 0 : 1)
            }
            let now = cv_now_ns()
            var deadline = pending.values.min() ?? .max
            if let killAt { deadline = min(deadline, killAt) }
            let timeout: Int64 = deadline == .max ? -1 : Int64(clamping: deadline > now ? deadline - now : 0)
            var pid: Int32 = 0, status: Int32 = 0
            switch cv_supervisor_next(timeout, &pid, &status) {
            case 1: exited(pid, status)
            case 2: signalled(status)
            case 0: timers()
            default: break
            }
        }
    }

    mutating func start(_ i: Int) {
        let pid = cv_supervisor_fork()
        if pid == 0 { runShard(i) }
        guard pid > 0 else {
            // Out of processes or memory: try again shortly.
            pending[i] = cv_now_ns() &+ 1_000_000_000
            return
        }
        running[pid] = i
        pids[i] = pid
        startedAt[i] = cv_now_ns()
        options.onEvent?(.started(shard: i, pid: pid))
    }

    func runShard(_ i: Int) -> Never {
        let cpus = layout[i]
        let workers = options.workersPerShard ?? cpus.count
        let rt = Runtime(scheduler: Scheduler(workers: max(workers, 1), name: "\(options.name)\(i)",
                                              pin: options.pinThreads, cpus: cpus))
        body(Shard(index: i, count: layout.count, cpus: cpus, runtime: rt))
        rt.shutdown()
        exit(0)
    }

    mutating func exited(_ pid: Int32, _ status: Int32) {
        guard let i = running.removeValue(forKey: pid) else { return }
        pids[i] = nil
        let code: Int32? = status & 0x7f == 0 ? (status >> 8) & 0xff : nil
        let sig: Int32? = code == nil ? status & 0x7f : nil
        options.onEvent?(.exited(shard: i, pid: pid, code: code, signal: sig))
        if stopping { return }
        if reloading == i {
            // Replaced on purpose: start it again, then move on.
            start(i)
            nextReload()
            return
        }
        guard code != 0 else { return } // finished
        guard options.restartCrashed else {
            crashed = true
            return
        }
        let lived = cv_now_ns() &- startedAt[i]
        quickCrashes[i] = lived < 1_000_000_000 ? quickCrashes[i] + 1 : 0
        // Right away the first time; then 100 ms, doubling to 5 s while it
        // keeps crashing within a second of starting.
        let delay: UInt64 = quickCrashes[i] <= 1 ? 0 : min(100_000_000 << UInt64(min(quickCrashes[i] - 2, 6)),
                                                          5_000_000_000)
        options.onEvent?(.restarting(shard: i, after: .nanoseconds(Int64(delay))))
        if delay == 0 {
            start(i)
        } else {
            pending[i] = cv_now_ns() &+ delay
        }
    }

    mutating func signalled(_ sig: Int32) {
        switch sig {
        case SIGHUP:
            guard !stopping, reloading == nil else { return }
            options.onEvent?(.reloading)
            reloadQueue = Array(layout.indices)
            nextReload()
        default:
            if stopping {
                killAll() // asked twice: don't wait
                return
            }
            stopping = true
            pending.removeAll()
            reloading = nil
            options.onEvent?(.stopping(signal: sig))
            for pid in running.keys { kill(pid, SIGTERM) }
            killAt = cv_now_ns() &+ UInt64(Scheduler.nanoseconds(options.shutdownGracePeriod))
        }
    }

    mutating func nextReload() {
        reloading = nil
        while !reloadQueue.isEmpty {
            let i = reloadQueue.removeFirst()
            if let pid = pids[i] {
                reloading = i
                kill(pid, SIGTERM)
                return
            }
        }
    }

    mutating func timers() {
        let now = cv_now_ns()
        if let killAt, now >= killAt {
            killAll()
            self.killAt = nil
        }
        for (i, due) in pending where due <= now {
            pending[i] = nil
            start(i)
        }
    }

    func killAll() {
        for pid in running.keys { kill(pid, SIGKILL) }
    }
}

/// CPU layout, for sharding.
enum Topology {
    /// CPU lists for `shards` shards (nil: one per cache domain). Each
    /// shard gets whole domains where the counts allow, else an even slice
    /// of the CPUs in domain order.
    static func layout(shards: Int?, workersPerShard: Int?) -> [[Int]] {
        let domains = cacheDomains()
        let count = max(shards ?? domains.count, 1)
        if count == domains.count { return domains }
        let all = domains.flatMap { $0 }
        if count >= all.count {
            return (0..<count).map { [all[$0 % all.count]] }
        }
        // Contiguous slices, the remainder spread over the first ones.
        var out: [[Int]] = []
        var start = 0
        for i in 0..<count {
            let size = all.count / count + (i < all.count % count ? 1 : 0)
            out.append(Array(all[start..<start + size]))
            start += size
        }
        return out
    }

    /// Online CPUs grouped by shared last-level cache: from sysfs on Linux,
    /// by performance level (each a cluster with its own L2) on Darwin; one
    /// group of every CPU otherwise, or if neither says anything.
    static func cacheDomains() -> [[Int]] {
        let fallback = [Array(0..<Int(cv_cpu_count()))]
        #if os(Linux)
        guard let online = read("/sys/devices/system/cpu/online").map(parseList), !online.isEmpty else {
            return fallback
        }
        var seen = Set<Int>()
        var domains: [[Int]] = []
        for cpu in online where !seen.contains(cpu) {
            let shared = lastLevelCache(cpu).map { $0.filter(online.contains) } ?? []
            let group = shared.isEmpty ? [cpu] : shared
            seen.formUnion(group)
            domains.append(group)
        }
        // No cache information at all: one domain, not one per CPU.
        if domains.count == online.count && domains.count > 1 && lastLevelCache(online[0]) == nil {
            return [online]
        }
        return domains
        #elseif canImport(Darwin)
        // Apple silicon: performance and efficiency cores, numbered here in
        // that order (threads can't be pinned on Darwin, so these are counts).
        let levels = sysctlInt("hw.nperflevels") ?? 0
        var domains: [[Int]] = []
        var next = 0
        for level in 0..<levels {
            guard let n = sysctlInt("hw.perflevel\(level).logicalcpu"), n > 0 else { return fallback }
            domains.append(Array(next..<next + n))
            next += n
        }
        return domains.count > 1 && next == fallback[0].count ? domains : fallback
        #else
        return fallback
        #endif
    }

    #if canImport(Darwin)
    private static func sysctlInt(_ name: String) -> Int? {
        var value: Int32 = 0
        var size = MemoryLayout<Int32>.size
        guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
        return Int(value)
    }
    #endif

    /// The CPUs sharing `cpu`'s highest-level cache.
    private static func lastLevelCache(_ cpu: Int) -> [Int]? {
        var best: (level: Int, cpus: [Int])?
        for index in 0..<8 {
            let dir = "/sys/devices/system/cpu/cpu\(cpu)/cache/index\(index)"
            guard let level = read(dir + "/level").flatMap({ Int($0) }) else { break }
            if let list = read(dir + "/shared_cpu_list").map(parseList), level >= (best?.level ?? 0) {
                best = (level, list)
            }
        }
        return best?.cpus
    }

    /// "0-3,8,10-11" → [0, 1, 2, 3, 8, 10, 11].
    static func parseList(_ s: String) -> [Int] {
        var out: [Int] = []
        for part in s.split(separator: ",") {
            let ends = part.split(separator: "-").compactMap { Int($0.trimmingCharacters()) }
            if ends.count == 1 {
                out.append(ends[0])
            } else if ends.count == 2, ends[0] <= ends[1] {
                out.append(contentsOf: ends[0]...ends[1])
            }
        }
        return out
    }

    private static func read(_ path: String) -> String? {
        var buf = [UInt8](repeating: 0, count: 4096)
        let n = buf.withUnsafeMutableBytes { cv_read_small_file(path, $0.baseAddress, $0.count) }
        guard n >= 0 else { return nil }
        return String(decoding: buf[..<n], as: UTF8.self).trimmingCharacters()
    }
}

private extension StringProtocol {
    func trimmingCharacters() -> String {
        var s = Substring(self)
        while let c = s.first, c.isWhitespace { s.removeFirst() }
        while let c = s.last, c.isWhitespace { s.removeLast() }
        return String(s)
    }
}
#endif
