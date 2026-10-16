#if os(Linux) || canImport(Darwin)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// One shard of a sharded server: a process with its own runtime, pinned
/// to its share of the CPUs. See `Runtime.sharded(_:_:)`.
@available(iOS, unavailable)
@available(tvOS, unavailable)
@available(watchOS, unavailable)
@available(visionOS, unavailable)
public struct Shard: Sendable {
    /// 0 ..< `count`; the same index across restarts.
    public let index: Int
    public let count: Int
    /// The CPUs its workers are pinned to (or would be, without pinning).
    public let cpus: [Int]
    /// The shard's runtime, started for this process.
    public let runtime: Runtime
    let listeners: [PreparedListener]

    /// A listener for `ShardOptions.listeners[index]`, on this shard's
    /// runtime: the supervisor's shared socket, or one bound here with
    /// `reusePort` (see `ShardListenerMode`). Each call gives a new one, for
    /// several accept loops. Call from a task on the shard's runtime.
    ///
    /// A Unix listener is given as a `TCPListener` too, so a server written
    /// for TCP -- `TCPServer`, and everything it hands connections to --
    /// serves it unchanged: its connections read, write and close as TCP
    /// ones do, have no TCP options to set, and name no peer address but the
    /// socket's. `unixListener(_:)` gives it as itself.
    public func listener(_ index: Int = 0) throws(IOError) -> TCPListener {
        precondition(listeners.indices.contains(index), "no ShardOptions.listeners[\(index)]")
        let l = listeners[index]
        let driver = try IODriver.current()
        guard l.shared >= 0 else {
            return try TCPListener.bind(host: l.host, port: l.port, backlog: l.backlog, reusePort: true)
        }
        let fd = fcntl(l.shared, F_DUPFD_CLOEXEC, 0)
        guard fd >= 0 else { throw IOError(code: errno) }
        return TCPListener(reg: try IORegistration(fd: fd, driver: driver))
    }

    /// A listener for the Unix socket `ShardOptions.listeners[index]`, on
    /// this shard's runtime: the supervisor's socket, which every shard
    /// shares. Each call gives a new one, for several accept loops. Call
    /// from a task on the shard's runtime.
    public func unixListener(_ index: Int) throws(IOError) -> UnixListener {
        precondition(listeners.indices.contains(index), "no ShardOptions.listeners[\(index)]")
        let l = listeners[index]
        precondition(l.path != nil && l.shared >= 0, "ShardOptions.listeners[\(index)] is not a Unix listener")
        let driver = try IODriver.current()
        let fd = fcntl(l.shared, F_DUPFD_CLOEXEC, 0)
        guard fd >= 0 else { throw IOError(code: errno) }
        return UnixListener(reg: try IORegistration(fd: fd, driver: driver))
    }

    /// `ShardOptions.sharedRegions[index]`, mapped into this shard: the same
    /// memory in every shard. At a page-aligned address that differs from
    /// shard to shard under exec launch, so it holds offsets, never pointers.
    public func sharedRegion(_ index: Int) -> UnsafeMutableRawBufferPointer {
        let regions = SharedRegions.mapped
        precondition(regions.indices.contains(index), "no ShardOptions.sharedRegions[\(index)]")
        let r = regions[index]
        return UnsafeMutableRawBufferPointer(start: UnsafeMutableRawPointer(bitPattern: r.base), count: r.size)
    }

    /// The port of `ShardOptions.listeners[index]` (the one picked, for port 0).
    public func port(_ index: Int = 0) -> Int { listeners[index].port }
}

/// A TCP listener the shards share (`ShardOptions.listeners`).
@available(iOS, unavailable)
@available(tvOS, unavailable)
@available(watchOS, unavailable)
@available(visionOS, unavailable)
public struct ShardListener: Sendable, Hashable {
    public var host: String
    /// 0 picks a free port, the same for every shard.
    public var port: Int
    public var backlog: Int
    /// A Unix socket's path, for a Unix listener; nil for TCP.
    public var path: String?

    public static func tcp(host: String = "", port: Int, backlog: Int = 1024) -> ShardListener {
        ShardListener(host: host, port: port, backlog: backlog, path: nil)
    }

    /// A Unix stream socket at `path`, taken in a shard with
    /// `Shard.unixListener(_:)`. The supervisor binds it before the first
    /// shard starts, whatever the `ShardListenerMode` (Unix sockets have no
    /// `SO_REUSEPORT` to spread connections with), and every shard accepts
    /// on it. A socket left at `path` by an earlier run is removed first;
    /// any other file there is an error. The socket is left behind when the
    /// server exits, as `UnixListener` leaves its own.
    public static func unix(path: String, backlog: Int = 1024) -> ShardListener {
        ShardListener(host: "", port: 0, backlog: backlog, path: path)
    }
}

/// How shards share their listeners.
@available(iOS, unavailable)
@available(tvOS, unavailable)
@available(watchOS, unavailable)
@available(visionOS, unavailable)
public enum ShardListenerMode: Sendable, Hashable {
    /// `.perShard` on Linux, `.shared` elsewhere.
    case automatic
    /// The supervisor binds each listener before starting shards; every shard
    /// accepts on that one socket, and a connection goes to a shard waiting
    /// in accept. Balances by who's free; works everywhere.
    case shared
    /// Each shard binds its own `SO_REUSEPORT` socket and the kernel hashes
    /// connections across them. On Linux that spreads them evenly; Darwin
    /// sends everything to the newest socket, so `.automatic` avoids it
    /// there.
    case perShard

    var resolved: ShardListenerMode {
        guard self == .automatic else { return self }
        #if os(Linux)
        return .perShard
        #else
        return .shared
        #endif
    }
}

/// How the supervisor starts a shard process.
@available(iOS, unavailable)
@available(tvOS, unavailable)
@available(watchOS, unavailable)
@available(visionOS, unavailable)
public enum ShardLaunch: Sendable, Hashable {
    /// `.fork` on Linux, `.exec` elsewhere.
    case automatic
    /// `fork` alone: the shard carries on from the `Runtime.sharded` call
    /// with the supervisor's memory. Fast, but only safe where the system
    /// libraries survive a fork without exec (Linux): on Darwin, os_log and
    /// libdispatch state the Swift runtime touches is gone in the child, and
    /// shards crash at random.
    case fork
    /// `posix_spawn` of the same executable with the same arguments: the
    /// shard runs `main` again, and its `Runtime.sharded` call (told by the
    /// environment which shard it is) runs `body` right away. Code before
    /// that call runs in every shard, so it must do the same thing each time
    /// and have no side effects. Listeners and ports carry over.
    case exec

    var resolved: ShardLaunch {
        guard self == .automatic else { return self }
        #if os(Linux)
        return .fork
        #else
        return .exec
        #endif
    }
}

/// `ShardOptions.sharedRegions` as this process has them mapped. Set once,
/// before any thread starts (by the supervisor, or by an exec'd shard as it
/// starts), and only read after: forked shards inherit it with the mappings.
@available(iOS, unavailable)
@available(tvOS, unavailable)
@available(watchOS, unavailable)
@available(visionOS, unavailable)
enum SharedRegions {
    struct Region: Sendable {
        let fd: Int32
        let size: Int
        let base: UInt
    }

    nonisolated(unsafe) static var mapped: [Region] = []

    /// Make and map them. A failure ends the process: nothing has started.
    static func prepare(_ sizes: [Int]) {
        mapped = sizes.map { size in
            precondition(size > 0, "a shared region needs a size")
            var err: Int32 = 0
            let fd = cv_shared_memory(size, &err)
            guard fd >= 0 else { fail("cannot make a shared region of \(size) bytes: \(IOError(code: err))") }
            return Region(fd: fd, size: size, base: map(fd, size))
        }
    }

    /// Map the regions an exec'd shard was handed.
    static func adopt(_ regions: [(Int32, Int)]) {
        mapped = regions.map { fd, size in
            _ = fcntl(fd, F_SETFD, FD_CLOEXEC) // not for the shard's children
            return Region(fd: fd, size: size, base: map(fd, size))
        }
    }

    private static func map(_ fd: Int32, _ size: Int) -> UInt {
        guard let p = mmap(nil, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0),
              p != UnsafeMutableRawPointer(bitPattern: -1) else {
            fail("cannot map a shared region of \(size) bytes: \(IOError(code: errno))")
        }
        return UInt(bitPattern: p)
    }

    private static func fail(_ message: String) -> Never {
        let msg = "vega: \(message)\n"
        _ = msg.withCString { write(2, $0, strlen($0)) }
        exit(1)
    }
}

/// A listener as the supervisor set it up.
@available(iOS, unavailable)
@available(tvOS, unavailable)
@available(watchOS, unavailable)
@available(visionOS, unavailable)
struct PreparedListener: Sendable {
    let host: String
    let port: Int
    let backlog: Int
    /// A Unix listener's path; nil for TCP.
    var path: String? = nil
    /// The listening socket shards adopt, or -1 when each binds its own.
    let shared: Int32
}

/// What the supervisor saw, for logging.
@available(iOS, unavailable)
@available(tvOS, unavailable)
@available(watchOS, unavailable)
@available(visionOS, unavailable)
public enum ShardEvent: Sendable, Equatable {
    case started(shard: Int, pid: Int32)
    /// A shard process ended: with an exit code, or killed by a signal.
    case exited(shard: Int, pid: Int32, code: Int32?, signal: Int32?)
    /// A crashed shard starts again after `after` (backing off while it
    /// keeps crashing at start).
    case restarting(shard: Int, after: Duration)
    /// SIGTERM, SIGINT or SIGQUIT: the shards are told to stop.
    case stopping(signal: Int32)
    /// SIGHUP, or `ShardWatchAction.reload`: shards restart one at a time.
    case reloading
    /// `ShardWatchAction.restartSupervisor`: the executable ran as far as
    /// `Runtime.sharded`, and the supervisor is about to become it. In the
    /// new image each shard the old one left is reported `started` again,
    /// then all of them are replaced, as on `reloading`.
    case restartingSupervisor
    /// The supervisor did not restart, and carries on as it was: the
    /// executable did not run, or could not be exec'd.
    case supervisorRestartFailed(reason: String)
}

/// What `ShardOptions.watch` asks of the supervisor.
@available(iOS, unavailable)
@available(tvOS, unavailable)
@available(watchOS, unavailable)
@available(visionOS, unavailable)
public enum ShardWatchAction: Sendable, Hashable {
    /// Nothing to do.
    case none
    /// Restart the shards one at a time, as SIGHUP does: for something they
    /// read as they start, such as a certificate, that has changed.
    case reload
    /// Restart the supervisor on its executable, rebuilt since it started:
    /// it execs the file it was started from, keeping its pid, its listeners,
    /// its shared regions and its shards, and the new image replaces the
    /// shards one at a time with ones that run the new code. The executable
    /// is first run as far as `Runtime.sharded` with the same arguments; if
    /// it does not get there, and exit 0, within five seconds, nothing
    /// changes (`ShardEvent.supervisorRestartFailed`). Listeners are not
    /// dropped, so no connection is refused.
    case restartSupervisor
}

/// How `Runtime.sharded` lays out and supervises its shards.
@available(iOS, unavailable)
@available(tvOS, unavailable)
@available(watchOS, unavailable)
@available(visionOS, unavailable)
public struct ShardOptions: Sendable {
    /// Shard processes; nil: one per last-level cache domain (L3, read from
    /// sysfs on Linux), else one. 0: no shards, `body` runs once in this
    /// process (see `Runtime.sharded`). The environment variable
    /// `VEGA_SHARDS`, when set, overrides it.
    public var shards: Int?
    /// Workers in each shard; nil: as many as the shard has CPUs.
    public var workersPerShard: Int?
    /// Pin each shard's workers to its CPUs, so shards don't share cores.
    public var pinThreads = true
    /// Most threads each shard's `Runtime.blocking` runs at once.
    public var blockingThreads = 512
    /// Most work each shard's `Runtime.blocking` lets wait for one of those
    /// threads before refusing more with `BlockingQueueFull`; nil: no bound.
    public var blockingQueue: Int? = nil
    /// Start a shard again when it crashes (dies by a signal, or exits
    /// non-zero). A shard that exits 0 has finished and isn't restarted.
    public var restartCrashed = true
    /// After SIGTERM, SIGINT or SIGQUIT, how long shards get to finish
    /// before SIGKILL.
    ///
    /// The supervisor passes SIGTERM on as SIGTERM, and SIGINT or SIGQUIT
    /// on as SIGINT, so a shard can tell an orderly stop, which it may
    /// put off for a while (to fail a load balancer's health check
    /// first, say), from one that's wanted now. SIGINT or SIGQUIT after
    /// SIGTERM is passed on too; the same signal twice doesn't wait, and
    /// the shards are killed. A rolling restart (SIGHUP) stops each shard
    /// with SIGINT: its replacement is about to serve.
    public var shutdownGracePeriod: Duration = .seconds(30)
    /// Listeners the shards serve, set up by the supervisor before the
    /// first shard starts; a shard takes each with `Shard.listener(_:)`.
    public var listeners: [ShardListener] = []
    public var listenerMode: ShardListenerMode = .automatic
    /// How shard processes start (see `ShardLaunch`).
    public var launch: ShardLaunch = .automatic
    /// Shared memory every shard maps, by size in bytes: zeroed when the
    /// server starts, the same bytes in every shard, and kept across shard
    /// restarts (a restarted shard finds what the others wrote). For state
    /// the shards share without a round trip: counters, a rate limiter's
    /// buckets, a cache. A shard takes region i with `Shard.sharedRegion(_:)`.
    /// Only atomics and the like are safe in it: shards are processes, and
    /// a pointer from one means nothing in another.
    public var sharedRegions: [Int] = []
    /// Thread name prefix; shard i's runtime is "\(name)\(i)".
    public var name = "vega-s"
    /// Called in the supervisor for each event (synchronously: keep it
    /// short, and don't start tasks or threads there).
    public var onEvent: (@Sendable (ShardEvent) -> Void)?
    /// Called in the supervisor every `watchInterval` while it is not
    /// stopping (synchronously, as `onEvent` is): for a development server
    /// to notice a rebuilt executable or a changed file, and say what is to
    /// be done about it.
    public var watch: (@Sendable () -> ShardWatchAction)?
    public var watchInterval: Duration = .milliseconds(100)

    public init(shards: Int? = nil, workersPerShard: Int? = nil) {
        self.shards = shards
        self.workersPerShard = workersPerShard
    }
}

// Apps on iOS, tvOS, watchOS and visionOS may not fork or spawn processes.
@available(iOS, unavailable)
@available(tvOS, unavailable)
@available(watchOS, unavailable)
@available(visionOS, unavailable)
extension Runtime {
    /// Run a server as K shard processes, each with its own multi-threaded
    /// runtime on its own CPUs, under a supervisor (the hybrid fault model:
    /// a trap in one shard takes down 1/K of the connections, and the
    /// shard comes back). Declare the server's ports in
    /// `ShardOptions.listeners`, and each shard takes them with
    /// `Shard.listener(_:)` (see `ShardListenerMode` for how they're shared).
    ///
    /// ```swift
    /// @main struct Server {
    ///     static func main() {
    ///         var options = ShardOptions(shards: 4)
    ///         options.listeners = [.tcp(port: 8080)]
    ///         Runtime.sharded(options) { shard in
    ///             try! shard.runtime.block { () async throws(IOError) in
    ///                 let server = try TCPServer.serve(try shard.listener()) { await serve($0) }
    ///                 await server.wait()
    ///             }
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// Call it first thing in a synchronous `main`, before any thread or
    /// task exists: a forked shard copies only the calling thread (this is
    /// checked). With `ShardLaunch.exec` (the default on Darwin) each shard
    /// runs `main` again up to this call, which then runs `body` at once
    /// with the options and closure as that run builds them: code before
    /// the call must be deterministic and free of side effects. Events and
    /// restarts are the same in both modes. The calling process becomes the
    /// supervisor and never runs `body`: it starts the shards, restarts the
    /// ones that crash, passes SIGTERM, SIGINT or SIGQUIT on to them (then
    /// SIGKILL after `shutdownGracePeriod`, which says how), restarts them
    /// one by one on SIGHUP, and
    /// exits when they're all gone: 0 after a signal or when every shard
    /// finished cleanly, 1 when one crashed and isn't restarted.
    ///
    /// In a shard, `body` runs on the process's main thread with the
    /// shard's runtime; when it returns, the shard exits 0. A shard gets
    /// SIGTERM if the supervisor dies. On Linux the shard's runtime is its
    /// process's global executor, as ``installGlobal(workers:name:)`` makes
    /// one: a plain `Task {}` in a shard runs on its workers too, and no
    /// task needs an executor preference to stay there.
    ///
    /// With `shards` 0 (or `VEGA_SHARDS=0` in the environment, which
    /// overrides `shards`), there is no supervisor and no shard process:
    /// `body` runs once, in this process, as shard 0 of 1, with a plain
    /// multi-threaded runtime (`workersPerShard` workers, else one per CPU,
    /// never pinned) and the listeners bound here. The same `main` then
    /// serves as one process or as K shards, chosen at deploy time. Nothing
    /// restarts it and no signal is handled for it; `Runtime.signals` in
    /// `body` works as in a shard. It may be called after threads exist.
    /// When `body` returns, the process exits 0.
    public static func sharded(_ options: ShardOptions = ShardOptions(),
                               _ body: @escaping (Shard) -> Void) -> Never {
        // A supervisor trying a rebuilt executable: it runs this far. No
        // exit handler runs: they are the real server's.
        if getenv(SupervisorRestart.probeKey) != nil { _exit(0) }
        if let launched = ExecShard.fromEnvironment(options) {
            Supervisor.runShard(options, launched.index, count: launched.count, cpus: launched.cpus,
                                listeners: launched.listeners, body: body)
        }
        var options = options
        if let shards = shardsFromEnvironment() { options.shards = shards }
        if options.shards == 0 {
            runInProcess(options, body)
            exit(0)
        }
        let threads = cv_thread_count()
        precondition(threads <= 1, "Runtime.sharded must run before any thread starts (\(threads) running)")
        let layout = Topology.layout(shards: options.shards, workersPerShard: options.workersPerShard)
        // Exec'd by a supervisor before it, on a rebuilt executable: its
        // listeners, regions and shards are this one's.
        let restarted = SupervisorRestart.fromEnvironment(options, shards: layout.count)
        if let restarted {
            SharedRegions.adopt(restarted.regions)
        } else {
            SharedRegions.prepare(options.sharedRegions)
        }
        let rc = cv_supervisor_init()
        precondition(rc == 0, "vega: cannot set up the shard supervisor (errno \(rc))")
        if restarted != nil { cv_supervisor_restarted() }
        let listeners = restarted?.listeners ?? prepareListeners(options)
        var supervisor = Supervisor(options: options, layout: layout, listeners: listeners, body: body)
        supervisor.run(adopting: restarted?.shards)
    }

    /// The path of this process's executable, or nil where it cannot be
    /// found. Read it before the file can change: once it is replaced, the
    /// path may name the old file as deleted (Linux).
    public static var executablePath: String? {
        var path = [CChar](repeating: 0, count: 4096)
        guard cv_self_exe(&path, Int32(path.count)) == 0 else { return nil }
        return String(cString: path)
    }

    /// `VEGA_SHARDS`: a shard count, or nil when unset. Anything but a
    /// count ends the process.
    static func shardsFromEnvironment() -> Int? {
        guard let raw = getenv("VEGA_SHARDS") else { return nil }
        let text = String(cString: raw)
        guard let shards = Int(text), shards >= 0 else {
            let msg = "vega: VEGA_SHARDS=\(text) is not a shard count (0 runs in-process)\n"
            _ = msg.withCString { write(2, $0, strlen($0)) }
            exit(1)
        }
        return shards
    }

    /// `shards` 0: `body` as shard 0 of 1 on a runtime of this process,
    /// with every listener bound here once and shared by its `listener()`
    /// calls. Returns when `body` does, with the runtime shut down.
    static func runInProcess(_ options: ShardOptions, _ body: (Shard) -> Void) {
        let cpus = Topology.cacheDomains().flatMap { $0 }
        let workers = options.workersPerShard ?? Int(cv_cpu_count())
        var local = options
        local.listenerMode = .shared
        let listeners = prepareListeners(local)
        SharedRegions.prepare(options.sharedRegions)
        let rt = Runtime(scheduler: Scheduler(workers: max(workers, 1), name: "\(options.name)0", pin: false,
                                              blockingThreads: max(options.blockingThreads, 1),
                                              blockingQueue: options.blockingQueue))
        body(Shard(index: 0, count: 1, cpus: cpus, runtime: rt, listeners: listeners))
        rt.shutdown()
        for l in listeners where l.shared >= 0 { close(l.shared) }
    }

    /// Bind the shared listeners, or hold the ports of per-shard ones that
    /// ask for port 0. A failure ends the process: nothing has started yet.
    private static func prepareListeners(_ options: ShardOptions) -> [PreparedListener] {
        let shared = options.listenerMode.resolved == .shared
        return options.listeners.map { spec in
            var err: Int32 = 0
            if let path = spec.path {
                // A socket a previous run left behind; anything else at the
                // path is someone else's, and stays.
                var st = stat()
                if lstat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFSOCK { unlink(path) }
                let fd = cv_unix_listen(path, Int32(spec.backlog), &err)
                guard fd >= 0 else {
                    let msg = "vega: cannot listen on \(path): \(IOError(code: err))\n"
                    _ = msg.withCString { write(2, $0, strlen($0)) }
                    exit(1)
                }
                return PreparedListener(host: "", port: 0, backlog: spec.backlog, path: path, shared: fd)
            }
            // Per-shard with a fixed port needs nothing here; port 0 is bound
            // (not listening) to pick one port for every shard, and stays so.
            guard shared || spec.port == 0 else {
                return PreparedListener(host: spec.host, port: spec.port, backlog: spec.backlog, shared: -1)
            }
            let fd = cv_tcp_listen(spec.host, Int32(spec.port), shared ? Int32(spec.backlog) : -1,
                                   shared ? 0 : 1, &err)
            guard fd >= 0 else {
                let msg = "vega: cannot listen on \(spec.host.isEmpty ? "*" : spec.host):\(spec.port): " +
                    "\(IOError(code: err))\n"
                _ = msg.withCString { write(2, $0, strlen($0)) }
                exit(1)
            }
            return PreparedListener(host: spec.host, port: Int(cv_local_port(fd)), backlog: spec.backlog,
                                    shared: shared ? fd : -1)
        }
    }
}

/// The supervisor's loop. Single-threaded, synchronous: it must never
/// start a thread, or later forks would copy a process in an unknown state.
@available(iOS, unavailable)
@available(tvOS, unavailable)
@available(watchOS, unavailable)
@available(visionOS, unavailable)
private struct Supervisor {
    let options: ShardOptions
    let layout: [[Int]]
    let listeners: [PreparedListener]
    let body: (Shard) -> Void

    /// Running shards by pid.
    var running: [Int32: Int] = [:]
    var pids: [Int32?]
    var startedAt: [UInt64]
    /// Crashes in a row that came soon after start, per shard.
    var quickCrashes: [Int]
    /// Shards waiting to restart, and when (cv_now_ns).
    var pending: [Int: UInt64] = [:]
    /// What the shards were told to stop with: SIGTERM, or SIGINT.
    var stoppedWith: Int32?
    var stopping: Bool { stoppedWith != nil }
    var killAt: UInt64?
    var crashed = false
    /// Rolling restart (SIGHUP): the shard being replaced, and what's left.
    var reloading: Int?
    var reloadQueue: [Int] = []
    /// Another rolling restart was asked for during this one.
    var reloadAgain = false
    /// When `options.watch` is next called (cv_now_ns), or .max.
    var nextWatch: UInt64 = .max
    /// What `ShardWatchAction.restartSupervisor` execs: the executable as it
    /// was found at start, before a rebuild could replace it.
    let executable: String?

    init(options: ShardOptions, layout: [[Int]], listeners: [PreparedListener], body: @escaping (Shard) -> Void) {
        self.options = options
        self.layout = layout
        self.listeners = listeners
        self.body = body
        pids = Array(repeating: nil, count: layout.count)
        startedAt = Array(repeating: 0, count: layout.count)
        quickCrashes = Array(repeating: 0, count: layout.count)
        executable = options.watch == nil ? nil : Runtime.executablePath
    }

    /// `adopting`: the shards a previous image of the supervisor started, by
    /// index (0 for none), to replace rather than start.
    mutating func run(adopting adopted: [Int32]? = nil) -> Never {
        if let adopted {
            for i in layout.indices {
                let pid = adopted[i]
                guard pid > 0 else {
                    start(i)
                    continue
                }
                running[pid] = i
                pids[i] = pid
                startedAt[i] = cv_now_ns()
                options.onEvent?(.started(shard: i, pid: pid))
            }
            // They run the old code.
            beginReload()
        } else {
            for i in layout.indices { start(i) }
        }
        let interval = UInt64(max(Scheduler.nanoseconds(options.watchInterval), 1_000_000))
        if options.watch != nil { nextWatch = cv_now_ns() &+ interval }
        while true {
            if running.isEmpty && pending.isEmpty {
                exit(stopping || !crashed ? 0 : 1)
            }
            let now = cv_now_ns()
            var deadline = pending.values.min() ?? .max
            if let killAt { deadline = min(deadline, killAt) }
            if !stopping { deadline = min(deadline, nextWatch) }
            let timeout: Int64 = deadline == .max ? -1 : Int64(clamping: deadline > now ? deadline - now : 0)
            var pid: Int32 = 0, status: Int32 = 0
            switch cv_supervisor_next(timeout, &pid, &status) {
            case 1: exited(pid, status)
            case 2: signalled(status)
            case 0: timers()
            default: break
            }
            if !stopping, let watch = options.watch, cv_now_ns() >= nextWatch {
                switch watch() {
                case .none: break
                case .reload: beginReload()
                case .restartSupervisor: restartSupervisor()
                }
                nextWatch = cv_now_ns() &+ interval
            }
        }
    }

    mutating func start(_ i: Int) {
        let pid: Int32
        switch options.launch.resolved {
        case .exec:
            pid = ExecShard.spawn(i, count: layout.count, cpus: layout[i], listeners: listeners)
        default:
            pid = cv_supervisor_fork()
            if pid == 0 {
                Supervisor.runShard(options, i, count: layout.count, cpus: layout[i], listeners: listeners,
                                    body: body)
            }
        }
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

    static func runShard(_ options: ShardOptions, _ i: Int, count: Int, cpus: [Int],
                         listeners: [PreparedListener], body: (Shard) -> Void) -> Never {
        let workers = options.workersPerShard ?? cpus.count
        // The shard's runtime is its process's global executor: a shard
        // starts with no task, and every task in it runs on its workers.
        #if os(Linux)
        let global = true
        #else
        let global = false
        #endif
        let rt = Runtime(scheduler: Scheduler(workers: max(workers, 1), name: "\(options.name)\(i)",
                                              pin: options.pinThreads, cpus: cpus, global: global,
                                              blockingThreads: max(options.blockingThreads, 1),
                                              blockingQueue: options.blockingQueue))
        if global { rt.scheduler.becomeGlobal() }
        body(Shard(index: i, count: count, cpus: cpus, runtime: rt, listeners: listeners))
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
            beginReload()
        default:
            // SIGTERM is passed on as it is; SIGINT and SIGQUIT as SIGINT,
            // which a shard takes as "now".
            let pass = sig == SIGTERM ? SIGTERM : SIGINT
            if let was = stoppedWith {
                if pass == was {
                    killAll() // asked twice: don't wait
                    return
                }
                // SIGTERM, then a stop now: the shards are told, and the
                // grace period runs on.
                stoppedWith = pass
                for pid in running.keys { kill(pid, pass) }
                return
            }
            stoppedWith = pass
            pending.removeAll()
            reloading = nil
            options.onEvent?(.stopping(signal: sig))
            for pid in running.keys { kill(pid, pass) }
            killAt = cv_now_ns() &+ UInt64(Scheduler.nanoseconds(options.shutdownGracePeriod))
        }
    }

    /// Restarts the shards one at a time, or, during such a restart, once
    /// it is done: a shard it has passed may have started before whatever
    /// asked for this one.
    mutating func beginReload() {
        guard !stopping else { return }
        guard reloading == nil else {
            reloadAgain = true
            return
        }
        options.onEvent?(.reloading)
        reloadQueue = Array(layout.indices)
        nextReload()
    }

    mutating func nextReload() {
        reloading = nil
        while !reloadQueue.isEmpty {
            let i = reloadQueue.removeFirst()
            if let pid = pids[i] {
                reloading = i
                kill(pid, SIGINT)
                return
            }
        }
        if reloadAgain {
            reloadAgain = false
            beginReload()
        }
    }

    /// `ShardWatchAction.restartSupervisor`: becomes the executable, after
    /// trying it, handing it the listeners, the shared regions and the
    /// shards in the environment. Returns only if it did not.
    mutating func restartSupervisor() {
        guard let path = executable else {
            options.onEvent?(.supervisorRestartFailed(reason: "the executable's path is not known"))
            return
        }
        // A file that is not a whole executable, or a build that fails at
        // start, is caught here: an exec that fails returns, but one of an
        // image that then dies takes the supervisor with it.
        if let why = SupervisorRestart.probe(path) {
            options.onEvent?(.supervisorRestartFailed(reason: why))
            return
        }
        options.onEvent?(.restartingSupervisor)
        let carried = listeners.map(\.shared).filter { $0 >= 0 } + SharedRegions.mapped.map(\.fd)
        for fd in carried { _ = fcntl(fd, F_SETFD, 0) }
        SupervisorRestart.record(listeners: listeners, pids: pids)
        let error = SupervisorRestart.exec(path)
        // Still here: the exec failed, and everything is as it was.
        for key in SupervisorRestart.keys { unsetenv(key) }
        for fd in carried { _ = fcntl(fd, F_SETFD, FD_CLOEXEC) }
        options.onEvent?(.supervisorRestartFailed(reason: "cannot exec \(path): \(IOError(code: error))"))
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
    /// group of every CPU otherwise, or if neither says anything. On Linux
    /// only the CPUs the process may run on: under `taskset` or a cpuset,
    /// shards and their pinned workers stay inside it.
    static func cacheDomains() -> [[Int]] {
        #if os(Linux)
        let allowed = affinity()
        guard let listed = read("/sys/devices/system/cpu/online").map(parseList), !listed.isEmpty else {
            return [allowed ?? Array(0..<Int(cv_cpu_count()))]
        }
        let online = allowed.map { mask in listed.filter(mask.contains) } ?? listed
        guard !online.isEmpty else { return [allowed ?? listed] }
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
        let fallback = [Array(0..<Int(cv_cpu_count()))]
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
        return [Array(0..<Int(cv_cpu_count()))]
        #endif
    }

    #if os(Linux)
    /// The process's affinity mask (nil if it can't be read).
    static func affinity() -> [Int]? {
        var cpus = [Int32](repeating: 0, count: 1024)
        let n = cv_affinity_list(&cpus, Int32(cpus.count))
        guard n > 0 else { return nil }
        return cpus[..<Int(n)].map(Int.init)
    }
    #endif

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
/// `ShardWatchAction.restartSupervisor`: what a supervisor passes the image
/// it execs in its environment, and that image reads back.
///
/// - `VEGA_SUPERVISOR_FDS`: per listener, "fd:port", as `VEGA_SHARD_FDS`.
/// - `VEGA_SUPERVISOR_REGIONS`: per shared region, "fd:size".
/// - `VEGA_SUPERVISOR_SHARDS`: per shard, its pid, or 0.
///
/// `VEGA_SUPERVISOR_PROBE`, set for a trial run of the executable, has
/// `Runtime.sharded` exit at once.
@available(iOS, unavailable)
@available(tvOS, unavailable)
@available(watchOS, unavailable)
@available(visionOS, unavailable)
enum SupervisorRestart {
    static let keys = ["VEGA_SUPERVISOR_FDS", "VEGA_SUPERVISOR_REGIONS", "VEGA_SUPERVISOR_SHARDS"]
    static let probeKey = "VEGA_SUPERVISOR_PROBE"

    struct Restarted {
        let listeners: [PreparedListener]
        let regions: [(Int32, Int)]
        let shards: [Int32]
    }

    /// In the supervisor: the record for the image about to be exec'd.
    static func record(listeners: [PreparedListener], pids: [Int32?]) {
        setenv(keys[0], listeners.map { "\($0.shared):\($0.port)" }.joined(separator: ","), 1)
        setenv(keys[1], SharedRegions.mapped.map { "\($0.fd):\($0.size)" }.joined(separator: ","), 1)
        setenv(keys[2], pids.map { "\($0 ?? 0)" }.joined(separator: ","), 1)
    }

    /// In a supervisor exec'd by another: what it was handed, with the
    /// variables removed so no shard sees them. Nil in one that was not.
    /// A record this image cannot take -- the shards or listeners differ
    /// in number -- is let go of: its shards are stopped and waited for and
    /// its sockets closed, and the supervisor starts as a new one.
    static func fromEnvironment(_ options: ShardOptions, shards count: Int) -> Restarted? {
        guard let raw = getenv(keys[2]) else { return nil }
        func value(_ key: String) -> String { getenv(key).map { String(cString: $0) } ?? "" }
        let pids = String(cString: raw).split(separator: ",").map { Int32($0) }
        let fds = value(keys[0]).split(separator: ",").map { pair -> (Int32, Int)? in
            let p = pair.split(separator: ":")
            guard p.count == 2, let fd = Int32(p[0]), let port = Int(p[1]) else { return nil }
            return (fd, port)
        }
        let regions = value(keys[1]).split(separator: ",").map { pair -> (Int32, Int)? in
            let p = pair.split(separator: ":")
            guard p.count == 2, let fd = Int32(p[0]), let size = Int(p[1]) else { return nil }
            return (fd, size)
        }
        for key in keys { unsetenv(key) }
        guard pids.count == count, pids.allSatisfy({ $0 != nil }),
              fds.count == options.listeners.count, fds.allSatisfy({ $0 != nil }),
              regions.count == options.sharedRegions.count, regions.allSatisfy({ $0 != nil }) else {
            let stale = pids.compactMap { $0 }.filter { $0 > 0 }
            for pid in stale { kill(pid, SIGINT) }
            var status: Int32 = 0
            for pid in stale { waitpid(pid, &status, 0) }
            for case let (fd, _)? in fds where fd >= 0 { close(fd) }
            for case let (fd, _)? in regions { close(fd) }
            return nil
        }
        let listeners = zip(options.listeners, fds).map { spec, pair -> PreparedListener in
            let (fd, port) = pair!
            if fd >= 0 { _ = fcntl(fd, F_SETFD, FD_CLOEXEC) }
            return PreparedListener(host: spec.host, port: port, backlog: spec.backlog, path: spec.path, shared: fd)
        }
        return Restarted(listeners: listeners, regions: regions.map { $0! }, shards: pids.map { $0! })
    }

    /// Runs `path`, with this process's arguments, as far as
    /// `Runtime.sharded`. Nil when it got there and exited 0 within five
    /// seconds; otherwise why not.
    static func probe(_ path: String) -> String? {
        var env: [String] = []
        if let environ = cv_environ() {
            var p = environ
            while let entry = p.pointee {
                env.append(String(cString: entry))
                p += 1
            }
        }
        env.append("\(probeKey)=1")
        var pid: Int32 = -1
        let rc = withCStrings(CommandLine.arguments) { argv in
            withCStrings(env) { envp in cv_shard_spawn(path, argv, envp, nil, nil, 0, &pid) }
        }
        guard rc == 0 else { return "cannot run \(path): \(IOError(code: rc))" }
        let deadline = cv_now_ns() &+ 5_000_000_000
        var status: Int32 = 0
        while true {
            let reaped = waitpid(pid, &status, WNOHANG)
            if reaped == pid { break }
            if reaped < 0 && errno != EINTR { return "cannot wait for \(path): \(IOError(code: errno))" }
            if cv_now_ns() >= deadline {
                kill(pid, SIGKILL)
                waitpid(pid, &status, 0)
                return "\(path) did not start within five seconds"
            }
            usleep(10_000)
        }
        if status & 0x7f != 0 { return "\(path) was killed by signal \(status & 0x7f) as it started" }
        let code = (status >> 8) & 0xff
        return code == 0 ? nil : "\(path) exited \(code) as it started"
    }

    /// Becomes `path`, with this process's arguments. Returns only on
    /// failure: why.
    static func exec(_ path: String) -> Int32 {
        withCStrings(CommandLine.arguments) { argv in cv_supervisor_exec(path, argv) }
    }

    private static func withCStrings<R>(_ strings: [String],
                                        _ body: (UnsafePointer<UnsafeMutablePointer<CChar>?>) -> R) -> R {
        var pointers = strings.map { strdup($0) }
        pointers.append(nil)
        defer { for p in pointers { free(p) } }
        return pointers.withUnsafeBufferPointer { body($0.baseAddress!) }
    }
}

/// Exec mode (`ShardLaunch.exec`): what the supervisor passes a shard in
/// its environment, and the shard reads back.
///
/// - `VEGA_SHARD`: the shard's index.
/// - `VEGA_SHARD_COUNT`: how many shards there are.
/// - `VEGA_SHARD_CPUS`: its CPU list ("0,1,2,3").
/// - `VEGA_SHARD_FDS`: per listener, "fd:port": the shared socket's number
///   in the shard (or -1 to bind its own), and the port.
/// - `VEGA_SHARD_PARENT`: the supervisor's pid.
@available(iOS, unavailable)
@available(tvOS, unavailable)
@available(watchOS, unavailable)
@available(visionOS, unavailable)
enum ExecShard {
    static let keys = ["VEGA_SHARD", "VEGA_SHARD_COUNT", "VEGA_SHARD_CPUS", "VEGA_SHARD_FDS", "VEGA_SHARD_PARENT",
                       "VEGA_SHARD_REGIONS"]

    struct Launched {
        let index: Int
        let count: Int
        let cpus: [Int]
        let listeners: [PreparedListener]
    }

    /// In a shard: its settings, with the variables removed so the shard's
    /// own children don't see them. Nil in the supervisor.
    static func fromEnvironment(_ options: ShardOptions) -> Launched? {
        guard let raw = getenv("VEGA_SHARD") else { return nil }
        func value(_ key: String) -> String { getenv(key).map { String(cString: $0) } ?? "" }
        let index = Int(String(cString: raw)), count = Int(value("VEGA_SHARD_COUNT"))
        let cpus = Topology.parseList(value("VEGA_SHARD_CPUS"))
        let parent = Int32(value("VEGA_SHARD_PARENT"))
        let fds = value("VEGA_SHARD_FDS").split(separator: ",").map { pair -> (Int32, Int)? in
            let p = pair.split(separator: ":")
            guard p.count == 2, let fd = Int32(p[0]), let port = Int(p[1]) else { return nil }
            return (fd, port)
        }
        let regions = value("VEGA_SHARD_REGIONS").split(separator: ",").map { pair -> (Int32, Int)? in
            let p = pair.split(separator: ":")
            guard p.count == 2, let fd = Int32(p[0]), let size = Int(p[1]) else { return nil }
            return (fd, size)
        }
        for key in keys { unsetenv(key) }
        guard let index, let count, index >= 0, index < count, let parent,
              fds.count == options.listeners.count, fds.allSatisfy({ $0 != nil }),
              regions.count == options.sharedRegions.count, regions.allSatisfy({ $0 != nil }) else {
            fail("a shard's VEGA_SHARD settings don't match its ShardOptions")
        }
        // Gone already, or going: nobody would supervise this shard.
        if cv_shard_adopt(parent) != 0 { exit(1) }
        SharedRegions.adopt(regions.map { $0! })
        let listeners = zip(options.listeners, fds).map { spec, pair -> PreparedListener in
            let (fd, port) = pair!
            if fd >= 0 { _ = fcntl(fd, F_SETFD, FD_CLOEXEC) } // not for the shard's children
            return PreparedListener(host: spec.host, port: port, backlog: spec.backlog, path: spec.path, shared: fd)
        }
        return Launched(index: index, count: count, cpus: cpus, listeners: listeners)
    }

    /// In the supervisor: start shard `i` as a new run of this executable.
    /// Returns its pid, or -1.
    static func spawn(_ i: Int, count: Int, cpus: [Int], listeners: [PreparedListener]) -> Int32 {
        var path = [CChar](repeating: 0, count: 4096)
        guard cv_self_exe(&path, Int32(path.count)) == 0 else { return -1 }
        // Shared sockets go above every one of them, so no dup2 overwrites
        // a socket still to be copied.
        let regions = SharedRegions.mapped
        let sources = listeners.map(\.shared).filter { $0 >= 0 } + regions.map(\.fd)
        var next = (sources.max() ?? 2) + 1
        var fds: [Int32] = [], targets: [Int32] = [], named: [String] = []
        for l in listeners {
            if l.shared >= 0 {
                fds.append(l.shared)
                targets.append(next)
                named.append("\(next):\(l.port)")
                next += 1
            } else {
                named.append("-1:\(l.port)")
            }
        }
        var shared: [String] = []
        for r in regions {
            fds.append(r.fd)
            targets.append(next)
            shared.append("\(next):\(r.size)")
            next += 1
        }
        var env: [String] = []
        if let environ = cv_environ() {
            var p = environ
            while let entry = p.pointee {
                let s = String(cString: entry)
                if !keys.contains(where: { s.hasPrefix($0 + "=") }) { env.append(s) }
                p += 1
            }
        }
        env += ["VEGA_SHARD=\(i)", "VEGA_SHARD_COUNT=\(count)",
                "VEGA_SHARD_CPUS=\(cpus.map(String.init).joined(separator: ","))",
                "VEGA_SHARD_FDS=\(named.joined(separator: ","))", "VEGA_SHARD_PARENT=\(getpid())",
                "VEGA_SHARD_REGIONS=\(shared.joined(separator: ","))"]
        var pid: Int32 = -1
        let rc = withCStrings(CommandLine.arguments) { argv in
            withCStrings(env) { envp in
                cv_shard_spawn(path, argv, envp, fds, targets, Int32(fds.count), &pid)
            }
        }
        return rc == 0 ? pid : -1
    }

    private static func withCStrings<R>(_ strings: [String],
                                        _ body: (UnsafePointer<UnsafeMutablePointer<CChar>?>) -> R) -> R {
        var pointers = strings.map { strdup($0) }
        pointers.append(nil)
        defer { for p in pointers { free(p) } }
        return pointers.withUnsafeBufferPointer { body($0.baseAddress!) }
    }

    private static func fail(_ message: String) -> Never {
        let line = "vega: \(message)\n"
        _ = line.withCString { write(2, $0, strlen($0)) }
        exit(1)
    }
}
#endif
