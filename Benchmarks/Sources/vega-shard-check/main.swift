// Runtime.sharded end to end. Run with no arguments: it starts itself as a
// three-shard server ("serve PORT") and checks, as a client, that
// connections reach every shard, that a crashed shard comes back, that
// SIGHUP replaces every shard (stopping each with SIGINT), that SIGTERM
// reaches the shards as SIGTERM, and that SIGQUIT after it reaches them as
// SIGINT and stops the lot with exit 0.
//
// The shards note each signal in the file VEGA_SHARD_CHECK_NOTES names.
// SIGTERM is only noted (as a server putting off its stop would), SIGINT
// stops the shard.
import Vega
import VegaProcess
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

let shardCount = 3

func log(_ s: String) {
    var line = s + "\n"
    line.withUTF8 { _ = write(2, $0.baseAddress, $0.count) }
}

func fail(_ s: String) -> Never {
    log("FAIL: \(s)")
    exit(1)
}

// MARK: - Server

func serve(port: Int) -> Never {
    var options = ShardConfiguration(shards: shardCount, workersPerShard: 1)
    options.pinThreads = false
    options.shutdownGracePeriod = .seconds(5)
    options.onEvent = { log("supervisor: \($0)") }
    options.listeners = [.tcp(host: "127.0.0.1", port: port)]
    // VEGA_SHARD_LISTENERS=shared or perShard; else the platform's default.
    switch getenv("VEGA_SHARD_LISTENERS").map({ String(cString: $0) }) {
    case "shared": options.listenerMode = .shared
    case "perShard": options.listenerMode = .perShard
    default: break
    }
    // VEGA_SHARD_LAUNCH=fork or exec; else the platform's default.
    switch getenv("VEGA_SHARD_LAUNCH").map({ String(cString: $0) }) {
    case "fork": options.launch = .fork
    case "exec": options.launch = .exec
    default: break
    }
    Runtime.sharded(options) { shard in
        do {
            try shard.runtime.block { () async throws(IOError) in
                let index = shard.index
                let terms = try Runtime.signals(SIGTERM)
                var ints = try Runtime.signals(SIGINT)
                let server = try TCPServer.serve(try shard.listener()) { await answer($0, index) }
                shard.runtime.spawn {
                    var terms = terms
                    while (try? await terms.recv()) != nil { note("term \(index)") }
                }
                try? await ints.recv()
                note("int \(index)")
                await server.shutdown(gracePeriod: .seconds(1))
            }
        } catch {
            log("shard \(shard.index): \(error)")
            exit(2)
        }
    }
}

/// A line in the notes file: O_APPEND, so the shards' lines don't mix.
func note(_ s: String) {
    guard let path = getenv("VEGA_SHARD_CHECK_NOTES") else { return }
    let fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0o644)
    guard fd >= 0 else { return }
    var line = s + "\n"
    line.withUTF8 { _ = write(fd, $0.baseAddress, $0.count) }
    close(fd)
}

func notes(_ path: String) -> [String] {
    guard let f = fopen(path, "r") else { return [] }
    defer { fclose(f) }
    var out: [String] = []
    var buf = [CChar](repeating: 0, count: 256)
    while fgets(&buf, Int32(buf.count), f) != nil {
        out.append(String(cString: buf).trimmingSuffix())
    }
    return out
}

/// Waits up to 5 s for the notes to hold every line in `want`.
func waitForNotes(_ path: String, _ want: Set<String>, what: String) async {
    let deadline = ContinuousClock.now + .seconds(5)
    while ContinuousClock.now < deadline {
        if want.isSubset(of: Set(notes(path))) { return }
        try? await Runtime.sleep(for: .milliseconds(50))
    }
    fail("\(what): notes \(notes(path)), wanted \(want.sorted())")
}

func answer(_ conn: consuming TCPStream, _ index: Int) async {
    var buf = IOBuffer(capacity: 64)
    while !buf.string.contains("\n") {
        guard let n = try? await conn.read(into: &buf), n > 0 else { return }
    }
    switch buf.string.trimmingSuffix() {
    case "crash":
        fatalError("crash requested")
    default:
        var reply = IOBuffer(capacity: 64)
        reply.append("\(index) \(getpid())\n")
        try? await conn.write(reply)
    }
}

extension String {
    func trimmingSuffix() -> String {
        var s = Substring(self)
        while s.last == "\n" || s.last == "\r" { s.removeLast() }
        return String(s)
    }
}

// MARK: - Client

func ask(_ port: Int, _ command: String) async throws(IOError) -> String {
    let conn = try await TCPStream.connect(to: SocketAddress(host: "127.0.0.1", port: port))
    var out = IOBuffer(capacity: 16)
    out.append(command + "\n")
    try await conn.write(out)
    var buf = IOBuffer(capacity: 64)
    while try await conn.read(into: &buf) > 0 {}
    return buf.string.trimmingSuffix()
}

/// shard index → pid, from `tries` connections.
func census(_ port: Int, tries: Int = 200) async -> [Int: Int32] {
    var seen: [Int: Int32] = [:]
    for _ in 0..<tries {
        guard let reply = try? await ask(port, "who") else { continue }
        let parts = reply.split(separator: " ")
        if parts.count == 2, let i = Int(parts[0]), let pid = Int32(parts[1]) { seen[i] = pid }
        if seen.count == shardCount && tries > shardCount { break }
    }
    return seen
}

func waitForAll(_ port: Int, differentFrom old: [Int: Int32] = [:], what: String) async -> [Int: Int32] {
    let deadline = ContinuousClock.now + .seconds(10)
    while ContinuousClock.now < deadline {
        let seen = await census(port)
        if seen.count == shardCount && seen.allSatisfy({ old[$0.key] != $0.value }) { return seen }
        try? await Runtime.sleep(for: .milliseconds(100))
    }
    fail("\(what): shards seen \(await census(port))")
}

func selfPath() -> String {
    #if os(Linux)
    var buf = [CChar](repeating: 0, count: 4096)
    let n = readlink("/proc/self/exe", &buf, buf.count - 1)
    if n > 0 { return String(decoding: buf[..<n].map { UInt8(bitPattern: $0) }, as: UTF8.self) }
    #endif
    return CommandLine.arguments[0]
}

let args = CommandLine.arguments
if args.count == 3, args[1] == "serve", let port = Int(args[2]) {
    serve(port: port)
}

let rt = Runtime(workers: 2)
// A port the OS says is free (one picked from the pid could fall in the
// ephemeral range, held by some connection, and every shard would fail to bind).
let port = try rt.block { () async throws(IOError) -> Int in
    try TCPListener.bind(host: "127.0.0.1", port: 0).localPort
}
let notesPath = "/tmp/vega-shard-check-\(getpid())"
unlink(notesPath)
setenv("VEGA_SHARD_CHECK_NOTES", notesPath, 1)
defer { unlink(notesPath) }
let all = Set(0..<shardCount)
try rt.block { () async throws in
    var server = try Command(selfPath(), arguments: ["serve", "\(port)"]).spawn()

    let first = await waitForAll(port, what: "start")
    log("client: shards \(first.sorted { $0.key < $1.key })")

    // A shard that traps is replaced; the others carry on.
    _ = try? await ask(port, "crash")
    try await Runtime.sleep(for: .milliseconds(200))
    let afterCrash = await waitForAll(port, what: "after a crash")
    let replaced = afterCrash.filter { first[$0.key] != $0.value }
    guard replaced.count == 1 else { fail("crash replaced \(replaced.count) shards") }
    log("client: crash replaced shard \(replaced.keys.first!)")

    // SIGHUP: every shard replaced, one at a time, each told with SIGINT.
    kill(server.pid, SIGHUP)
    let reloaded = await waitForAll(port, differentFrom: afterCrash, what: "after SIGHUP")
    await waitForNotes(notesPath, Set(all.map { "int \($0)" }), what: "SIGHUP")
    log("client: SIGHUP replaced every shard with SIGINT")
    unlink(notesPath)

    // SIGTERM reaches every shard as SIGTERM; these ones go on serving.
    kill(server.pid, SIGTERM)
    await waitForNotes(notesPath, Set(all.map { "term \($0)" }), what: "SIGTERM")
    guard await census(port) == reloaded else { fail("a shard stopped on SIGTERM") }
    log("client: SIGTERM passed on as SIGTERM")

    // SIGQUIT after it: passed on as SIGINT, and everything stops, exit 0.
    kill(server.pid, SIGQUIT)
    await waitForNotes(notesPath, Set(all.map { "int \($0)" }), what: "SIGQUIT")
    let deadline = ContinuousClock.now + .seconds(10)
    var ended: ExitStatus?
    while ended == nil && ContinuousClock.now < deadline {
        ended = try server.tryWait()
        if ended == nil { try await Runtime.sleep(for: .milliseconds(20)) }
    }
    guard let status = ended else {
        try? server.kill()
        fail("supervisor still running 10 s after SIGQUIT")
    }
    guard status.code == 0 else { fail("supervisor ended with \(status)") }
    if (try? await ask(port, "who")) != nil { fail("still serving after SIGQUIT") }
}
print("OK: sharded runtime checks passed")
