// Scheduler microbenchmarks, after Tokio's rt_multi_threaded benches.
//
//   vega-bench [--global] [--no-baseline] [--workers N] [--runs N] [--only name,name]
//
// Without --global: Vega (executor preference) vs Swift's default executor.
// With --global:    Vega installed as the process's global executor, so even
//                   plain Task {} and Task.sleep run on it.
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
#if !os(Linux)
import Dispatch
#endif
import Synchronization
import Vega

// MARK: options

var global = false, baseline = true, workers: Int? = nil, runs = 7
var only: Set<String>? = nil
var args = CommandLine.arguments.dropFirst()
while let a = args.popFirst() {
    switch a {
    case "--global": global = true
    case "--no-baseline": baseline = false
    case "--workers": workers = Int(args.popFirst()!)!
    case "--runs": runs = Int(args.popFirst()!)!
    case "--only": only = Set(args.popFirst()!.split(separator: ",").map(String.init))
    default: fatalError("unknown option \(a)")
    }
}

// Must happen before any task exists.
let rt = global ? Runtime.installGlobal(workers: workers) : Runtime(workers: workers)

// MARK: harness

/// Run `op` as a task on `executor` (nil = Swift's default) and block this
/// thread until it returns.
#if os(Linux)
final class BlockBox<T>: @unchecked Sendable {
    var value: T?
    var sem = sem_t()
}

func blockOn<T: Sendable>(_ executor: (any TaskExecutor)?, _ op: @escaping @Sendable () async -> T) -> T {
    let box = BlockBox<T>()
    sem_init(&box.sem, 0, 0)
    Task.detached(executorPreference: executor) {
        box.value = await op()
        sem_post(&box.sem)
    }
    while sem_wait(&box.sem) != 0 {}
    sem_destroy(&box.sem)
    return box.value!
}
#else
/// DispatchSemaphore: macOS has no unnamed POSIX semaphores (sem_init fails
/// with ENOSYS, and the wait never returned).
final class BlockBox<T>: @unchecked Sendable {
    var value: T?
    let done = DispatchSemaphore(value: 0)
}

func blockOn<T: Sendable>(_ executor: (any TaskExecutor)?, _ op: @escaping @Sendable () async -> T) -> T {
    let box = BlockBox<T>()
    Task.detached(executorPreference: executor) {
        box.value = await op()
        box.done.signal()
    }
    box.done.wait()
    return box.value!
}
#endif

func nanos(_ d: Duration) -> Double {
    Double(d.components.seconds) * 1e9 + Double(d.components.attoseconds) / 1e9
}

struct Bench {
    let name: String
    let ops: Int
    let body: @Sendable ((any TaskExecutor)?) async -> Void
}

// MARK: benches

/// Spawn `n` empty tasks from one task and wait for them all.
let spawnMany = Bench(name: "spawn_many", ops: 100_000) { ex in
    await withTaskGroup(of: Void.self) { g in
        for _ in 0..<100_000 { g.addTask(executorPreference: ex) {} }
        await g.waitForAll()
    }
}

/// spawn_many with a discarding group: the parent is resumed once at the end,
/// not once per child, so this isolates the cost of the spawns themselves.
let spawnDiscard = Bench(name: "spawn_discard", ops: 100_000) { ex in
    await withDiscardingTaskGroup { g in
        for _ in 0..<100_000 { g.addTask(executorPreference: ex) {} }
    }
}

/// Each task spawns the next: no parallelism, pure spawn+wake latency.
let chainedSpawn = Bench(name: "chained_spawn", ops: 10_000) { ex in
    @Sendable func chain(_ n: Int) async {
        if n == 0 { return }
        await Task(executorPreference: ex) { await chain(n - 1) }.value
    }
    await chain(10_000)
}

/// Two tasks hand a token back and forth through continuations.
let pingPong = Bench(name: "ping_pong", ops: 100_000) { ex in
    final class Slot: @unchecked Sendable {
        let m = Mutex<(UnsafeContinuation<Void, Never>?, Bool)>((nil, false))
        func wait() async {
            await withUnsafeContinuation { (c: UnsafeContinuation<Void, Never>) in
                let fire = m.withLock { s -> Bool in
                    if s.1 { s.1 = false; return true }
                    s.0 = c; return false
                }
                if fire { c.resume() }
            }
        }
        func signal() {
            let c = m.withLock { s -> UnsafeContinuation<Void, Never>? in
                if let c = s.0 { s.0 = nil; return c }
                s.1 = true; return nil
            }
            c?.resume()
        }
    }
    let a = Slot(), b = Slot()
    await withTaskGroup(of: Void.self) { g in
        g.addTask(executorPreference: ex) { for _ in 0..<100_000 { await a.wait(); b.signal() } }
        g.addTask(executorPreference: ex) { for _ in 0..<100_000 { a.signal(); await b.wait() } }
        await g.waitForAll()
    }
}

/// 200 tasks each yield 500 times.
let yieldMany = Bench(name: "yield_many", ops: 100_000) { ex in
    await withTaskGroup(of: Void.self) { g in
        for _ in 0..<200 {
            g.addTask(executorPreference: ex) { for _ in 0..<500 { await Task.yield() } }
        }
        await g.waitForAll()
    }
}

/// ping_pong with Vega's Notify: the same shape as Tokio's bench.
let pingPongNotify = Bench(name: "ping_pong_notify", ops: 100_000) { ex in
    let a = Notify(), b = Notify()
    await withTaskGroup(of: Void.self) { g in
        g.addTask(executorPreference: ex) { for _ in 0..<100_000 { await a.notified(); b.notifyOne() } }
        g.addTask(executorPreference: ex) { for _ in 0..<100_000 { a.notifyOne(); await b.notified() } }
        await g.waitForAll()
    }
}

/// ping_pong_notify without cancellation support (no status record per wait).
let pingPongNotifyNC = Bench(name: "ping_pong_notify_nc", ops: 100_000) { ex in
    let a = Notify(), b = Notify()
    await withTaskGroup(of: Void.self) { g in
        g.addTask(executorPreference: ex) { for _ in 0..<100_000 { await a.notifiedIgnoringCancellation(); b.notifyOne() } }
        g.addTask(executorPreference: ex) { for _ in 0..<100_000 { a.notifyOne(); await b.notifiedIgnoringCancellation() } }
        await g.waitForAll()
    }
}

/// yield_many with Runtime.yield instead of Task.yield.
let yieldVega = Bench(name: "yield_vega", ops: 100_000) { ex in
    await withTaskGroup(of: Void.self) { g in
        for _ in 0..<200 {
            g.addTask(executorPreference: ex) { for _ in 0..<500 { await Runtime.yield() } }
        }
        await g.waitForAll()
    }
}

/// spawn_many on a TaskPool: 100k closures, wait for the last one.
final class PoolDone: @unchecked Sendable {
    let left = Atomic<Int>(0)
    let done = Notify()
}
/// Not a top-level var: those are main-actor isolated, and the main thread is
/// blocked while benches run.
enum Shared { nonisolated(unsafe) static var pool: TaskPool! }
Shared.pool = TaskPool(runtime: rt)
let poolSpawn = Bench(name: "pool_spawn", ops: 100_000) { _ in
    let d = PoolDone()
    d.left.store(100_000, ordering: .relaxed)
    for _ in 0..<100_000 {
        Shared.pool.spawn { if d.left.subtract(1, ordering: .acquiringAndReleasing).newValue == 0 { d.done.notifyOne() } }
    }
    await d.done.notified()
}

/// Carries a `~Copyable` value into a task closure, which can't capture one.
final class Move<T: ~Copyable>: @unchecked Sendable {
    var value: T?
    init(_ v: consuming T) { value = consume v }
    func take() -> T { value.take()! }
}

struct EchoEnds: ~Copyable, Sendable {
    var rx: Channel<Int>.Receiver
    let tx: Channel<Int>.Sender
}

/// A value bounced through two capacity-1 channels: every send meets a
/// full or empty channel, so each round trip parks and wakes both sides.
let mpscPingPong = Bench(name: "mpsc_ping_pong", ops: 100_000) { ex in
    let there = Channel<Int>(capacity: 1), back = Channel<Int>(capacity: 1)
    let ends = Move(EchoEnds(rx: there.receiver, tx: back.sender))
    let echo = Task(executorPreference: ex) {
        var e = ends.take()
        while let v = try? await e.rx.receive() { try? await e.tx.send(v) }
    }
    let tx = there.sender
    var rx = back.receiver
    for i in 0..<100_000 {
        try? await tx.send(i)
        _ = try? await rx.receive()
    }
    _ = consume tx
    await echo.value
}

/// 8 producers × 12,500 sends into one bounded(1024) channel, one consumer.
let mpscFanIn = Bench(name: "mpsc_fan_in", ops: 100_000) { ex in
    let ch = Channel<Int>(capacity: 1024)
    var producers: [Task<Void, Never>] = []
    for _ in 0..<8 {
        let tx = Move(ch.sender.clone())
        producers.append(Task(executorPreference: ex) {
            let tx = tx.take()
            for i in 0..<12_500 { try? await tx.send(i) }
        })
    }
    _ = consume ch.sender
    var rx = ch.receiver
    var n = 0
    while (try? await rx.receive()) != nil { n += 1 }
    precondition(n == 100_000)
    for p in producers { await p.value }
}

/// 200 tasks × 500 acquire/release on a 2-permit semaphore.
let semaphore = Bench(name: "semaphore", ops: 100_000) { ex in
    let sem = Semaphore(permits: 2)
    await withTaskGroup(of: Void.self) { g in
        for _ in 0..<200 {
            g.addTask(executorPreference: ex) {
                for _ in 0..<500 {
                    try? await sem.acquire()
                    sem.release()
                }
            }
        }
        await g.waitForAll()
    }
}

/// mpsc_ping_pong with the non-cancellable send and receive.
let mpscPingPongNC = Bench(name: "mpsc_ping_pong_nc", ops: 100_000) { ex in
    let there = Channel<Int>(capacity: 1), back = Channel<Int>(capacity: 1)
    let ends = Move(EchoEnds(rx: there.receiver, tx: back.sender))
    let echo = Task(executorPreference: ex) {
        var e = ends.take()
        while let v = try? await e.rx.receiveIgnoringCancellation() { try? await e.tx.sendIgnoringCancellation(v) }
    }
    let tx = there.sender
    var rx = back.receiver
    for i in 0..<100_000 {
        try? await tx.sendIgnoringCancellation(i)
        _ = try? await rx.receiveIgnoringCancellation()
    }
    _ = consume tx
    await echo.value
}

/// mpsc_fan_in with the non-cancellable send and receive.
let mpscFanInNC = Bench(name: "mpsc_fan_in_nc", ops: 100_000) { ex in
    let ch = Channel<Int>(capacity: 1024)
    var producers: [Task<Void, Never>] = []
    for _ in 0..<8 {
        let tx = Move(ch.sender.clone())
        producers.append(Task(executorPreference: ex) {
            let tx = tx.take()
            for i in 0..<12_500 { try? await tx.sendIgnoringCancellation(i) }
        })
    }
    _ = consume ch.sender
    var rx = ch.receiver
    var n = 0
    while (try? await rx.receiveIgnoringCancellation()) != nil { n += 1 }
    precondition(n == 100_000)
    for p in producers { await p.value }
}

/// semaphore with the non-cancellable acquire.
let semaphoreNC = Bench(name: "semaphore_nc", ops: 100_000) { ex in
    let sem = Semaphore(permits: 2)
    await withTaskGroup(of: Void.self) { g in
        for _ in 0..<200 {
            g.addTask(executorPreference: ex) {
                for _ in 0..<500 {
                    try? await sem.acquireIgnoringCancellation()
                    sem.release()
                }
            }
        }
        await g.waitForAll()
    }
}

/// 10,000 tasks start a 60 s sleep and are cancelled once all are asleep:
/// spawn, timer insert, cancel and timer removal. Off Vega (the baseline)
/// Runtime.sleep is Task.sleep.
final class Armed: @unchecked Sendable { let n = Atomic<Int>(0) }
let sleepCancel = Bench(name: "sleep_cancel", ops: 10_000) { ex in
    let armed = Armed()
    await withTaskGroup(of: Void.self) { g in
        for _ in 0..<10_000 {
            g.addTask(executorPreference: ex) {
                armed.n.add(1, ordering: .relaxed)
                try? await Runtime.sleep(for: .seconds(60))
            }
        }
        while armed.n.load(ordering: .relaxed) < 10_000 { await Task.yield() }
        await Task.yield()
        g.cancelAll()
        await g.waitForAll()
    }
}

/// 10,000 tasks each sleep 1 ms, all at once: firing a large batch of timers.
let sleepMany = Bench(name: "sleep_many", ops: 10_000) { ex in
    await withTaskGroup(of: Void.self) { g in
        for _ in 0..<10_000 {
            g.addTask(executorPreference: ex) { try? await Runtime.sleep(for: .milliseconds(1)) }
        }
        await g.waitForAll()
    }
}

/// 10,000 tasks each run an operation under a timeout it beats: the cost of
/// `Runtime.timeout` (a child task plus arming and unlinking a timer).
let timeoutOK = Bench(name: "timeout_ok", ops: 10_000) { ex in
    await withTaskGroup(of: Void.self) { g in
        for i in 0..<10_000 {
            g.addTask(executorPreference: ex) { _ = try? await Runtime.timeout(.seconds(10)) { i } }
        }
        await g.waitForAll()
    }
}

/// Keeps a result alive past the optimizer.
@inline(never) func blackHole(_ x: Int) { if x == .min { print(x) } }

/// One task runs 10,000 operations in a row, each under a timeout it beats:
/// what `Runtime.timeout` adds to a step of a connection's work, as a child
/// task plus a timer.
let timeoutSeq = Bench(name: "timeout_seq", ops: 10_000) { _ in
    var sum = 0
    for i in 0..<10_000 { sum &+= (try? await Runtime.timeout(.seconds(10)) { i }) ?? 0 }
    blackHole(sum)
}

/// The same under `Runtime.withIODeadline`: no child task, just the timer
/// and the task-local that the I/O waits read.
let ioDeadlineSeq = Bench(name: "io_deadline_seq", ops: 10_000) { _ in
    var sum = 0
    for i in 0..<10_000 { sum &+= await Runtime.withIODeadline(.seconds(10)) { i } }
    blackHole(sum)
}

let benches = [spawnMany, spawnDiscard, poolSpawn, chainedSpawn, pingPong, pingPongNotify, pingPongNotifyNC, yieldMany, yieldVega,
               mpscPingPong, mpscPingPongNC, mpscFanIn, mpscFanInNC, semaphore, semaphoreNC, sleepCancel, sleepMany, timeoutOK, timeoutSeq, ioDeadlineSeq].filter { only?.contains($0.name) ?? true }

// MARK: run

print("vega-bench: \(rt.workerCount) workers, \(global ? "Vega is the global executor" : "Vega via executor preference"), median of \(runs) runs")
print("bench".padded(16) + "Vega ns/op".padded(14, left: true) + (global || !baseline ? "" : "Swift default ns/op".padded(22, left: true) + "speedup".padded(10, left: true)))

for b in benches {
    func measure(_ ex: (any TaskExecutor)?) -> Double {
        var samples: [Double] = []
        // As global executor Vega needs no preference, and an app wouldn't
        // pass one (it costs Swift an extra allocation per task). Read here:
        // top-level vars are main-actor isolated, and the main thread is
        // blocked in blockOn, so reading `global` inside the task deadlocks.
        let pref = global ? nil : ex
        for _ in 0..<runs {
            let d = blockOn(ex) { () async -> Duration in
                let clock = ContinuousClock()
                return await clock.measure { await b.body(pref) }
            }
            samples.append(nanos(d) / Double(b.ops))
        }
        return samples.sorted()[runs / 2]
    }
    let vega = measure(rt.executor)
    var line = b.name.padded(16) + String(format1(vega)).padded(14, left: true)
    if !global && baseline {
        let base = measure(nil)
        line += format1(base).padded(22, left: true) + (format1(base / vega) + "x").padded(10, left: true)
    }
    print(line)
}

func format1(_ x: Double) -> String {
    let r = (x * 10).rounded() / 10
    return String(r)
}

extension String {
    func padded(_ n: Int, left: Bool = false) -> String {
        let pad = String(repeating: " ", count: max(0, n - count))
        return left ? pad + self : self + pad
    }
}
