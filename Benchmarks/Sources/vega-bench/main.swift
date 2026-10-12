// Scheduler microbenchmarks, after Tokio's rt_multi_threaded benches.
//
//   vega-bench [--global] [--no-baseline] [--workers N] [--runs N] [--only name,name]
//
// Without --global: Vega (executor preference) vs Swift's default executor.
// With --global:    Vega installed as the process's global executor, so even
//                   plain Task {} and Task.sleep run on it.
import Glibc
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

let benches = [spawnMany, spawnDiscard, chainedSpawn, pingPong, yieldMany].filter { only?.contains($0.name) ?? true }

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
