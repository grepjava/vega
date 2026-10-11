import Glibc
import Synchronization

actor Counter {
    var n = 0
    func bump() -> Int { n += 1; return currentPoolWorker() }
}

nonisolated func plainAsync() async -> Int { currentPoolWorker() }

/// Resumes `c` from a fresh pthread that is not part of any executor.
func resumeFromForeignThread(_ c: UnsafeContinuation<Void, Never>) {
    final class Box { let c: UnsafeContinuation<Void, Never>; init(_ c: UnsafeContinuation<Void, Never>) { self.c = c } }
    var t = pthread_t()
    pthread_create(&t, nil, { raw in
        Unmanaged<Box>.fromOpaque(raw!).takeRetainedValue().c.resume()
        return nil
    }, Unmanaged.passRetained(Box(c)).toOpaque())
    pthread_detach(t)
}

public func line(_ name: String, _ ok: Bool, _ detail: String = "") {
    print("\(ok ? "PASS" : "FAIL")  \(name)\(detail.isEmpty ? "" : "  (\(detail))")")
}

/// Where does each kind of code run when the task prefers `pool`?
@_spi(Vega) public func probePlacement(pool: Pool) async {
    let r = await Task(executorPreference: pool) { () async -> [String: Int] in
        var out: [String: Int] = [:]
        out["start"] = currentPoolWorker()
        await withUnsafeContinuation { resumeFromForeignThread($0) }
        out["afterForeignResume"] = currentPoolWorker()
        out["nonisolatedAsync"] = await plainAsync()
        out["defaultActor"] = await Counter().bump()
        out["afterActorHop"] = currentPoolWorker()
        let before = pool.timedEnqueues.load(ordering: .relaxed)
        try? await Task.sleep(for: .milliseconds(5))
        out["afterSleep"] = currentPoolWorker()
        out["sleepUsedSchedulingExecutor"] = pool.timedEnqueues.load(ordering: .relaxed) > before ? 1 : 0
        out["childTask"] = await withTaskGroup(of: Int.self) { g in
            g.addTask { currentPoolWorker() }
            return await g.next()!
        }
        out["unstructuredInherits"] = await Task { currentPoolWorker() }.value
        out["detached"] = await Task.detached { currentPoolWorker() }.value
        return out
    }.value
    for k in ["start", "afterForeignResume", "nonisolatedAsync", "defaultActor", "afterActorHop",
              "afterSleep", "childTask", "unstructuredInherits", "detached"] {
        line("preference: \(k) runs on pool", r[k]! > 0, "worker \(r[k]!)")
    }
    line("preference: Task.sleep routed via SchedulingExecutor", r["sleepUsedSchedulingExecutor"] == 1)
}

/// Spawn N trivial tasks on `executor` (nil = global) and await them all.
@_spi(Vega) public func benchSpawn(_ executor: (any TaskExecutor)?, n: Int) async -> Duration {
    let clock = ContinuousClock()
    return await clock.measure {
        await withTaskGroup(of: Void.self) { g in
            for _ in 0..<n { g.addTask(executorPreference: executor) { } }
            await g.waitForAll()
        }
    }
}

/// Two tasks hand a token back and forth through continuations, n round trips.
@_spi(Vega) public func benchPingPong(_ executor: (any TaskExecutor)?, n: Int) async -> Duration {
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
    let clock = ContinuousClock()
    return await clock.measure {
        await withTaskGroup(of: Void.self) { g in
            g.addTask(executorPreference: executor) { for _ in 0..<n { await a.wait(); b.signal() } }
            g.addTask(executorPreference: executor) { for _ in 0..<n { a.signal(); await b.wait() } }
            await g.waitForAll()
        }
    }
}

public func report(_ label: String, _ d: Duration, ops: Int) {
    let ns = Double(d.components.seconds) * 1e9 + Double(d.components.attoseconds) / 1e9
    let head = "  \(label):"
    print(head + String(repeating: " ", count: max(1, 34 - head.count))
          + "\(Int(ns / Double(ops))) ns/op, \(Int(Double(ops) / (ns / 1e9))) ops/s")
}

@_spi(Vega) public func runBenches(pool: Pool, label: String) async {
    let n = 200_000
    print("bench (\(label)), \(n) ops each, 3rd of 3 runs:")
    var s1 = Duration.zero, s2 = Duration.zero, p1 = Duration.zero, p2 = Duration.zero
    for _ in 0..<3 {
        s1 = await benchSpawn(nil, n: n)
        s2 = await benchSpawn(pool, n: n)
        p1 = await benchPingPong(nil, n: n)
        p2 = await benchPingPong(pool, n: n)
    }
    report("spawn, default executor", s1, ops: n)
    report("spawn, pool preference", s2, ops: n)
    report("ping-pong, default executor", p1, ops: n)
    report("ping-pong, pool preference", p2, ops: n)
}
