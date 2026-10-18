// Runs Vega as the process-wide executor and checks that Swift concurrency
// works on it: plain and detached tasks, sleeps, groups, actors, async let,
// cancellation, yields. Exits non-zero on the first failure.
//
// Also a smoke test for a patched libswift_Concurrency: run it with the
// patched library first on LD_LIBRARY_PATH.
import Vega

#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

enum Check {
    static func expect(_ ok: Bool, _ what: String) {
        if !ok {
            print("FAIL: \(what)")
            exit(1)
        }
    }

    static func onWorker() -> Bool { Runtime.currentWorker != nil }

    actor Counter {
        var value = 0
        var sawWorker = true
        func bump() {
            value += 1
            if Runtime.currentWorker == nil { sawWorker = false }
        }
    }

    static func run(_ rt: Runtime) {
        rt.block { () async -> Void in
            expect(await Task { onWorker() }.value, "Task {} runs on a Vega worker")
            expect(await Task.detached { onWorker() }.value, "Task.detached runs on a Vega worker")

            // Each form of Task.sleep comes back to a Vega worker. (On Linux it
            // runs on Vega's timer wheel; on Darwin on Dispatch's timers, and
            // the resume returns through the enqueue hook: docs/PLAN.md.)
            let sleeps: [(String, @Sendable () async -> Void)] = [
                ("for: (continuous)", { try? await Task.sleep(for: .milliseconds(20)) }),
                ("until: suspending", {
                    try? await Task.sleep(until: .now + .milliseconds(20), clock: SuspendingClock())
                }),
                ("nanoseconds:", { try? await Task.sleep(nanoseconds: 20_000_000) }),
            ]
            for (form, sleep) in sleeps {
                let start = ContinuousClock.now
                await sleep()
                let slept = ContinuousClock.now - start
                expect(slept >= .milliseconds(20) && slept < .seconds(1), "Task.sleep(\(form) 20ms) took \(slept)")
                expect(onWorker(), "resumes on a Vega worker after Task.sleep(\(form))")
            }

            let n = 20_000
            let sum = await withTaskGroup(of: Int.self) { g in
                for i in 0..<n { g.addTask { onWorker() ? i : -1_000_000 } }
                return await g.reduce(0, +)
            }
            expect(sum == n * (n - 1) / 2, "task group of \(n) children on workers (sum \(sum))")

            await withDiscardingTaskGroup { g in
                for _ in 0..<n { g.addTask { await Task.yield() } }
            }

            let counter = Counter()
            await withTaskGroup(of: Void.self) { g in
                for _ in 0..<1_000 { g.addTask { await counter.bump() } }
            }
            expect(await counter.value == 1_000, "actor serialises 1000 increments")
            expect(await counter.sawWorker, "actor runs on Vega workers")

            async let a = Task.detached { 21 }.value
            async let b = Task.detached { 21 }.value
            expect(await a + b == 42, "async let")

            let t = Task {
                await withTaskCancellationHandler {
                    while !Task.isCancelled { await Task.yield() }
                    return true
                } onCancel: {}
            }
            t.cancel()
            expect(await t.value, "cancellation reaches a yielding task")

            // Cancellation racing a waiter's own exit from
            // withTaskCancellationHandler: cancel lands while the waiter is
            // being notified and is removing its handler.
            let racy = Notify()
            for _ in 0..<20 {
                let waiters = (0..<1_000).map { _ in Task { try? await racy.notified() } }
                await withTaskGroup(of: Void.self) { g in
                    g.addTask { for w in waiters { w.cancel() } }
                    g.addTask { for _ in 0..<1_000 { racy.notifyOne() } }
                }
                for w in waiters { await w.value }
                racy.notifyWaiters()
            }

            let notify = Notify(), back = Notify()
            let rounds = 100_000
            await withTaskGroup(of: Void.self) { g in
                g.addTask { for _ in 0..<rounds { try? await notify.notified(); back.notifyOne() } }
                g.addTask { for _ in 0..<rounds { notify.notifyOne(); try? await back.notified() } }
            }

            await withTaskGroup(of: Void.self) { g in
                for _ in 0..<8 { g.addTask { for _ in 0..<50_000 { await Task.yield() } } }
            }
        }
    }
}

let rt = Runtime.installGlobal(workers: 4)
Check.run(rt)
print("OK: Vega global executor checks passed")
