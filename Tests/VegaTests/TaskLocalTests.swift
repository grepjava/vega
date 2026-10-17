import Testing
@testable import Vega

private enum Trace {
    @TaskLocal static var id: String?
}

/// Task-locals, as Tokio's `task_local!`: Swift's own `@TaskLocal`, which a
/// Vega task inherits from whoever spawns it, as any Swift task does.
@Suite("Task-locals")
struct TaskLocalTests {
    @Test func spawnedTasksInheritThem() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let seen = rt.block { () async -> [String?] in
            await Trace.$id.withValue("req-1") {
                var seen: [String?] = []
                // Runtime.spawn, on this runtime and from the caller's.
                seen.append(await rt.spawn { Trace.id }.value)
                seen.append(await Runtime.spawn { Trace.id }.value)
                // Across suspensions and I/O-free hops between workers.
                seen.append(await rt.spawn { () async -> String? in
                    await Runtime.yield()
                    try? await Runtime.sleep(for: .milliseconds(1))
                    await Runtime.yieldToAnyWorker()
                    return Trace.id
                }.value)
                // Child tasks of a group on the runtime.
                seen.append(await withTaskGroup(of: String?.self) { group in
                    group.addTask(executorPreference: rt.executor) { Trace.id }
                    return await group.next()!
                })
                // JoinSet and LocalExecutor.
                let set = JoinSet<String?, Never>(runtime: rt)
                set.spawn { Trace.id }
                seen.append(await set.nextValue()!)
                seen.append(await LocalExecutor(runtime: rt).spawn { _ in Trace.id }.value)
                return seen
            }
        }
        #expect(seen == Array(repeating: "req-1", count: 6))
    }

    @Test func boundOnlyWhereSet() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (inside, outside) = rt.block { () async -> (String?, String?) in
            let inside = await Trace.$id.withValue("a") {
                await Trace.$id.withValue("b") { await rt.spawn { Trace.id }.value }
            }
            return (inside, await rt.spawn { Trace.id }.value)
        }
        #expect(inside == "b")
        #expect(outside == nil)
    }

    /// `TaskPool` runs closures on its own long-lived tasks: they don't see
    /// the spawner's task-locals (as its documentation says).
    @Test func taskPoolDoesNotCarryThem() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let seen = rt.block { () async -> String? in
            let pool = TaskPool(runtime: rt)
            defer { pool.close() }
            let (stream, continuation) = AsyncStream<String?>.makeStream()
            Trace.$id.withValue("x") {
                pool.spawn { continuation.yield(Trace.id) }
            }
            var it = stream.makeAsyncIterator()
            return await it.next() ?? "none"
        }
        #expect(seen == nil)
    }
}
