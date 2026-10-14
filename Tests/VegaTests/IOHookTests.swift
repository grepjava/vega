import CVega
import Testing
@testable import Vega

private let ms: UInt64 = 1_000_000

/// A connected client and server on loopback.
private struct Pair: ~Copyable {
    var client: TCPStream
    var server: TCPStream
}

private func connectedPair() async throws(IOError) -> Pair {
    let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
    let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
    let server = try await listener.accept()
    return Pair(client: client, server: server)
}

/// What a read ended with: "read N" or the error.
private func outcome(_ stream: borrowing TCPStream) async -> String {
    var buffer = IOBuffer(capacity: 8)
    do throws(IOError) {
        return "read \(try await stream.read(into: &buffer))"
    } catch {
        return error == .timedOut ? "timedOut" : error == .cancelled ? "cancelled" : "\(error)"
    }
}

/// The per-task I/O hook (IOTaskHook): tasks Vega starts arm it per wait;
/// other tasks, child tasks among them (they inherit the task-local), fall
/// back to a cancellation handler per wait.
@Suite("I/O cancellation hook")
struct IOHookTests {
    /// Tasks Vega starts carry a hook; their child tasks don't own it.
    @Test func vegaTasksHaveAHookAndChildrenDoNot() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (own, child) = rt.block { () async -> (Bool, Bool) in
            async let child = IOTaskHook.active != nil
            return (IOTaskHook.active != nil, await child)
        }
        #expect(own)
        #expect(!child)
    }

    /// A child task's read is interrupted by the child's own cancellation,
    /// not only by its parent's.
    @Test func cancellingAChildTaskInterruptsItsRead() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let start = cv_now_ns()
        let (result, parentCancelled) = try rt.block { () async throws(IOError) -> (String, Bool) in
            let pair = try await connectedPair()
            let client = pair.client, server = pair.server
            defer { _ = try? server.localAddress }
            let box = Handoff(client)
            let result = await withTaskGroup(of: String.self) { group in
                group.addTask { await outcome(box.take()) }
                try? await Runtime.sleep(for: .milliseconds(20))
                group.cancelAll()
                return await group.next()!
            }
            return (result, Task.isCancelled)
        }
        #expect(result == "cancelled")
        #expect(!parentCancelled)
        #expect((cv_now_ns() - start) / ms < 1_000)
    }

    /// A deadline set in a child task bounds that task's read.
    @Test func aChildTasksOwnDeadlineFires() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let result = try rt.block { () async throws(IOError) -> String in
            let pair = try await connectedPair()
            let client = pair.client, server = pair.server
            defer { _ = try? server.localAddress }
            let box = Handoff(client)
            async let child = { () async -> String in
                let client = box.take()
                return await Runtime.withIODeadline(.milliseconds(20)) { await outcome(client) }
            }()
            return await child
        }
        #expect(result == "timedOut")
    }

    /// Once a hooked task is cancelled, each later wait fails at once.
    @Test func aCancelledTaskFailsLaterWaitsAtOnce() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let start = cv_now_ns()
        let results = try rt.block { () async throws(IOError) -> [String] in
            let pair = try await connectedPair()
            let client = pair.client, server = pair.server
            defer { _ = try? server.localAddress }
            let reader = rt.spawn(with: client) { client -> [String] in
                [await outcome(client), await outcome(client), await outcome(client)]
            }
            try? await Runtime.sleep(for: .milliseconds(20))
            reader.cancel()
            return await reader.value
        }
        #expect(results == ["cancelled", "cancelled", "cancelled"])
        #expect((cv_now_ns() - start) / ms < 1_000)
    }

    /// An inner scope's end puts the outer deadline back on the hook.
    @Test func nestedDeadlinesRestoreTheOuterOne() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let start = cv_now_ns()
        let (inner, outer) = try rt.block { () async throws(IOError) -> (String, String) in
            let pair = try await connectedPair()
            let client = pair.client, server = pair.server
            defer { _ = try? server.localAddress }
            return await Runtime.withIODeadline(.milliseconds(60)) { () async -> (String, String) in
                let inner = await Runtime.withIODeadline(.milliseconds(10)) { await outcome(client) }
                return (inner, await outcome(client))
            }
        }
        let elapsed = (cv_now_ns() - start) / ms
        #expect(inner == "timedOut")
        #expect(outer == "timedOut")
        #expect(elapsed >= 60 && elapsed < 1_000, "took \(elapsed) ms")
    }

    /// A deadline and a cancellation in the same wait: the cancellation
    /// that comes first is what the wait reports, and the task's later
    /// waits still fail as cancelled after the scope ends.
    @Test func cancellationInsideADeadlineScope() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let results = try rt.block { () async throws(IOError) -> [String] in
            let pair = try await connectedPair()
            let client = pair.client, server = pair.server
            defer { _ = try? server.localAddress }
            let reader = rt.spawn(with: client) { client -> [String] in
                let first = await Runtime.withIODeadline(.seconds(60)) { await outcome(client) }
                return [first, await outcome(client)]
            }
            try? await Runtime.sleep(for: .milliseconds(20))
            reader.cancel()
            return await reader.value
        }
        #expect(results == ["cancelled", "cancelled"])
    }
}
