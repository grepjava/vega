#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif
import CVega
import Synchronization
import Testing
@testable import Vega

private func pthread_self_id() -> Int {
    #if canImport(Glibc) || os(Windows)
    return Int(bitPattern: UInt(pthread_self()))
    #else
    return Int(bitPattern: pthread_self())
    #endif
}

@Suite struct CurrentThreadTests {
    /// Everything runs on the thread that called block: the operation, the
    /// tasks it spawns, and what they await.
    @Test func runsOnTheCallingThread() throws {
        let rt = Runtime.currentThread()
        defer { rt.shutdown() }
        #expect(rt.isCurrentThread)
        #expect(rt.workerCount == 1)
        let caller = pthread_self_id()
        let threads = try rt.block { () async throws -> [Int] in
            var seen = [pthread_self_id()]
            let child = rt.spawn { () async throws -> Int in
                try await Runtime.sleep(for: .milliseconds(5))
                return pthread_self_id()
            }
            await Runtime.yield()
            seen.append(pthread_self_id())
            seen.append(try await child.value)
            return seen
        }
        #expect(threads.allSatisfy { $0 == caller })
    }

    /// A task spawned outside block waits for the next one to run.
    @Test func spawnedTasksRunDuringTheNextBlock() throws {
        let rt = Runtime.currentThread()
        defer { rt.shutdown() }
        let ran = Atomic<Bool>(false)
        try withUnsafePointer(to: ran) { p in
            nonisolated(unsafe) let ran = p
            rt.spawn { ran.pointee.store(true, ordering: .relaxed) }
            usleep(20_000)
            let early = ran.pointee.load(ordering: .relaxed)
            #expect(!early)
            try rt.block { () async throws in try await Runtime.sleep(for: .milliseconds(1)) }
            let after = ran.pointee.load(ordering: .relaxed)
            #expect(after)
        }
    }

    /// Several blocks in a row, from different threads.
    @Test func blocksFromSeveralThreads() throws {
        let rt = Runtime.currentThread()
        defer { rt.shutdown() }
        #expect(rt.block { 1 } == 1)
        let other = Atomic<Int>(0)
        withUnsafePointer(to: other) { p in
            nonisolated(unsafe) let other = p
            let t = Thread { other.pointee.store(rt.block { 2 }, ordering: .relaxed) }
            t.join()
        }
        let fromOther = other.load(ordering: .relaxed)
        #expect(fromOther == 2)
        #expect(rt.block { 3 } == 3)
    }

    #if os(Linux) || canImport(Darwin)
    /// I/O on the driving thread: a TCP echo, both ends on this runtime.
    @Test func tcpEchoOnOneThread() throws {
        let rt = Runtime.currentThread()
        defer { rt.shutdown() }
        #expect(rt.ioBackend == .readiness)
        let reply = try rt.block { () async throws -> String in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            async let reply = roundTrip(port: listener.localPort, message: "one thread")
            let conn = try await listener.accept()
            var buf = IOBuffer(capacity: 64)
            try await readExactly(conn, 10, into: &buf)
            try await conn.write(buf)
            return try await reply
        }
        #expect(reply == "one thread")
    }
    #endif

    @Test func blockingJobsAndTimers() throws {
        let rt = Runtime.currentThread()
        defer { rt.shutdown() }
        let (n, timedOut) = try rt.block { () async throws -> (Int, Bool) in
            let n = await Runtime.blocking { 6 * 7 }
            do {
                try await Runtime.timeout(.milliseconds(10)) { try await Runtime.sleep(for: .seconds(5)) }
                return (n, false)
            } catch is TimeoutError {
                return (n, true)
            }
        }
        #expect(n == 42)
        #expect(timedOut)
    }
}

/// A plain thread, for tests that need a second caller of `block`.
private final class Thread: @unchecked Sendable {
    private let body: @Sendable () -> Void
    private let finished = cv_parker_new()!
    private let done = Atomic<Bool>(false)

    init(_ body: @escaping @Sendable () -> Void) {
        self.body = body
        let rc = cv_thread_spawn({ raw in
            let t = Unmanaged<Thread>.fromOpaque(raw!).takeRetainedValue()
            t.body()
            t.done.store(true, ordering: .releasing)
            cv_unpark(t.finished)
        }, Unmanaged.passRetained(self).toOpaque(), "test-caller", -1)
        precondition(rc == 0)
    }

    deinit { cv_parker_free(finished) }

    func join() {
        while !done.load(ordering: .acquiring) { cv_park(finished, -1) }
    }
}
