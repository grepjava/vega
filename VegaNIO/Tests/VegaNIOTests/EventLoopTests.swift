import NIOConcurrencyHelpers
import NIOCore
import Testing
import class Vega.Runtime
@testable import VegaNIO

@Suite struct EventLoopTests {
    @Test func executeRunsInOrderOnTheLoop() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        #expect(!loop.inEventLoop)
        let seen = NIOLockedValueBox<[Int]>([])
        let futures = (0..<1000).map { i in
            loop.submit {
                loop.preconditionInEventLoop()
                seen.withLockedValue { $0.append(i) }
            }
        }
        try EventLoopFuture.andAllSucceed(futures, on: loop).wait()
        #expect(seen.withLockedValue { $0 } == Array(0..<1000))
    }

    /// Work from many threads at once still runs one at a time.
    @Test func serial() throws {
        let group = VegaEventLoopGroup(loops: 4)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let running = NIOLockedValueBox(0)
        let overlap = NIOLockedValueBox(false)
        let count = NIOLockedValueBox(0)
        let done = loop.makePromise(of: Void.self)
        let total = 8 * 2000
        for _ in 0..<8 {
            group.runtime.spawn {
                for _ in 0..<2000 {
                    loop.execute {
                        if running.withLockedValue({ $0 += 1; return $0 }) > 1 { overlap.withLockedValue { $0 = true } }
                        running.withLockedValue { $0 -= 1 }
                        if count.withLockedValue({ $0 += 1; return $0 }) == total { done.succeed(()) }
                    }
                }
            }
        }
        try done.futureResult.wait()
        #expect(!overlap.withLockedValue { $0 })
    }

    @Test func scheduledTasks() throws {
        let group = VegaEventLoopGroup(loops: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let start = NIODeadline.now()
        let value = try loop.scheduleTask(in: .milliseconds(20)) { () -> Int in
            loop.preconditionInEventLoop()
            return 42
        }.futureResult.wait()
        #expect(value == 42)
        #expect(NIODeadline.now() - start >= .milliseconds(20))

        let ran = NIOLockedValueBox(false)
        let cancelled = loop.scheduleTask(in: .milliseconds(20)) { ran.withLockedValue { $0 = true } }
        cancelled.cancel()
        #expect(throws: EventLoopError.self) { try cancelled.futureResult.wait() }
        try loop.scheduleTask(in: .milliseconds(50)) {}.futureResult.wait()
        #expect(!ran.withLockedValue { $0 })

        // Cancelled from the loop just before it would run: it doesn't.
        let late = NIOLockedValueBox(false)
        try loop.submit {
            let s = loop.scheduleTask(deadline: .now()) { late.withLockedValue { $0 = true } }
            s.cancel()
        }.wait()
        try loop.scheduleTask(in: .milliseconds(10)) {}.futureResult.wait()
        #expect(!late.withLockedValue { $0 })
    }

    @Test func repeatedTask() throws {
        let group = VegaEventLoopGroup(loops: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let count = NIOLockedValueBox(0)
        let done = loop.makePromise(of: Void.self)
        loop.scheduleRepeatedTask(initialDelay: .milliseconds(1), delay: .milliseconds(1)) { task in
            if count.withLockedValue({ $0 += 1; return $0 }) == 5 {
                task.cancel()
                done.succeed(())
            }
        }
        try done.futureResult.wait()
        #expect(count.withLockedValue { $0 } == 5)
    }

    /// Swift tasks isolated to a loop run on it.
    @Test func serialExecutor() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()
        let rt = group.runtime
        let result = try rt.block {
            let counter = LoopCounter(loop: loop)
            await withTaskGroup(of: Void.self) { tasks in
                for _ in 0..<100 { tasks.addTask { await counter.bump() } }
            }
            return await counter.value
        }
        #expect(result == 100)
    }

    @Test func anyPrefersTheCurrentLoop() throws {
        let group = VegaEventLoopGroup(loops: 4)
        defer { try? group.syncShutdownGracefully() }
        for _ in 0..<4 {
            let loop = group.next()
            #expect(try loop.submit { group.any() === loop }.wait())
        }
        #expect(Array(group.makeIterator()).count == 4)
    }

    @Test func groupOnASharedRuntime() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let group = VegaEventLoopGroup(runtime: rt, loops: 8)
        #expect(Array(group.makeIterator()).count == 8)
        let sum = try EventLoopFuture.reduce(0, group.makeIterator().map { loop in loop.submit { 1 } }, on: group.next(), +).wait()
        #expect(sum == 8)
        try group.syncShutdownGracefully()
    }
}

actor LoopCounter {
    let loop: EventLoop
    var value = 0
    nonisolated var unownedExecutor: UnownedSerialExecutor { loop.executor.asUnownedSerialExecutor() }

    init(loop: EventLoop) { self.loop = loop }

    func bump() {
        loop.preconditionInEventLoop()
        value += 1
    }
}
