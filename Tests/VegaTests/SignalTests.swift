#if os(Linux) || canImport(Darwin)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif
import Testing
@testable import Vega

// Signals are process-wide and tests run in parallel: each test owns its own
// signal, so no test sees another's deliveries. They signal Vega's
// dispatcher thread rather than the process: under TSan a handler runs only
// once its thread makes an intercepted call, and the kernel may pick the
// main thread, parked in a wait TSan doesn't see.

private func deliver(_ signal: Int32) { #expect(cv_signal_raise(signal) == 0) }

/// The next delivery, or nil if none comes within `ms`.
private func next(_ stream: SignalStream, within ms: Int = 2_000) async -> Int32? {
    let r = try? await Runtime.timeout(.milliseconds(ms)) { () async -> Int32? in
        var it = stream.makeAsyncIterator()
        return await it.next()
    }
    return r ?? nil
}

@Suite struct SignalTests {
    /// A task waiting on the stream wakes when the signal comes.
    @Test func deliversToAWaitingTask() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let got = try rt.block { () async throws(IOError) -> Int32? in
            let stream = try Runtime.signals(SIGUSR1)
            let waiter = rt.spawn { await next(stream) }
            try? await Runtime.sleep(for: .milliseconds(50)) // let it suspend
            deliver(SIGUSR1)
            return await waiter.value
        }
        #expect(got == SIGUSR1)
    }

    /// A signal between making the stream and the first wait is not lost.
    @Test func deliversWhatCameBeforeTheFirstWait() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let got = try rt.block { () async throws(IOError) -> Int32? in
            let stream = try Runtime.signals(SIGUSR2)
            deliver(SIGUSR2)
            return await next(stream)
        }
        #expect(got == SIGUSR2)
    }

    /// Signals that come while nobody waits make one delivery, as in Tokio.
    @Test func coalescesWhileNobodyWaits() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (first, second) = try rt.block { () async throws(IOError) -> (Bool, Bool) in
            var stream = try Runtime.signals(SIGURG)
            for _ in 0..<3 { deliver(SIGURG) }
            // Give the handler and the dispatcher a moment.
            try? await Runtime.sleep(for: .milliseconds(20))
            let first = await stream.recv()
            let again = stream
            return (first, await next(again, within: 200) != nil)
        }
        #expect(first)
        #expect(!second)
    }

    /// Every stream for a signal sees each delivery.
    @Test func everyStreamSeesIt() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let got = try rt.block { () async throws(IOError) -> [Int32?] in
            let a = try Runtime.signals(SIGWINCH), b = try Runtime.signals(SIGWINCH)
            let ta = rt.spawn { await next(a) }, tb = rt.spawn { await next(b) }
            try? await Runtime.sleep(for: .milliseconds(50))
            deliver(SIGWINCH)
            return [await ta.value, await tb.value]
        }
        #expect(got == [SIGWINCH, SIGWINCH])
    }

    /// Cancelling a waiting task ends its iteration.
    @Test func cancellingEndsTheIteration() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (got, elapsed) = try rt.block { () async throws(IOError) -> (Int32??, UInt64) in
            let stream = try Runtime.signals(SIGALRM)
            let waiter = rt.spawn { () async -> Int32? in
                var it = stream.makeAsyncIterator()
                return await it.next()
            }
            try? await Runtime.sleep(for: .milliseconds(50))
            let start = cv_now_ns()
            waiter.cancel()
            let got = await waiter.value
            return (.some(got), (cv_now_ns() - start) / 1_000_000)
        }
        #expect(got == .some(nil))
        #expect(elapsed < 500, "took \(elapsed) ms")
    }

    @Test func refusesSignalsItCannotHandle() {
        for s in [SIGKILL, SIGSTOP, SIGSEGV, SIGILL, SIGFPE, 0, 1_000] {
            #expect(throws: IOError(code: EINVAL)) { _ = try Runtime.signals(s) }
        }
    }
}
#endif
