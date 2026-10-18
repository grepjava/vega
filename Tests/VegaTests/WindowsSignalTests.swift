#if os(Windows)
import CVega
import Testing
@testable import Vega

/// Console control events as signals. Each test owns its signal: they're
/// process-wide and tests run in parallel.
@Suite struct WindowsSignalTests {
    private func next(_ stream: SignalStream) async -> Int32? {
        let r = try? await Runtime.timeout(for: .seconds(2)) { () async -> Int32? in
            var it = stream.makeAsyncIterator()
            return await it.next()
        }
        return r ?? nil
    }

    @Test func ctrlBreakIsDelivered() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let got = try rt.block { () async throws -> [Int32?] in
            let stream = try Runtime.signals(21) // SIGBREAK
            #expect(cv_signal_raise(21) == 0)
            let first = await next(stream)
            // Two before anyone looks: one wake-up, as on POSIX.
            #expect(cv_signal_raise(21) == 0)
            #expect(cv_signal_raise(21) == 0)
            var s = stream
            try await s.recv()
            return [first, s.signal]
        }
        #expect(got == [21, 21])
    }

    @Test func closeArrivesAsSIGTERM() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let got = try rt.block { () async throws -> Int32? in
            let stream = try Runtime.signals(15)
            #expect(cv_signal_raise(15) == 0)
            return await next(stream)
        }
        #expect(got == 15)
    }

    @Test func onlyConsoleSignalsCanBeWatched() {
        for signo: Int32 in [1, 3, 9, 10, 11] {
            #expect(throws: IOError.self) { _ = try Runtime.signals(signo) }
        }
    }
}
#endif
