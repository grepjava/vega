import Testing
@testable import Vega
import VegaIO
import VegaTest

private struct Mismatch: Error {}

@Suite("FaultyStream")
struct FaultTests {
    /// Lines framed and unframed through short reads, split writes and
    /// delays, under many schedules.
    @Test func framingSurvivesFaults() throws {
        try Simulation.run(seeds: 0..<30) { rt in
            let pair = duplex(capacity: 256)
            let plan = FaultPlan(seed: rt.seed ?? 0)
            let writer = rt.spawn(with: FaultyStream(pair.first, plan: plan)) { stream -> Bool in
                var out = FramedWrite(writing: stream, encoder: LinesCodec())
                do {
                    for i in 0..<300 { try await out.feed("line \(i) " + String(repeating: "x", count: i % 37)) }
                    try await out.flush()
                    out.writer.inner.shutdownWrite()
                    return true
                } catch {
                    return false
                }
            }
            var input = FramedRead(reading: FaultyStream(pair.second, plan: FaultPlan(seed: (rt.seed ?? 0) &+ 1)),
                                   decoder: LinesCodec(), capacity: 16)
            var n = 0
            while let line = try await input.next() {
                guard line == "line \(n) " + String(repeating: "x", count: n % 37) else { throw Mismatch() }
                n += 1
            }
            guard await writer.value, n == 300 else { throw Mismatch() }
        }
    }

    @Test func resetSurfaces() throws {
        let errors = try Simulation.run(seeds: 0..<5) { rt -> FramedError? in
            let pair = duplex()
            rt.spawn(with: pair.first) { stream in
                var out = FramedWrite(writing: stream, encoder: LinesCodec())
                for i in 0..<100 { try? await out.feed("line \(i)") }
                try? await out.flush()
            }
            var input = FramedRead(reading: FaultyStream(pair.second, plan: FaultPlan(seed: rt.seed ?? 0, resetAfterRead: 100)),
                                   decoder: LinesCodec())
            do throws(FramedError) {
                while try await input.next() != nil {}
                return nil
            } catch {
                return error
            }
        }
        #expect(errors.allSatisfy { $0 == .io(.connectionReset) })
    }
}
