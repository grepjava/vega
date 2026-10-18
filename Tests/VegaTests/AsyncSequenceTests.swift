import Synchronization
import Testing
@testable import Vega
import VegaIO

private final class Produced: Sendable { let count = Atomic<Int>(0) }

@Suite("AsyncSequence adapters")
struct AsyncSequenceTests {
    /// `FramedRead.items()`: `for try await` over a byte stream's frames.
    @Test func framedItems() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (lines, firstLong) = try rt.block { () async throws -> ([String], String?) in
            let pair = try UnixStream.pair()
            rt.spawn(with: pair.first) { stream in
                var out = FramedWrite(writing: stream, encoder: LinesCodec())
                for i in 0..<500 { try? await out.feed(i % 50 == 0 ? String(repeating: "x", count: 100) : "line \(i)") }
                try? await out.flush()
            }
            var lines: [String] = []
            for try await line in FramedRead(reading: pair.second, decoder: LinesCodec(), capacity: 32).items() {
                lines.append(line)
            }
            // The sequence algorithms work on it too.
            let pair2 = try UnixStream.pair()
            rt.spawn(with: pair2.first) { stream in
                var out = FramedWrite(writing: stream, encoder: LinesCodec())
                for s in ["a", "bb", "cccc", "d"] { try? await out.feed(s) }
                try? await out.flush()
            }
            let first = try await FramedRead(reading: pair2.second, decoder: LinesCodec()).items()
                .first { $0.count > 2 }
            return (lines, first)
        }
        #expect(lines.count == 500)
        #expect(lines[1] == "line 1")
        #expect(lines[50].count == 100)
        #expect(firstLong == "cccc")
    }

    @Test func framedItemsThrowTyped() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let error = try rt.block { () async throws -> FramedError? in
            let pair = try UnixStream.pair()
            rt.spawn(with: pair.first) { stream in
                // A length prefix promising more than ever comes.
                try? await stream.write(IOBuffer(copying: [0, 0, 0, 10, 1, 2]))
            }
            do throws(FramedError) {
                for try await _ in FramedRead(reading: pair.second, decoder: LengthDelimitedCodec()).items() {}
                return nil
            } catch {
                return error
            }
        }
        #expect(error != nil)
    }

    /// `MPSCChannel.Receiver.values()`, ending once the senders are gone.
    @Test func channelValues() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let sum = rt.block { () async -> Int in
            let ch = MPSCChannel<Int>(capacity: 8)
            for p in 0..<4 {
                rt.spawn(with: ch.sender.clone()) { tx in
                    for i in 1...250 { try? await tx.send(p * 1000 + i) }
                }
            }
            _ = consume ch.sender
            var sum = 0
            for await v in ch.receiver.values() { sum += v }
            return sum
        }
        #expect(sum == (0..<4).reduce(0) { $0 + 250 * $1 * 1000 + 250 * 251 / 2 })
    }

    /// A bounded channel holds a fast producer to the consumer's pace: it
    /// is never more than `capacity` values (plus the one in hand) ahead.
    @Test func backpressure() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let produced = Produced()
        let maxAhead = rt.block { () async -> Int in
            let ch = MPSCChannel<Int>(capacity: 4)
            rt.spawn(with: ch.sender) { tx in
                for i in 0..<100 {
                    try? await tx.send(i)
                    produced.count.store(i + 1, ordering: .releasing)
                }
            }
            var maxAhead = 0
            var consumed = 0
            for await _ in ch.receiver.values() {
                consumed += 1
                try? await Runtime.sleep(for: .milliseconds(1))
                maxAhead = max(maxAhead, produced.count.load(ordering: .acquiring) - consumed)
            }
            return maxAhead
        }
        #expect(maxAhead <= 5)
    }

    /// Cancelling the iterating task ends the sequence.
    @Test func channelValuesEndOnCancel() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (got, ended) = rt.block { () async -> (Int, Bool) in
            let ch = MPSCChannel<Int>(capacity: 4)
            try? ch.sender.trySend(1)
            let values = ch.receiver.values()
            let consumer = rt.spawn { () async -> (Int, Bool) in
                var got = 0
                for await _ in values { got += 1 }
                return (got, true)
            }
            try? await Runtime.sleep(for: .milliseconds(20))
            consumer.cancel()
            let result = await consumer.value
            _ = ch.sender
            return result
        }
        #expect(got == 1)
        #expect(ended)
    }
}
