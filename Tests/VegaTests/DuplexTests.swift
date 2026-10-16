#if os(Linux) || canImport(Darwin) || os(Windows)
import Testing
import Vega
import VegaIO
import VegaTest

@Suite struct DuplexTests {
    /// An echo server over a pipe much smaller than the data: every write
    /// waits on the reader, and everything comes back in order.
    @Test func echoThroughATinyBuffer() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let sent = (0..<100_000).map { UInt8(truncatingIfNeeded: $0 &* 31) }
        let echoed = try rt.block { () async throws -> [UInt8] in
            let pair = duplex(capacity: 7)
            rt.spawn(with: pair.second) { s in _ = try? await copy(from: s, to: s, bufferSize: 5) }
            let client = pair.first.split()
            rt.spawn(with: client.writer) { w in try? await w.write(IOBuffer(copying: sent)) }
            var got = IOBuffer(capacity: sent.count)
            while got.count < sent.count {
                if try await client.reader.read(into: &got) == 0 { break }
            }
            return got.withUnsafeBytes { Array($0) }
        }
        #expect(echoed == sent)
    }

    /// Dropping an end delivers what it wrote, then end of stream.
    @Test func droppingAnEndEndsTheStream() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let (text, end) = try rt.block { () async throws -> (String, Int) in
            let pair = duplex()
            let a = pair.first, b = pair.second
            try await a.write(IOBuffer(copying: Array("bye".utf8)))
            _ = consume a
            var buf = IOBuffer(capacity: 16)
            _ = try await readAtLeast(16, from: b, into: &buf)
            let end = try await b.read(into: &buf)
            return (buf.string, end)
        }
        #expect(text == "bye")
        #expect(end == 0)
    }

    /// `shutdownWrite` ends one direction; the other still works.
    @Test func halfClose() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let (end, reply) = try rt.block { () async throws -> (Int, String) in
            let pair = duplex()
            let a = pair.first, b = pair.second
            a.shutdownWrite()
            var buf = IOBuffer(capacity: 8)
            let end = try await b.read(into: &buf)
            try await b.write(IOBuffer(copying: Array("ok".utf8)))
            _ = try await a.read(into: &buf)
            return (end, buf.string)
        }
        #expect(end == 0)
        #expect(reply == "ok")
    }

    @Test func writingToADroppedEndIsABrokenPipe() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let error = try rt.block { () async throws -> IOError? in
            let pair = duplex(capacity: 4)
            let a = pair.first, b = pair.second
            _ = consume b
            do {
                try await a.write(IOBuffer(copying: [1, 2, 3]))
                return nil
            } catch {
                return error as? IOError
            }
        }
        #expect(error == .brokenPipe)
    }

    /// A writer blocked on a full pipe is woken by the reader going away.
    @Test func blockedWriterSeesTheReaderLeave() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let error = try rt.block { () async throws -> IOError? in
            let pair = duplex(capacity: 4)
            let a = pair.first, b = pair.second
            let writer = rt.spawn(with: a) { a -> IOError? in
                do throws(IOError) {
                    try await a.write(IOBuffer(copying: [UInt8](repeating: 0, count: 64)))
                    return nil
                } catch {
                    return error
                }
            }
            try await Runtime.sleep(for: .milliseconds(10))
            _ = consume b
            return await writer.value
        }
        #expect(error == .brokenPipe)
    }

    /// Cancelling a waiting read ends it with `.cancelled`; the stream still
    /// works afterwards.
    @Test func cancelledReadLeavesTheStreamUsable() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (error, after) = try rt.block { () async throws -> (IOError?, String) in
            let pair = duplex()
            let a = pair.first, b = pair.second
            let reader = rt.spawn(with: b) { b -> (IOError?, String) in
                var buf = IOBuffer(capacity: 8)
                var first: IOError?
                do throws(IOError) {
                    _ = try await b.read(into: &buf)
                } catch {
                    first = error
                }
                // Still cancelled, so wait without parking: a read with
                // bytes ready doesn't park.
                while b.available == 0 { await Runtime.yield() }
                _ = try? await b.read(into: &buf)
                return (first, buf.string)
            }
            try await Runtime.sleep(for: .milliseconds(10))
            reader.cancel()
            try await Runtime.sleep(for: .milliseconds(10))
            try await a.write(IOBuffer(copying: Array("hi".utf8)))
            return await reader.value
        }
        #expect(error == .cancelled)
        #expect(after == "hi")
    }

    /// A waiting read ends as a socket's does at its I/O deadline, and when
    /// another task fires the scope's trigger; the task is not cancelled,
    /// and the stream still works afterwards.
    @Test func aWaitingReadEndsAtItsDeadlineOrTrigger() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (deadline, triggered, cancelled, after) = try rt.block {
            () async throws -> (IOError?, IOError?, Bool, String) in
            let pair = duplex()
            let a = pair.first, b = pair.second
            var buf = IOBuffer(capacity: 8)
            var deadline: IOError?
            do throws(IOError) {
                _ = try await Runtime.withIODeadline(.milliseconds(20)) { () async throws(IOError) -> Int in
                    try await b.read(into: &buf)
                }
            } catch {
                deadline = error
            }
            let trigger = IODeadlineTrigger()
            rt.spawn {
                try? await Runtime.sleep(for: .milliseconds(20))
                trigger.fire()
            }
            var triggered: IOError?
            do throws(IOError) {
                _ = try await Runtime.withIODeadline(.seconds(30), trigger: trigger) { () async throws(IOError) -> Int in
                    try await b.read(into: &buf)
                }
            } catch {
                triggered = error
            }
            try await a.write(IOBuffer(copying: Array("hi".utf8)))
            _ = try await b.read(into: &buf)
            return (deadline, triggered, Task.isCancelled, buf.string)
        }
        #expect(deadline == .timedOut)
        #expect(triggered == .timedOut)
        #expect(!cancelled)
        #expect(after == "hi")
    }

    /// Lines through a duplex pipe with a capacity that splits every line.
    @Test func framedOverDuplex() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let lines = try rt.block { () async throws -> [String] in
            let pair = duplex(capacity: 3)
            let a = pair.first, b = pair.second
            rt.spawn(with: a) { a in
                var out = FramedWrite(writing: a, encoder: LinesCodec())
                for i in 0..<200 { try? await out.feed("line \(i)") }
                try? await out.flush()
            }
            var input = FramedRead(reading: b, decoder: LinesCodec(), capacity: 4)
            var got: [String] = []
            while let line = try await input.next() { got.append(line) }
            return got
        }
        #expect(lines == (0..<200).map { "line \($0)" })
    }
}
#endif
