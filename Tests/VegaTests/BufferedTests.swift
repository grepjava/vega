import Testing
@testable import Vega
import VegaIO
import VegaTest

@Suite("BufferedReader, BufferedWriter and ContentLengthCodec")
struct BufferedTests {
    @Test func linesAndExactReads() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (lines, exact, tail) = try rt.block { () async throws -> ([String], [UInt8], String?) in
            let pair = duplex(capacity: 64)
            rt.spawn(with: pair.first) { stream in
                let out = BufferedWriter(stream, capacity: 16)
                for i in 0..<50 { try? await out.write("line \(i)\r\n") }
                try? await out.write("BIN")
                try? await out.write(UnsafeRawBufferPointer(start: nil, count: 0))
                try? await out.write("last")
                try? await out.flush()
                out.writer.shutdownWrite()
            }
            let input = BufferedReader(pair.second, capacity: 7)
            var lines: [String] = []
            for _ in 0..<50 { if let line = try await input.readLine() { lines.append(line) } }
            let exact = try await input.readExactly(3)
            let tail = try await input.readLine()
            #expect(try await input.readLine() == nil)
            return (lines, exact, tail)
        }
        #expect(lines.count == 50)
        #expect(lines[49] == "line 49")
        #expect(exact == Array("BIN".utf8))
        #expect(tail == "last")
    }

    @Test func readExactlyAtTheEndThrows() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let error = rt.block { () async -> IOError? in
            let pair = duplex()
            rt.spawn(with: pair.first) { stream in
                try? await stream.write(UnsafeRawBufferPointer(start: [1, 2], count: 0))
                stream.shutdownWrite()
            }
            let input = BufferedReader(pair.second)
            do throws(IOError) {
                _ = try await input.readExactly(4)
                return nil
            } catch {
                return error
            }
        }
        #expect(error == .connectionReset)
    }

    @Test func contentLengthFraming() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let messages = try rt.block { () async throws -> [String] in
            let pair = duplex(capacity: 32)
            rt.spawn(with: pair.first) { stream in
                var out = FramedWrite(writing: stream, encoder: ContentLengthCodec())
                for body in [#"{"jsonrpc":"2.0","id":1}"#, "", String(repeating: "é", count: 100)] {
                    try? await out.feed(Array(body.utf8))
                }
                try? await out.flush()
                // Another header line, which is ignored.
                var extra = IOBuffer(capacity: 128)
                _ = extra.append("Content-Type: application/vscode-jsonrpc\r\nContent-Length: 2\r\n\r\n{}")
                try? await out.writer.write(extra)
                out.writer.shutdownWrite()
            }
            var input = FramedRead(reading: pair.second, decoder: ContentLengthCodec())
            var messages: [String] = []
            while let m = try await input.next() { messages.append(String(decoding: m, as: UTF8.self)) }
            return messages
        }
        #expect(messages == [#"{"jsonrpc":"2.0","id":1}"#, "", String(repeating: "é", count: 100), "{}"])
    }
}
