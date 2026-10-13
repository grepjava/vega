#if os(Linux) || canImport(Darwin) || os(Windows)
import Testing
import Vega
import VegaIO

private func decodeAll<D: Decoder>(_ decoder: inout D, _ bytes: [UInt8]) throws -> (items: [D.Item], rest: Int) {
    var items: [D.Item] = []
    var at = 0
    while true {
        let next = try bytes.withUnsafeBytes { all in
            try decoder.decode(UnsafeRawBufferPointer(rebasing: all[at...]))
        }
        guard let next else { return (items, bytes.count - at) }
        items.append(next.item)
        at += next.consumed
    }
}

private func encoded<E: Encoder>(_ encoder: inout E, _ items: [E.Item]) throws(CodecError) -> [UInt8] {
    var buf = IOBuffer(capacity: 4)
    for item in items { try encoder.encode(item, into: &buf) }
    return buf.withUnsafeBytes { Array($0) }
}

@Suite struct CodecTests {
    @Test func lengthDelimitedRoundTrip() throws {
        var codec = LengthDelimitedCodec()
        let frames: [[UInt8]] = [[], [1], Array(0..<200), [UInt8](repeating: 7, count: 70_000)]
        let bytes = try encoded(&codec, frames)
        #expect(Array(bytes[0..<4]) == [0, 0, 0, 0])
        #expect(Array(bytes[4..<9]) == [0, 0, 0, 1, 1])
        let (items, rest) = try decodeAll(&codec, bytes)
        #expect(items == frames)
        #expect(rest == 0)
    }

    @Test func lengthDelimitedWaitsForWholeFrames() throws {
        var codec = LengthDelimitedCodec(lengthFieldSize: 2, bigEndian: false)
        let bytes = try encoded(&codec, [[9, 8, 7]])
        #expect(bytes == [3, 0, 9, 8, 7])
        for cut in 0..<bytes.count {
            let (items, rest) = try decodeAll(&codec, Array(bytes[0..<cut]))
            #expect(items.isEmpty)
            #expect(rest == cut)
        }
    }

    @Test func lengthDelimitedRejectsHugeFrames() {
        var codec = LengthDelimitedCodec(maxFrameLength: 10)
        #expect(throws: CodecError.frameTooLong(11)) {
            _ = try decodeAll(&codec, [0, 0, 0, 11])
        }
        #expect(throws: CodecError.frameTooLong(11)) {
            _ = try encoded(&codec, [[UInt8](repeating: 0, count: 11)])
        }
    }

    @Test func linesSplitOnNewlines() throws {
        var codec = LinesCodec()
        let (items, rest) = try decodeAll(&codec, Array("one\ntwo\r\n\nthree".utf8))
        #expect(items == ["one", "two", ""])
        #expect(rest == 5)
        let bytes = try encoded(&codec, ["a", "bc"])
        #expect(bytes == Array("a\nbc\n".utf8))
    }

    @Test func linesHaveAMaximum() {
        var codec = LinesCodec(maxLength: 4)
        #expect(throws: CodecError.frameTooLong(5)) { _ = try decodeAll(&codec, Array("abcde\n".utf8)) }
        #expect(throws: CodecError.frameTooLong(6)) { _ = try decodeAll(&codec, Array("abcdef".utf8)) }
    }
}

@Suite struct FramedTests {
    /// Lines through a socket pair: written in batches, read back in order,
    /// the last one without a newline.
    @Test func linesOverASocket() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let lines = try rt.block { () async throws -> [String] in
            let pair = try UnixStream.pair()
            let writer = rt.spawn(with: pair.first) { stream -> Bool in
                var out = FramedWrite(writing: stream, encoder: LinesCodec())
                do {
                    for i in 0..<1_000 { try await out.feed("line \(i)") }
                    try await out.flush()
                    // A last line without its newline, then end of stream.
                    let s = out.intoWriter()
                    try await s.write(IOBuffer(copying: Array("tail".utf8)))
                    return true
                } catch {
                    return false
                }
            }
            var input = FramedRead(reading: pair.second, decoder: LinesCodec(), capacity: 64)
            var got: [String] = []
            while let line = try await input.next() { got.append(line) }
            #expect(await writer.value)
            return got
        }
        #expect(lines.count == 1_001)
        #expect(lines.first == "line 0")
        #expect(lines[999] == "line 999")
        #expect(lines.last == "tail")
    }

    /// Frames far bigger than the read buffer: it grows to fit.
    @Test func bigFramesGrowTheBuffer() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let sizes = try rt.block { () async throws -> [Int] in
            let pair = try UnixStream.pair()
            rt.spawn(with: pair.first) { stream in
                var out = FramedWrite(writing: stream, encoder: LengthDelimitedCodec())
                for n in [10, 100_000, 3, 1_000_000] {
                    try? await out.send([UInt8](repeating: UInt8(n % 251), count: n))
                }
            }
            var input = FramedRead(reading: pair.second, decoder: LengthDelimitedCodec(), capacity: 16)
            var sizes: [Int] = []
            while let frame = try await input.next() {
                #expect(frame.allSatisfy { $0 == UInt8(frame.count % 251) })
                sizes.append(frame.count)
            }
            return sizes
        }
        #expect(sizes == [10, 100_000, 3, 1_000_000])
    }

    /// A stream that ends inside a frame is reported, not silently cut.
    @Test func truncatedFrameIsAnError() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let error = try rt.block { () async throws -> FramedError? in
            let pair = try UnixStream.pair()
            try await pair.first.write(IOBuffer(copying: [0, 0, 0, 9, 1, 2]))
            _ = consume pair.first
            var input = FramedRead(reading: pair.second, decoder: LengthDelimitedCodec())
            do {
                _ = try await input.next()
                return nil
            } catch {
                return error as? FramedError
            }
        }
        #expect(error == .codec(.truncated(6)))
    }

    @Test func copyMovesEverything() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let n = try rt.block { () async throws -> Int in
            let a = try UnixStream.pair(), b = try UnixStream.pair()
            rt.spawn(with: a.first) { s in
                let chunk = IOBuffer(copying: [UInt8](repeating: 1, count: 50_000))
                for _ in 0..<10 { try? await s.write(chunk) }
            }
            let reader = rt.spawn(with: b.second) { s -> Int in
                var buf = IOBuffer(capacity: 4096)
                var total = 0
                while let n = try? await s.read(into: &buf), n > 0 {
                    total += n
                    buf.clear()
                }
                return total
            }
            let copied = try await copy(from: a.second, to: b.first)
            _ = consume b.first
            #expect(await reader.value == copied)
            return copied
        }
        #expect(n == 500_000)
    }
}

extension IOBuffer {
    init(copying bytes: UnsafeRawBufferPointer) {
        self.init(capacity: Swift.max(bytes.count, 1))
        append(bytes)
    }

    init(copying bytes: [UInt8]) {
        self.init(capacity: Swift.max(bytes.count, 1))
        bytes.withUnsafeBytes { _ = append($0) }
    }
}
#endif
