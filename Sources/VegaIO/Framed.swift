import Vega

/// Items read from a byte stream with a `Decoder`: Tokio's `FramedRead`.
///
/// ```swift
/// var lines = FramedRead(reading: stream, decoder: LinesCodec())
/// while let line = try await lines.next() { print(line) }
/// ```
///
/// Bytes are read into one buffer and decoded in place: a frame costs no
/// copy beyond what its decoder makes, and the buffer is compacted only
/// once most of it has been decoded. It grows for frames bigger than it.
public struct FramedRead<Reader: AsyncReader & ~Copyable, Decoding: Decoder>: ~Copyable {
    public var reader: Reader
    public var decoder: Decoding
    private var buffer: IOBuffer
    /// Bytes `start..<buffer.count` are not decoded yet.
    private var start = 0
    private var ended = false

    public init(reading reader: consuming Reader, decoder: Decoding, capacity: Int = 8 * 1024) {
        self.reader = reader
        self.decoder = decoder
        buffer = IOBuffer(capacity: capacity)
    }

    /// The next item; nil once the stream has ended and every byte has been
    /// decoded.
    public mutating func next() async throws(FramedError) -> Decoding.Item? {
        while true {
            // Offered even when empty: a decoder may have an item that needs
            // no more bytes (the end of an HTTP message without a body).
            let s = start
            let decoded: (item: Decoding.Item, consumed: Int)?
            do throws(CodecError) {
                decoded = try buffer.withUnsafeBytes { all throws(CodecError) in
                    let rest = UnsafeRawBufferPointer(rebasing: all[s...])
                    return ended ? try decoder.decodeAtEnd(rest) : try decoder.decode(rest)
                }
            } catch {
                throw .codec(error)
            }
            if let decoded {
                precondition(decoded.consumed >= 0 && decoded.consumed <= buffer.count - s,
                             "a Decoder consumed a bad byte count")
                start += decoded.consumed
                return decoded.item
            }
            if ended {
                // decodeAtEnd declined the leftovers.
                start = buffer.count
                return nil
            }
            try await fill()
        }
    }

    /// Read more bytes, making room first: drop what's decoded, then grow
    /// if the undecoded part fills the buffer.
    private mutating func fill() async throws(FramedError) {
        if start > 0 {
            buffer.consume(start)
            start = 0
        }
        if buffer.spareCapacity == 0 { buffer.reserveCapacity(buffer.capacity * 2) }
        do throws(IOError) {
            if try await reader.read(into: &buffer) == 0 { ended = true }
        } catch {
            throw .io(error)
        }
    }

    /// Put `bytes` ahead of what is still to be decoded: bytes already read
    /// from the stream for something else, such as a sniffed preface or a
    /// stream type.
    public mutating func prepend(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        let s = start
        var merged = IOBuffer(capacity: max(buffer.capacity, bytes.count + buffer.count - s))
        _ = bytes.withUnsafeBytes { merged.append($0) }
        _ = buffer.withUnsafeBytes { merged.append(UnsafeRawBufferPointer(rebasing: $0[s...])) }
        buffer = merged
        start = 0
    }

    /// Give back the reader, with any bytes read but not decoded lost.
    public consuming func intoReader() -> Reader {
        reader
    }

    /// The bytes read but not decoded yet: after a protocol switch (an HTTP
    /// upgrade), what arrived with the request for the new protocol. Take
    /// them before `intoReader()`.
    public var leftover: [UInt8] {
        let s = start
        return buffer.withUnsafeBytes { Array($0[s...]) }
    }
}

extension FramedRead where Reader: ~Copyable {
    /// The items as an `AsyncSequence`, for `for try await` and the
    /// sequence algorithms:
    ///
    /// ```swift
    /// for try await line in FramedRead(reading: stream, decoder: LinesCodec()).items() { ... }
    /// ```
    public consuming func items() -> FramedItems<Reader, Decoding> {
        FramedItems(self)
    }
}

/// A `FramedRead`'s items as an `AsyncSequence` (`FramedRead.items()`). It
/// reads one stream, so it can be iterated once: two iterators at the same
/// time trap.
public struct FramedItems<Reader: AsyncReader & ~Copyable, Decoding: Decoder>: AsyncSequence {
    public typealias Element = Decoding.Item
    public typealias Failure = FramedError

    final class Box {
        var framed: FramedRead<Reader, Decoding>
        init(_ framed: consuming FramedRead<Reader, Decoding>) { self.framed = framed }
    }

    let box: Box

    init(_ framed: consuming FramedRead<Reader, Decoding>) {
        box = Box(framed)
    }

    public func makeAsyncIterator() -> Iterator { Iterator(box: box) }

    public struct Iterator: AsyncIteratorProtocol {
        let box: Box

        public mutating func next() async throws(FramedError) -> Decoding.Item? {
            try await box.framed.next()
        }

        public mutating func next(isolation actor: isolated (any Actor)?) async throws(FramedError) -> Decoding.Item? {
            try await box.framed.next()
        }
    }
}

/// Items written to a byte stream with an `Encoder`: Tokio's `FramedWrite`.
///
/// `feed` encodes into a buffer; `flush` writes it out. `send` does both.
/// Feeding several items before one flush writes them with one syscall.
public struct FramedWrite<Writer: AsyncWriter & ~Copyable, Encoding: Encoder>: ~Copyable {
    public var writer: Writer
    public var encoder: Encoding
    private var buffer: IOBuffer
    /// `feed` flushes on its own once this much is buffered.
    public var highWaterMark: Int

    public init(writing writer: consuming Writer, encoder: Encoding, capacity: Int = 8 * 1024,
                highWaterMark: Int = 128 * 1024) {
        self.writer = writer
        self.encoder = encoder
        self.highWaterMark = highWaterMark
        buffer = IOBuffer(capacity: capacity)
    }

    /// Encode `item` into the buffer, writing the buffer out first if it
    /// has passed the high-water mark.
    public mutating func feed(_ item: Encoding.Item) async throws(FramedError) {
        if buffer.count >= highWaterMark { try await flush() }
        do throws(CodecError) {
            try encoder.encode(item, into: &buffer)
        } catch {
            throw .codec(error)
        }
    }

    /// Write out everything buffered.
    public mutating func flush() async throws(FramedError) {
        guard !buffer.isEmpty else { return }
        do throws(IOError) {
            try await writer.write(buffer)
        } catch {
            throw .io(error)
        }
        buffer.clear()
    }

    /// `feed`, then `flush`.
    public mutating func send(_ item: Encoding.Item) async throws(FramedError) {
        try await feed(item)
        try await flush()
    }

    /// Give back the writer, with anything not flushed lost.
    public consuming func intoWriter() -> Writer {
        writer
    }
}
