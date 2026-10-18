import VegaWire
import VegaHTTP
@_spi(Garuda) import VegaHTTP2Core

/// A header block to send, encoded with VegaWire's HPACK.
///
/// Stateless, as the encoder always was here: each field is a literal without
/// indexing, so no block depends on another and the peer's table is never
/// touched. A field whose name and value are a whole static entry takes that
/// entry's index instead (`:method GET` is one byte), and one whose name alone
/// is in the static table takes the name's index.
struct HeaderBlockEncoder: ~Copyable {
    private var buffer = ByteBuffer()
    private let encoder = HPACKEncoder()

    init() {}

    deinit {
        var buffer = buffer
        buffer.destroy()
    }

    /// A whole static entry, for the commonest pseudo-header values.
    static func staticIndex(_ name: String, _ value: String) -> Int? {
        switch (name, value) {
        case (":method", "GET"): 2
        case (":method", "POST"): 3
        case (":path", "/"): 4
        case (":path", "/index.html"): 5
        case (":scheme", "http"): 6
        case (":scheme", "https"): 7
        case (":status", "200"): 8
        case (":status", "204"): 9
        case (":status", "206"): 10
        case (":status", "304"): 11
        case (":status", "400"): 12
        case (":status", "404"): 13
        case (":status", "500"): 14
        default: nil
        }
    }

    mutating func add(name: String, value: String) {
        if let index = Self.staticIndex(name, value) {
            hpackWriteInteger(index, prefixBits: 7, flags: 0x80, into: &buffer)
            return
        }
        var name = name, value = value
        name.withUTF8 { n in
            value.withUTF8 { v in
                encoder.encode(name: n.baseAddress ?? Self.empty, nameLength: n.count,
                               value: v.baseAddress ?? Self.empty, valueLength: v.count, into: &buffer)
            }
        }
    }

    /// The block as bytes.
    var bytes: [UInt8] {
        let n = buffer.readableBytes
        guard n > 0 else { return [] }
        return Array(UnsafeBufferPointer(start: buffer.readPointer, count: n))
    }

    /// Where an empty string's bytes are said to be: never read.
    nonisolated(unsafe) private static let empty: UnsafePointer<UInt8> = {
        let p = UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
        p.initialize(to: 0)
        return UnsafePointer(p)
    }()
}

extension HPACKDecoder {
    /// Decodes a received header block into `fields`.
    mutating func decode(_ block: [UInt8], sizeLimit: Int, into fields: inout DecodedFields) throws {
        guard !block.isEmpty else { return }
        try block.withUnsafeBufferPointer { b in
            try decode(b.baseAddress!, b.count, sizeLimit: sizeLimit) { field in
                fields.add(UnsafeRawBufferPointer(start: field.name, count: field.nameLength),
                           UnsafeRawBufferPointer(start: field.value, count: field.valueLength))
            }
        }
    }
}
