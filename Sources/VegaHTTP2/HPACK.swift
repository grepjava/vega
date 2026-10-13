// HPACK, HTTP/2 header compression (RFC 7541), ported from aviancore.
//
// The decoder hands each field to a callback as borrowed bytes, valid for
// the call: they point into the static table, the dynamic table's arena,
// or a staging buffer. A header block costs no allocation per field.
//
// The encoder never indexes. Indexing would mean mirroring the peer's
// table to save a few bytes on fields that barely repeat; Huffman-coding
// the literals gets most of the gain without the bookkeeping.

/// Why a header block couldn't be decoded. Each is a COMPRESSION_ERROR.
enum HPACKError: Error, Equatable {
    /// The block ended inside a field.
    case truncated
    /// An index naming no entry, or index 0 where one is needed.
    case badIndex
    /// An integer too large to mean anything.
    case integerOverflow
    /// Padding that isn't all ones, an EOS symbol, or an over-long code.
    case badHuffman
    /// A table size update above what was allowed, or after a field.
    case badTableSize
    /// The decoded fields add up to more than allowed.
    case tooLarge
}

/// The static table as bytes.
enum HPACKStatic {
    static let entries: [(name: [UInt8], value: [UInt8])] =
        HPACKTables.staticTable.map { (Array($0.name.utf8), Array($0.value.utf8)) }

    static var count: Int { entries.count }

    /// The index of the first entry named `name`, or nil.
    static func nameIndex(_ name: UnsafeRawBufferPointer) -> Int? {
        for (i, e) in entries.enumerated() where e.name.count == name.count {
            if e.name.withUnsafeBytes({ $0.elementsEqual(name) }) { return i + 1 }
        }
        return nil
    }
}

// MARK: - Huffman

enum HPACKHuffman {
    /// Canonical decoding tables, derived from the code lengths: deriving
    /// them proves at start-up that the committed table is the canonical
    /// code the decoder assumes.
    struct Tables {
        /// Symbols ordered by (length, code).
        var symbols: [UInt16]
        /// First code of each length, and where its symbols start.
        var firstCode: [UInt32]
        var firstIndex: [Int]
        var count: [Int]
    }

    static let tables: Tables = {
        let lengths = HPACKTables.huffmanLengths
        var count = [Int](repeating: 0, count: 31)
        for l in lengths { count[Int(l)] += 1 }
        var firstCode = [UInt32](repeating: 0, count: 31)
        var firstIndex = [Int](repeating: 0, count: 31)
        var code: UInt32 = 0
        var index = 0
        for len in 1...30 {
            firstCode[len] = code
            firstIndex[len] = index
            index += count[len]
            code = (code &+ UInt32(count[len])) << 1
        }
        var symbols = [UInt16](repeating: 0, count: lengths.count)
        var cursor = firstIndex
        for (symbol, l) in lengths.enumerated() {
            symbols[cursor[Int(l)]] = UInt16(symbol)
            cursor[Int(l)] += 1
        }
        return Tables(symbols: symbols, firstCode: firstCode, firstIndex: firstIndex, count: count)
    }()

    /// Whether the committed codes are the ones the lengths imply.
    static func tablesAreCanonical() -> Bool {
        let t = tables
        for (symbol, l) in HPACKTables.huffmanLengths.enumerated() {
            let len = Int(l)
            guard let position = (0..<t.count[len]).first(where: { t.symbols[t.firstIndex[len] + $0] == UInt16(symbol) })
            else { return false }
            if t.firstCode[len] &+ UInt32(position) != HPACKTables.huffmanCodes[symbol] { return false }
        }
        return true
    }

    /// Decode `input`, appending to `out`.
    static func decode(_ input: UnsafeRawBufferPointer, into out: inout [UInt8]) throws(HPACKError) {
        let t = tables
        var code: UInt32 = 0
        var len = 0
        for byte in input {
            for bit in stride(from: 7, through: 0, by: -1) {
                code = code << 1 | UInt32(byte >> UInt8(bit) & 1)
                len += 1
                if len > 30 { throw .badHuffman }
                if len < 5 { continue }
                let c = t.count[len]
                if c == 0 { continue }
                let offset = code &- t.firstCode[len]
                if offset >= UInt32(c) { continue }
                let symbol = t.symbols[t.firstIndex[len] + Int(offset)]
                // 256 is EOS, which never appears in a literal.
                if symbol > 255 { throw .badHuffman }
                out.append(UInt8(truncatingIfNeeded: symbol))
                code = 0
                len = 0
            }
        }
        // What's left must be a short prefix of EOS: all ones, under 8 bits.
        if len >= 8 { throw .badHuffman }
        if len > 0 && code != (UInt32(1) << UInt32(len)) &- 1 { throw .badHuffman }
    }

    static func encodedLength(_ input: UnsafeRawBufferPointer) -> Int {
        var bits = 0
        for byte in input { bits += Int(HPACKTables.huffmanLengths[Int(byte)]) }
        return (bits + 7) / 8
    }

    static func encode(_ input: UnsafeRawBufferPointer, into out: inout [UInt8]) {
        var accumulator: UInt64 = 0
        var bits = 0
        for byte in input {
            let len = Int(HPACKTables.huffmanLengths[Int(byte)])
            accumulator = accumulator << UInt64(len) | UInt64(HPACKTables.huffmanCodes[Int(byte)])
            bits += len
            while bits >= 8 {
                bits -= 8
                out.append(UInt8(truncatingIfNeeded: accumulator >> UInt64(bits)))
            }
        }
        if bits > 0 {
            // Pad with the start of EOS, which is all ones.
            let pad = 8 - bits
            out.append(UInt8(truncatingIfNeeded: accumulator << UInt64(pad) | (1 << UInt64(pad) - 1)))
        }
    }
}

// MARK: - Integers

/// An RFC 7541 integer with a `prefixBits`-bit prefix at `cursor`.
func hpackReadInteger(_ p: UnsafeRawBufferPointer, _ cursor: inout Int, prefixBits: Int) throws(HPACKError) -> Int {
    guard cursor < p.count else { throw .truncated }
    let mask = (1 << prefixBits) - 1
    var value = Int(p[cursor]) & mask
    cursor += 1
    if value < mask { return value }
    var shift = 0
    while true {
        guard cursor < p.count else { throw .truncated }
        let byte = p[cursor]
        cursor += 1
        if shift > 21 { throw .integerOverflow }
        value += Int(byte & 0x7F) << shift
        if value > 1 << 30 { throw .integerOverflow }
        if byte & 0x80 == 0 { return value }
        shift += 7
    }
}

func hpackWriteInteger(_ value: Int, prefixBits: Int, flags: UInt8, into out: inout [UInt8]) {
    let mask = (1 << prefixBits) - 1
    if value < mask {
        out.append(flags | UInt8(value))
        return
    }
    out.append(flags | UInt8(mask))
    var rest = value - mask
    while rest >= 0x80 {
        out.append(UInt8(truncatingIfNeeded: rest & 0x7F | 0x80))
        rest >>= 7
    }
    out.append(UInt8(truncatingIfNeeded: rest))
}

// MARK: - Decoder

struct HPACKDecoder {
    /// A dynamic table entry, as offsets into `arena`.
    private struct Entry {
        var offset: Int
        var nameCount: Int
        var valueCount: Int
        /// RFC 7541 4.1: an entry's size counts 32 bytes of overhead.
        var cost: Int { nameCount + valueCount + 32 }
    }

    private var arena: [UInt8] = []
    /// Bytes before this in the arena belong to evicted entries.
    private var liveStart = 0
    /// Oldest first; HPACK index 62 is the newest.
    private var entries: [Entry] = []
    private(set) var tableSize = 0
    /// The size in force, which the peer may lower at will.
    private(set) var maxTableSize: Int
    /// The largest size we've told the peer it may use.
    private var permittedMaxSize: Int
    private var staging: [UInt8] = []

    init(maxTableSize: Int = 4096) {
        self.maxTableSize = maxTableSize
        permittedMaxSize = maxTableSize
    }

    var dynamicEntryCount: Int { entries.count }

    private mutating func setMaxSize(_ n: Int) {
        maxTableSize = n
        evictToFit(0)
    }

    private mutating func evictToFit(_ incoming: Int) {
        while tableSize + incoming > maxTableSize, !entries.isEmpty {
            let victim = entries.removeFirst()
            tableSize -= victim.cost
            liveStart = victim.offset + victim.nameCount + victim.valueCount
        }
        if entries.isEmpty {
            tableSize = 0
            arena.removeAll(keepingCapacity: true)
            liveStart = 0
        }
    }

    private mutating func insert(_ field: UnsafeRawBufferPointer, nameCount: Int) {
        let cost = field.count + 32
        evictToFit(cost)
        // An entry bigger than the table empties it and isn't stored.
        if cost > maxTableSize { return }
        // Drop the evicted bytes once they dominate the arena.
        if liveStart > 0 && arena.count > 4 * maxTableSize + 4096 {
            arena.removeFirst(liveStart)
            for i in entries.indices { entries[i].offset -= liveStart }
            liveStart = 0
        }
        entries.append(Entry(offset: arena.count, nameCount: nameCount, valueCount: field.count - nameCount))
        arena.append(contentsOf: field)
        tableSize += cost
    }

    /// Call `body` with the name and value at table `index`.
    private func withEntry<R>(_ index: Int, _ body: (UnsafeRawBufferPointer, UnsafeRawBufferPointer) -> R) throws(HPACKError) -> R {
        if index <= HPACKStatic.count {
            guard index > 0 else { throw .badIndex }
            let e = HPACKStatic.entries[index - 1]
            return e.name.withUnsafeBytes { n in e.value.withUnsafeBytes { v in body(n, v) } }
        }
        let position = entries.count - (index - HPACKStatic.count)
        guard position >= 0 && position < entries.count else { throw .badIndex }
        let e = entries[position]
        return arena.withUnsafeBytes { a in
            body(UnsafeRawBufferPointer(rebasing: a[e.offset..<e.offset + e.nameCount]),
                 UnsafeRawBufferPointer(rebasing: a[e.offset + e.nameCount..<e.offset + e.nameCount + e.valueCount]))
        }
    }

    /// Decode one header block, calling `emit` with each field in order.
    ///
    /// The dynamic table changes as the block is read, so a block whose
    /// fields will be refused must still be decoded whole: skipping one
    /// would decode every later block wrongly.
    mutating func decode(_ p: UnsafeRawBufferPointer, sizeLimit: Int = .max,
                         emit: (UnsafeRawBufferPointer, UnsafeRawBufferPointer) -> Void) throws(HPACKError) {
        var cursor = 0
        var decodedSize = 0
        var sawField = false
        while cursor < p.count {
            let first = p[cursor]
            if first & 0x80 != 0 {
                // An indexed field.
                let index = try hpackReadInteger(p, &cursor, prefixBits: 7)
                let size = try withEntry(index) { n, v in
                    emit(n, v)
                    return n.count + v.count + 32
                }
                decodedSize += size
                if decodedSize > sizeLimit { throw .tooLarge }
                sawField = true
                continue
            }
            if first & 0xE0 == 0x20 {
                // A table size update: only before the first field.
                if sawField { throw .badTableSize }
                let size = try hpackReadInteger(p, &cursor, prefixBits: 5)
                if size > permittedMaxSize { throw .badTableSize }
                setMaxSize(size)
                continue
            }
            // A literal, added to the table or not.
            let indexing = first & 0xC0 == 0x40
            let nameIndex = try hpackReadInteger(p, &cursor, prefixBits: indexing ? 6 : 4)
            // Name and value are staged together, so adding them to the
            // table can't move the bytes `emit` sees.
            staging.removeAll(keepingCapacity: true)
            if nameIndex == 0 {
                try Self.readString(p, &cursor, into: &staging)
            } else {
                var name: [UInt8] = []
                try withEntry(nameIndex) { n, _ in name.append(contentsOf: n) }
                staging.append(contentsOf: name)
            }
            let nameCount = staging.count
            try Self.readString(p, &cursor, into: &staging)
            decodedSize += staging.count + 32
            if decodedSize > sizeLimit { throw .tooLarge }
            let field = staging
            field.withUnsafeBytes { f in
                if indexing { insert(f, nameCount: nameCount) }
                emit(UnsafeRawBufferPointer(rebasing: f[..<nameCount]), UnsafeRawBufferPointer(rebasing: f[nameCount...]))
            }
            sawField = true
        }
    }

    /// One length-prefixed string literal, appended to `out`.
    private static func readString(_ p: UnsafeRawBufferPointer, _ cursor: inout Int, into out: inout [UInt8]) throws(HPACKError) {
        guard cursor < p.count else { throw .truncated }
        let huffman = p[cursor] & 0x80 != 0
        let length = try hpackReadInteger(p, &cursor, prefixBits: 7)
        guard length <= p.count - cursor else { throw .truncated }
        let bytes = UnsafeRawBufferPointer(rebasing: p[cursor..<cursor + length])
        cursor += length
        if huffman {
            try HPACKHuffman.decode(bytes, into: &out)
        } else {
            out.append(contentsOf: bytes)
        }
    }
}

// MARK: - Encoder

/// Stateless: each field is a literal without indexing, with a static
/// name index where there is one.
enum HPACKEncoder {
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

    static func encode(name: String, value: String, into out: inout [UInt8]) {
        if let index = staticIndex(name, value) {
            hpackWriteInteger(index, prefixBits: 7, flags: 0x80, into: &out)
            return
        }
        var name = name, value = value
        name.withUTF8 { n in
            value.withUTF8 { v in encode(name: UnsafeRawBufferPointer(n), value: UnsafeRawBufferPointer(v), into: &out) }
        }
    }

    static func encode(name: UnsafeRawBufferPointer, value: UnsafeRawBufferPointer, into out: inout [UInt8]) {
        if let index = HPACKStatic.nameIndex(name) {
            hpackWriteInteger(index, prefixBits: 4, flags: 0, into: &out)
        } else {
            out.append(0)
            encodeString(name, into: &out)
        }
        encodeString(value, into: &out)
    }

    static func encodeString(_ s: UnsafeRawBufferPointer, into out: inout [UInt8]) {
        let huffmanLength = HPACKHuffman.encodedLength(s)
        if huffmanLength < s.count {
            hpackWriteInteger(huffmanLength, prefixBits: 7, flags: 0x80, into: &out)
            HPACKHuffman.encode(s, into: &out)
        } else {
            hpackWriteInteger(s.count, prefixBits: 7, flags: 0, into: &out)
            out.append(contentsOf: s)
        }
    }
}
