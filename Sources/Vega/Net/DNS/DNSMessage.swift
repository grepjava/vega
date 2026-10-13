// DNS messages (RFC 1035), built and parsed with no I/O. Ported from Garuda.
//
// A reply comes from a socket anyone on the path can write to, so every
// length in it is untrusted. Every read is bounded by the buffer, not by the
// lengths the message claims, and a compression pointer must land strictly
// before itself: the offsets a name walk visits then strictly descend, so a
// pointer loop (the classic way to hang a resolver) can't form.

/// Why a message couldn't be built, or couldn't be believed.
enum DNSError: Error, Equatable {
    /// The message ended inside something it promised.
    case truncated
    /// An empty label, one over 63 bytes, or one of the two label kinds RFC
    /// 1035 reserved.
    case badLabel
    /// A name over the wire format's 255 bytes.
    case nameTooLong
    /// A compression pointer that doesn't go strictly backwards.
    case badPointer
}

/// The record types the resolver reads. Others parse as `.other`: a server
/// may send records nobody asked for, and that mustn't fail the answer.
enum DNSRecordType: UInt16, Equatable {
    case a = 1
    case cname = 5
    case aaaa = 28
}

enum DNSData: Equatable {
    /// 4 bytes for A, 16 for AAAA, in network order.
    case address([UInt8])
    /// The name this one is an alias for.
    case canonicalName(String)
    /// A type the resolver doesn't model.
    case other(UInt16)
}

struct DNSRecord: Equatable {
    /// The name the record is about: after a CNAME, not the name asked for.
    var name: String
    var ttl: UInt32
    var data: DNSData
}

struct DNSResponse: Equatable {
    var id: UInt16
    var isResponse: Bool
    /// The answer didn't fit in a datagram: ask again over TCP. The records
    /// that fitted are here, and aren't the whole answer.
    var isTruncated: Bool
    /// RCODE: 0 success, 3 no such name.
    var responseCode: UInt8
    /// The question as echoed, to check the reply answers what was asked.
    var questionName: String
    var questionType: UInt16
    var answers: [DNSRecord]
}

enum DNSMessage {
    /// Id, flags, and four counts.
    static let headerLength = 12

    /// Write a recursive query into `buffer`, replacing its contents. `id`
    /// should be unpredictable: an off-path attacker who guesses it can
    /// answer first.
    static func encodeQuery(id: UInt16, name: String, type: DNSRecordType,
                            into buffer: inout [UInt8]) throws(DNSError) {
        buffer.removeAll(keepingCapacity: true)
        buffer.reserveCapacity(headerLength + name.utf8.count + 6)
        buffer.append(UInt8(truncatingIfNeeded: id >> 8))
        buffer.append(UInt8(truncatingIfNeeded: id))
        buffer.append(0x01)                         // recursion desired
        buffer.append(0x00)
        buffer.append(0x00); buffer.append(0x01)    // one question
        buffer.append(0x00); buffer.append(0x00)    // no answers
        buffer.append(0x00); buffer.append(0x00)    // no authority records
        buffer.append(0x00); buffer.append(0x00)    // no additional records
        try appendName(name, to: &buffer)
        buffer.append(UInt8(truncatingIfNeeded: type.rawValue >> 8))
        buffer.append(UInt8(truncatingIfNeeded: type.rawValue))
        buffer.append(0x00); buffer.append(0x01)    // class IN
    }

    /// `name` as length-prefixed labels and a root label, uncompressed (a
    /// question holds one name, so there's nothing to share).
    private static func appendName(_ name: String, to buffer: inout [UInt8]) throws(DNSError) {
        var label: [UInt8] = []
        label.reserveCapacity(63)
        var total = 1                      // the root label
        var labels = 0

        func flush() throws(DNSError) {
            // Only the root label is empty, and it's written once, at the end.
            guard !label.isEmpty, label.count <= 63 else { throw .badLabel }
            total += 1 + label.count
            guard total <= 255 else { throw .nameTooLong }
            buffer.append(UInt8(label.count))
            buffer.append(contentsOf: label)
            label.removeAll(keepingCapacity: true)
            labels += 1
        }

        for byte in name.utf8 {
            if byte == UInt8(ascii: ".") {
                try flush()
            } else {
                label.append(byte)
            }
        }
        // A trailing dot is the root, already counted.
        if !label.isEmpty { try flush() }
        guard labels > 0 else { throw .badLabel }
        buffer.append(0)
    }

    /// Parse a reply, every read bounded by the buffer. The id and question
    /// are the resolver's to check: only it knows what it asked.
    static func parse(_ bytes: UnsafeRawBufferPointer) throws(DNSError) -> DNSResponse {
        guard bytes.count >= headerLength else { throw .truncated }
        let id = be16(bytes, 0)
        let flags = be16(bytes, 2)
        let questionCount = Int(be16(bytes, 4))
        let answerCount = Int(be16(bytes, 6))

        var at = headerLength
        var questionName = ""
        var questionType: UInt16 = 0
        for question in 0..<questionCount {
            let (name, next) = try readName(bytes, at)
            at = next
            guard at + 4 <= bytes.count else { throw .truncated }
            if question == 0 {
                questionName = name
                questionType = be16(bytes, at)
            }
            at += 4
        }

        var answers: [DNSRecord] = []
        // Bounded by the bytes present, not the header's count: 65,535
        // answers claimed in a 40-byte datagram mustn't reserve for them all.
        answers.reserveCapacity(min(answerCount, bytes.count / 12))
        for _ in 0..<answerCount {
            let (name, afterName) = try readName(bytes, at)
            at = afterName
            guard at + 10 <= bytes.count else { throw .truncated }
            let type = be16(bytes, at)
            let ttl = UInt32(be16(bytes, at + 4)) << 16 | UInt32(be16(bytes, at + 6))
            let length = Int(be16(bytes, at + 8))
            at += 10
            guard at + length <= bytes.count else { throw .truncated }
            let data: DNSData
            switch type {
            case DNSRecordType.a.rawValue where length == 4,
                 DNSRecordType.aaaa.rawValue where length == 16:
                data = .address(Array(bytes[at..<(at + length)]))
            case DNSRecordType.cname.rawValue:
                // A name in the record may point outside it: bounded by the
                // buffer like every other read.
                data = .canonicalName(try readName(bytes, at).0)
            default:
                data = .other(type)
            }
            at += length
            answers.append(DNSRecord(name: name, ttl: ttl, data: data))
        }

        return DNSResponse(id: id,
                           isResponse: flags & 0x8000 != 0,
                           isTruncated: flags & 0x0200 != 0,
                           responseCode: UInt8(flags & 0x000f),
                           questionName: questionName,
                           questionType: questionType,
                           answers: answers)
    }

    @inline(__always)
    private static func be16(_ bytes: UnsafeRawBufferPointer, _ at: Int) -> UInt16 {
        UInt16(bytes[at]) << 8 | UInt16(bytes[at + 1])
    }

    /// A name, following compression pointers, and the offset just past it
    /// as it appeared in the record (past the first pointer, not past where
    /// that pointer led).
    private static func readName(_ bytes: UnsafeRawBufferPointer,
                                 _ start: Int) throws(DNSError) -> (String, Int) {
        var name: [UInt8] = []
        var at = start
        var after = -1
        while true {
            guard at < bytes.count else { throw .truncated }
            let length = Int(bytes[at])
            if length == 0 {
                at += 1
                if after < 0 { after = at }
                break
            }
            switch length & 0xc0 {
            case 0x00:
                guard at + 1 + length <= bytes.count else { throw .truncated }
                if !name.isEmpty { name.append(UInt8(ascii: ".")) }
                name.append(contentsOf: bytes[(at + 1)..<(at + 1 + length)])
                guard name.count <= 255 else { throw .nameTooLong }
                at += 1 + length
            case 0xc0:
                guard at + 2 <= bytes.count else { throw .truncated }
                let target = (length & 0x3f) << 8 | Int(bytes[at + 1])
                if after < 0 { after = at + 2 }
                // Strictly backwards, so the walk always ends.
                guard target < at else { throw .badPointer }
                at = target
            default:
                throw .badLabel
            }
        }
        return (String(decoding: name, as: UTF8.self), after)
    }
}
