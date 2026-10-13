// HTTP/1 head and body parsing, ported from aviancore's AvianHTTP.
//
// Strict where strictness prevents request smuggling:
//   * whitespace between a field name and its colon is refused
//   * Content-Length with Transfer-Encoding is refused (in requests)
//   * Content-Lengths that disagree are refused
//   * Transfer-Encoding is read as the list it is: only a final, bare
//     `chunked` frames a body
//   * a second Host field is refused
//   * obs-fold (a continuation line) is refused, not unfolded
//   * bare CR, NUL and other control bytes in a field value are refused

let cCR: UInt8 = 13
let cLF: UInt8 = 10
let cSP: UInt8 = 32
let cHT: UInt8 = 9
let cColon = UInt8(ascii: ":")
let cComma = UInt8(ascii: ",")
let cSemicolon = UInt8(ascii: ";")

/// RFC 9110 `tchar`, as two bitmasks.
@inline(__always)
func isTokenChar(_ c: UInt8) -> Bool {
    if c < 64 { return (0x03FF6CFA00000000 as UInt64) >> UInt64(c) & 1 == 1 }
    if c < 128 { return (0x57FFFFFFC7FFFFFE as UInt64) >> UInt64(c &- 64) & 1 == 1 }
    return false
}

/// Allowed in a field value: VCHAR, SP, HTAB and obs-text.
@inline(__always)
func isFieldValueChar(_ c: UInt8) -> Bool {
    c >= 0x20 ? c != 0x7F : c == cHT
}

@inline(__always)
func asciiLower(_ c: UInt8) -> UInt8 {
    c &- 65 < 26 ? c | 0x20 : c
}

func equalsIgnoringCase(_ a: UnsafeRawBufferPointer, _ b: UnsafeRawBufferPointer) -> Bool {
    guard a.count == b.count else { return false }
    for i in 0..<a.count where asciiLower(a[i]) != asciiLower(b[i]) { return false }
    return true
}

func equalsIgnoringCase(_ a: UnsafeRawBufferPointer, _ b: StaticString) -> Bool {
    equalsIgnoringCase(a, UnsafeRawBufferPointer(start: b.utf8Start, count: b.utf8CodeUnitCount))
}

/// Whether the comma-separated `list` has an element equal to `token`,
/// ignoring case and surrounding whitespace.
func listContains(_ list: UnsafeRawBufferPointer, _ token: UnsafeRawBufferPointer) -> Bool {
    var found = false
    forEachElement(list) { if equalsIgnoringCase($0, token) { found = true } }
    return found
}

/// Each non-empty element of a comma-separated list, trimmed.
func forEachElement(_ list: UnsafeRawBufferPointer, _ body: (UnsafeRawBufferPointer) -> Void) {
    var i = 0
    while i <= list.count {
        var end = i
        while end < list.count, list[end] != cComma { end += 1 }
        var s = i, e = end
        while s < e, list[s] == cSP || list[s] == cHT { s += 1 }
        while e > s, list[e - 1] == cSP || list[e - 1] == cHT { e -= 1 }
        if e > s { body(UnsafeRawBufferPointer(rebasing: list[s..<e])) }
        i = end + 1
    }
}

/// The index just past the empty line that ends a head (or trailer section)
/// starting at or before `from`, or nil if it hasn't arrived.
func findHeadEnd(_ b: UnsafeRawBufferPointer, from: Int) -> Int? {
    var i = from
    while i < b.count {
        guard let lf = b[i...].firstIndex(of: cLF) else { return nil }
        if lf + 1 < b.count, b[lf + 1] == cLF { return lf + 2 }
        if lf + 2 < b.count, b[lf + 1] == cCR, b[lf + 2] == cLF { return lf + 3 }
        i = lf + 1
    }
    return nil
}

/// How a message's fields say its body is framed.
struct Framing {
    enum TransferEncoding { case none, chunked, notChunked, chunkedOverOther }
    var contentLength: Int?
    var transferEncoding = TransferEncoding.none
    var hosts = 0
}

/// Parse field lines from `i` through the empty line that ends them, which
/// is known to be before `end`.
func parseFields(_ b: UnsafeRawBufferPointer, _ i: inout Int, end: Int, maxFields: Int,
                 into fields: inout HTTPFields, framing: inout Framing) throws(HTTP1Error) {
    while true {
        guard i < end else { throw .badHeader }
        if b[i] == cCR {
            guard i + 1 < end, b[i + 1] == cLF else { throw .badHeader }
            i += 2
            return
        }
        if b[i] == cLF { i += 1; return }
        // A line starting with whitespace is obs-fold: unfolding it is how
        // parsers come to disagree, so refuse.
        if b[i] == cSP || b[i] == cHT { throw .badHeader }

        let nameStart = i
        while i < end, isTokenChar(b[i]) { i += 1 }
        // No whitespace allowed between the name and the colon.
        guard i > nameStart, i < end, b[i] == cColon else { throw .badHeader }
        let nameEnd = i
        i += 1
        while i < end, b[i] == cSP || b[i] == cHT { i += 1 }
        let valueStart = i
        while i < end, isFieldValueChar(b[i]) { i += 1 }
        var valueEnd = i
        while valueEnd > valueStart, b[valueEnd - 1] == cSP || b[valueEnd - 1] == cHT { valueEnd -= 1 }
        guard i < end else { throw .badHeader }
        if b[i] == cCR {
            guard i + 1 < end, b[i + 1] == cLF else { throw .badHeader }
            i += 2
        } else if b[i] == cLF {
            i += 1
        } else {
            throw .badHeader // a control byte in the value
        }

        guard fields.count < maxFields else { throw .tooManyFields }
        let name = UnsafeRawBufferPointer(rebasing: b[nameStart..<nameEnd])
        let value = UnsafeRawBufferPointer(rebasing: b[valueStart..<valueEnd])
        fields.append(name: name, value: value)

        switch name.count {
        case 4 where equalsIgnoringCase(name, "host"):
            framing.hosts += 1
        case 14 where equalsIgnoringCase(name, "content-length"):
            let n = try contentLength(value)
            if let seen = framing.contentLength, seen != n { throw .conflictingFraming }
            framing.contentLength = n
        case 17 where equalsIgnoringCase(name, "transfer-encoding"):
            // Repeated fields are one list, so a second one means the first
            // one's codings weren't the last: the body can't be framed.
            guard framing.transferEncoding == .none else { throw .conflictingFraming }
            framing.transferEncoding = transferEncoding(value)
        default:
            break
        }
    }
}

/// A Content-Length value: digits only. A list of equal values ("5, 5"),
/// which RFC 9110 lets a recipient accept, is refused too.
private func contentLength(_ v: UnsafeRawBufferPointer) throws(HTTP1Error) -> Int {
    guard !v.isEmpty, v.count <= 18 else { throw .badHeader }
    var n = 0
    for c in v {
        guard c >= 48, c <= 57 else { throw .badHeader }
        n = n * 10 + Int(c - 48)
    }
    return n
}

/// Reads a Transfer-Encoding value as the list of codings it is (RFC 9112
/// 6.1). A suffix test would take `xchunked`, or take `gzip, chunked` and
/// quietly drop the gzip.
private func transferEncoding(_ v: UnsafeRawBufferPointer) -> Framing.TransferEncoding {
    var codings = 0
    var lastIsChunked = false
    forEachElement(v) {
        codings += 1
        lastIsChunked = equalsIgnoringCase($0, "chunked")
    }
    if !lastIsChunked { return .notChunked }
    return codings == 1 ? .chunked : .chunkedOverOther
}

/// "HTTP/1.0" or "HTTP/1.1" at `i`.
private func version(_ b: UnsafeRawBufferPointer, _ i: Int, end: Int) throws(HTTP1Error) -> HTTPVersion {
    guard end - i >= 8 else { throw .badVersion }
    let prefix: StaticString = "HTTP/1."
    for k in 0..<7 where b[i + k] != prefix.utf8Start[k] { throw .badVersion }
    switch b[i + 7] {
    case 48: return .http1_0
    case 49: return .http1_1
    default: throw .badVersion
    }
}

/// CRLF (or a bare LF) at `i`.
private func lineEnd(_ b: UnsafeRawBufferPointer, _ i: inout Int, end: Int, _ error: HTTP1Error) throws(HTTP1Error) {
    if i < end, b[i] == cLF { i += 1; return }
    guard i + 1 < end, b[i] == cCR, b[i + 1] == cLF else { throw error }
    i += 2
}

/// A whole request head, `b[start..<end]`, `end` just past its empty line.
func parseRequestHead(_ b: UnsafeRawBufferPointer, start: Int, end: Int,
                      maxFields: Int) throws(HTTP1Error) -> (HTTPRequestHead, Framing) {
    var i = start
    let methodStart = i
    while i < end, isTokenChar(b[i]) { i += 1 }
    guard i > methodStart, i < end, b[i] == cSP else { throw .badRequestLine }
    let method = String(decoding: UnsafeRawBufferPointer(rebasing: b[methodStart..<i]), as: UTF8.self)
    i += 1
    let targetStart = i
    while i < end, b[i] > cSP, b[i] != 0x7F { i += 1 }
    guard i > targetStart, i < end, b[i] == cSP else { throw .badRequestLine }
    let target = String(decoding: UnsafeRawBufferPointer(rebasing: b[targetStart..<i]), as: UTF8.self)
    i += 1
    let v = try version(b, i, end: end)
    i += 8
    try lineEnd(b, &i, end: end, .badRequestLine)

    var head = HTTPRequestHead(method: HTTPMethod(rawValue: method), target: target, version: v)
    var framing = Framing()
    try parseFields(b, &i, end: end, maxFields: maxFields, into: &head.fields, framing: &framing)
    if framing.hosts > 1 { throw .duplicateHost }
    if framing.hosts == 0 && v.minor == 1 { throw .missingHost }
    switch framing.transferEncoding {
    case .none: break
    case .chunked:
        // The spec lets Transfer-Encoding win, but a request with both is
        // the shape of a smuggling attempt.
        if framing.contentLength != nil { throw .conflictingFraming }
    case .notChunked: throw .conflictingFraming // no way to find the end
    case .chunkedOverOther: throw .unsupportedTransferEncoding
    }
    return (head, framing)
}

/// A whole response head, `b[start..<end]`.
func parseResponseHead(_ b: UnsafeRawBufferPointer, start: Int, end: Int,
                       maxFields: Int) throws(HTTP1Error) -> (HTTPResponseHead, Framing) {
    var i = start
    let v: HTTPVersion
    do throws(HTTP1Error) { v = try version(b, i, end: end) } catch { throw .badStatusLine }
    i += 8
    guard end - i >= 4, b[i] == cSP else { throw .badStatusLine }
    var status = 0
    for k in 1...3 {
        let c = b[i + k]
        guard c >= 48, c <= 57 else { throw .badStatusLine }
        status = status * 10 + Int(c - 48)
    }
    guard status >= 100 else { throw .badStatusLine }
    i += 4
    var reason = ""
    if i < end, b[i] == cSP {
        i += 1
        let reasonStart = i
        while i < end, isFieldValueChar(b[i]) { i += 1 }
        reason = String(decoding: UnsafeRawBufferPointer(rebasing: b[reasonStart..<i]), as: UTF8.self)
    }
    try lineEnd(b, &i, end: end, .badStatusLine)

    var head = HTTPResponseHead(status: status, reason: reason, version: v)
    var framing = Framing()
    try parseFields(b, &i, end: end, maxFields: maxFields, into: &head.fields, framing: &framing)
    if framing.transferEncoding == .chunkedOverOther { throw .unsupportedTransferEncoding }
    return (head, framing)
}

/// A message body being read.
struct BodyReader {
    enum State {
        /// This many bytes to go (more than zero).
        case fixed(Int)
        /// Up to the next chunk-size line (after the CRLF ending a chunk,
        /// when `afterData`).
        case chunkHeader(afterData: Bool)
        /// This much of the current chunk to go.
        case chunkData(Int)
        /// Everything until the connection closes.
        case untilClose
        /// All read; the end is due.
        case done
    }

    var state: State
    var maxFields: Int
    var maxTrailerSize: Int

    enum Part { case body([UInt8]), end(HTTPFields?) }

    /// The next part from `b`, or nil if it needs more bytes. Chunk framing
    /// is only consumed together with a part, so nothing is lost on nil.
    mutating func next(_ b: UnsafeRawBufferPointer) throws(HTTP1Error) -> (Part, Int)? {
        var i = 0
        var st = state
        while true {
            switch st {
            case .done:
                state = .done
                return (.end(nil), i)
            case .fixed(let n):
                guard i < b.count else { return nil }
                let take = min(n, b.count - i)
                state = take == n ? .done : .fixed(n - take)
                return (.body(Array(b[i..<i + take])), i + take)
            case .untilClose:
                guard i < b.count else { return nil }
                return (.body(Array(b[i...])), b.count)
            case .chunkData(let n):
                guard i < b.count else { return nil }
                let take = min(n, b.count - i)
                state = take == n ? .chunkHeader(afterData: true) : .chunkData(n - take)
                return (.body(Array(b[i..<i + take])), i + take)
            case .chunkHeader(let afterData):
                if afterData {
                    guard b.count - i >= 2 else { return nil }
                    guard b[i] == cCR, b[i + 1] == cLF else { throw .badChunk }
                    i += 2
                }
                guard let lf = b[i...].firstIndex(of: cLF) else {
                    if b.count - i > 4096 { throw .badChunk }
                    return nil
                }
                guard lf > i, b[lf - 1] == cCR else { throw .badChunk }
                var size = 0, digits = 0, k = i
                while k < lf - 1, let d = hexValue(b[k]) {
                    // 15 digits keep the size inside Int with room to spare.
                    guard digits < 15 else { throw .badChunk }
                    size = size << 4 | d
                    digits += 1
                    k += 1
                }
                // Chunk extensions are allowed, and ignored.
                guard digits > 0, k == lf - 1 || b[k] == cSemicolon else { throw .badChunk }
                i = lf + 1
                st = size == 0 ? .done : .chunkData(size)
                if size == 0 { return try trailers(b, i) }
            }
        }
    }

    /// The trailer section after the last chunk, at `i`.
    private mutating func trailers(_ b: UnsafeRawBufferPointer, _ start: Int) throws(HTTP1Error) -> (Part, Int)? {
        guard start < b.count else { return nil }
        if b[start] == cLF {
            state = .done
            return (.end(nil), start + 1)
        }
        if b[start] == cCR {
            guard start + 1 < b.count else { return nil }
            guard b[start + 1] == cLF else { throw .badChunk }
            state = .done
            return (.end(nil), start + 2)
        }
        // Trailers decode to no body bytes, so they need a limit of their own.
        guard let end = findHeadEnd(b, from: start) else {
            if b.count - start > maxTrailerSize { throw .headTooLarge }
            return nil
        }
        if end - start > maxTrailerSize { throw .headTooLarge }
        var fields = HTTPFields()
        var framing = Framing()
        var i = start
        try parseFields(b, &i, end: end, maxFields: maxFields, into: &fields, framing: &framing)
        state = .done
        return (.end(fields), end)
    }

    private func hexValue(_ c: UInt8) -> Int? {
        switch c {
        case 48...57: Int(c - 48)
        case 65...70: Int(c - 55)
        case 97...102: Int(c - 87)
        default: nil
        }
    }
}
