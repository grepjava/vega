@_spi(Garuda) import VegaWire

// Field syntax (RFC 9110 section 5) that every HTTP version's fields share.

/// RFC 9110 `tchar`, as two bitmasks.
@inline(__always)
package func isTokenChar(_ c: UInt8) -> Bool {
    if c < 64 { return (0x03FF6CFA00000000 as UInt64) >> UInt64(c) & 1 == 1 }
    if c < 128 { return (0x57FFFFFFC7FFFFFE as UInt64) >> UInt64(c &- 64) & 1 == 1 }
    return false
}

/// Allowed in a field value: VCHAR, SP, HTAB and obs-text.
@inline(__always)
package func isFieldValueChar(_ c: UInt8) -> Bool {
    c >= 0x20 ? c != 0x7F : c == cHT
}

package func equalsIgnoringCase(_ a: UnsafeRawBufferPointer, _ b: UnsafeRawBufferPointer) -> Bool {
    guard a.count == b.count else { return false }
    for i in 0..<a.count where asciiLower(a[i]) != asciiLower(b[i]) { return false }
    return true
}

package func equalsIgnoringCase(_ a: UnsafeRawBufferPointer, _ b: StaticString) -> Bool {
    equalsIgnoringCase(a, UnsafeRawBufferPointer(start: b.utf8Start, count: b.utf8CodeUnitCount))
}

/// Whether the comma-separated `list` has an element equal to `token`,
/// ignoring case and surrounding whitespace.
package func listContains(_ list: UnsafeRawBufferPointer, _ token: UnsafeRawBufferPointer) -> Bool {
    var found = false
    forEachElement(list) { if equalsIgnoringCase($0, token) { found = true } }
    return found
}

/// Each non-empty element of a comma-separated list, trimmed.
package func forEachElement(_ list: UnsafeRawBufferPointer, _ body: (UnsafeRawBufferPointer) -> Void) {
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
