import VegaWire

// Field sections as HTTP/2 and HTTP/3 carry them: lowercase names,
// pseudo-fields first, no connection-specific fields.

/// Fields that describe a connection, which HTTP/2 and HTTP/3 have no use
/// for (RFC 9113 section 8.2.2, RFC 9114 section 4.2).
package let connectionSpecific: Set<String> = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host"]

/// A lowercase token (RFC 9113 section 8.2.1).
package func isValidName(_ n: [UInt8]) -> Bool {
    !n.isEmpty && n.allSatisfy { c in
        switch c {
        case 0x30...0x39, 0x61...0x7A, 0x21, 0x23...0x27, 0x2A, 0x2B, 0x2D, 0x2E, 0x5E, 0x5F, 0x60, 0x7C, 0x7E: true
        default: false
        }
    }
}

/// No NUL, CR or LF, and no whitespace at either end.
package func isValidValue(_ v: [UInt8]) -> Bool {
    if let f = v.first, f == 0x20 || f == 0x09 { return false }
    if let l = v.last, l == 0x20 || l == 0x09 { return false }
    return !v.contains { $0 == 0 || $0 == 0x0A || $0 == 0x0D }
}

/// A decoded HTTP/2 or HTTP/3 field section, checked as it arrives.
package struct DecodedFields {
    package var pseudo: [(String, String)] = []
    package var fields = HTTPFields()
    package var malformed = false

    package init() {}

    package mutating func add(_ name: UnsafeRawBufferPointer, _ value: UnsafeRawBufferPointer) {
        let n = Array(name), v = Array(value)
        if n.first == UInt8(ascii: ":") {
            // Pseudo-fields come first.
            if !fields.isEmpty { malformed = true }
            pseudo.append((String(decoding: n, as: UTF8.self), String(decoding: v, as: UTF8.self)))
            return
        }
        guard isValidName(n), isValidValue(v) else {
            malformed = true
            return
        }
        let nameString = String(decoding: n, as: UTF8.self)
        if connectionSpecific.contains(nameString) && nameString != "host" { malformed = true }
        if nameString == "te" && v != Array("trailers".utf8) { malformed = true }
        fields.append(name: name, value: value)
    }

    /// Each pseudo-field once, and only those in `allowed`.
    private func pseudoFields(_ allowed: Set<String>) -> [String: String]? {
        var seen: [String: String] = [:]
        for (name, value) in pseudo {
            guard allowed.contains(name), seen[name] == nil else { return nil }
            seen[name] = value
        }
        return seen
    }

    package func requestHead(version: HTTPVersion) -> HTTPRequestHead? {
        guard !malformed, let p = pseudoFields([":method", ":scheme", ":authority", ":path"]),
              let method = p[":method"], !method.isEmpty
        else { return nil }
        var fields = fields
        let target: String
        if method == "CONNECT" {
            guard let authority = p[":authority"], p[":scheme"] == nil, p[":path"] == nil else { return nil }
            target = authority
        } else {
            guard p[":scheme"] != nil, let path = p[":path"], !path.isEmpty else { return nil }
            target = path
        }
        if let authority = p[":authority"], !fields.contains("host") {
            fields.append(name: "host", value: authority)
        }
        return HTTPRequestHead(method: HTTPMethod(rawValue: method), target: target, version: version, fields: fields)
    }

    package func responseHead(version: HTTPVersion) -> HTTPResponseHead? {
        guard !malformed, let p = pseudoFields([":status"]), let status = p[":status"],
              status.utf8.count == 3, let code = Int(status), code >= 100
        else { return nil }
        return HTTPResponseHead(status: code, version: version, fields: fields)
    }

    package func trailers() -> HTTPFields? {
        malformed || !pseudo.isEmpty ? nil : fields
    }
}
