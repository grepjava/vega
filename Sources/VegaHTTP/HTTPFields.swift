import VegaWire

/// A message's fields (headers or trailers), in order, with names matched
/// ignoring case.
///
/// All names and values share one byte array, so a parsed head costs two
/// allocations however many fields it has; strings are made only when asked
/// for.
public struct HTTPFields: Sendable {
    private var bytes: [UInt8] = []
    private var entries: [Entry] = []

    private struct Entry: Sendable {
        var start: UInt32
        var nameCount: UInt32
        var valueCount: UInt32
        var valueStart: Int { Int(start + nameCount) }
    }

    public init() {}

    public var count: Int { entries.count }
    public var isEmpty: Bool { entries.isEmpty }

    /// Add a field after the others, keeping any with the same name.
    public mutating func append(name: String, value: String) {
        var name = name, value = value
        name.withUTF8 { n in
            value.withUTF8 { v in append(name: UnsafeRawBufferPointer(n), value: UnsafeRawBufferPointer(v)) }
        }
    }

    package mutating func append(name: UnsafeRawBufferPointer, value: UnsafeRawBufferPointer) {
        entries.append(Entry(start: UInt32(bytes.count), nameCount: UInt32(name.count), valueCount: UInt32(value.count)))
        bytes.append(contentsOf: name)
        bytes.append(contentsOf: value)
    }

    /// The first value of the field named `name`. Setting replaces every
    /// field of that name (nil removes them).
    public subscript(name: String) -> String? {
        get { firstIndex(name).map { value(at: $0) } }
        set {
            remove(name)
            if let newValue { append(name: name, value: newValue) }
        }
    }

    /// Every value of the field named `name`, in order.
    public func values(for name: String) -> [String] {
        entries.indices.filter { matches($0, name) }.map { value(at: $0) }
    }

    public func contains(_ name: String) -> Bool { firstIndex(name) != nil }

    /// Remove every field named `name`.
    public mutating func remove(_ name: String) {
        guard firstIndex(name) != nil else { return }
        var kept = HTTPFields()
        for i in entries.indices where !matches(i, name) {
            withRaw(i) { n, v in kept.append(name: n, value: v) }
        }
        self = kept
    }

    /// Whether the comma-separated fields named `name` list `token`,
    /// ignoring case: `containsToken("close", in: "connection")`.
    public func containsToken(_ token: String, in name: String) -> Bool {
        var token = token
        return token.withUTF8 { t in
            entries.indices.contains { i in
                matches(i, name) && withRaw(i) { _, v in listContains(v, UnsafeRawBufferPointer(t)) }
            }
        }
    }

    package func name(at i: Int) -> String {
        withRaw(i) { n, _ in String(decoding: n, as: UTF8.self) }
    }

    package func value(at i: Int) -> String {
        withRaw(i) { _, v in String(decoding: v, as: UTF8.self) }
    }

    /// The raw name and value of field `i`.
    package func withRaw<R>(_ i: Int, _ body: (UnsafeRawBufferPointer, UnsafeRawBufferPointer) -> R) -> R {
        let e = entries[i]
        return bytes.withUnsafeBytes { all in
            body(UnsafeRawBufferPointer(rebasing: all[Int(e.start)..<e.valueStart]),
                 UnsafeRawBufferPointer(rebasing: all[e.valueStart..<e.valueStart + Int(e.valueCount)]))
        }
    }

    private func firstIndex(_ name: String) -> Int? {
        entries.indices.first { matches($0, name) }
    }

    private func matches(_ i: Int, _ name: String) -> Bool {
        var name = name
        return name.withUTF8 { want in
            withRaw(i) { n, _ in equalsIgnoringCase(n, UnsafeRawBufferPointer(want)) }
        }
    }

    /// Whether `fields` let a connection carry another message.
    static func keepAlive(_ fields: HTTPFields, _ version: HTTPVersion) -> Bool {
        if fields.containsToken("close", in: "connection") { return false }
        return version.minor >= 1 || fields.containsToken("keep-alive", in: "connection")
    }
}

extension HTTPFields: Sequence {
    public struct Iterator: IteratorProtocol {
        let fields: HTTPFields
        var i = 0

        public mutating func next() -> (name: String, value: String)? {
            guard i < fields.count else { return nil }
            defer { i += 1 }
            return (fields.name(at: i), fields.value(at: i))
        }
    }

    public func makeIterator() -> Iterator { Iterator(fields: self) }
    public var underestimatedCount: Int { count }
}

extension HTTPFields: Equatable {
    /// The same fields in the same order; names compare ignoring case.
    public static func == (a: HTTPFields, b: HTTPFields) -> Bool {
        guard a.count == b.count else { return false }
        for i in 0..<a.count {
            let same = a.withRaw(i) { an, av in
                b.withRaw(i) { bn, bv in equalsIgnoringCase(an, bn) && av.elementsEqual(bv) }
            }
            if !same { return false }
        }
        return true
    }
}

extension HTTPFields: ExpressibleByDictionaryLiteral {
    public init(dictionaryLiteral elements: (String, String)...) {
        for (name, value) in elements { append(name: name, value: value) }
    }
}

extension HTTPFields: CustomStringConvertible {
    public var description: String {
        "[" + map { "\($0.name): \($0.value)" }.joined(separator: ", ") + "]"
    }
}
