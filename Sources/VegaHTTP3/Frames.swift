// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import Vega
import VegaIO
import VegaHTTP
import VegaHTTP3Core
import VegaQUICCore
import VegaWire

/// One HTTP/3 frame (RFC 9114 section 7): its type and payload.
struct HTTP3RawFrame {
    var type: UInt64
    var payload: [UInt8]
}

/// HTTP/3 frames from a QUIC stream, for `FramedRead`.
struct HTTP3FrameDecoder: Decoder {
    /// A longer frame, but DATA, is refused before it's buffered.
    var maxPayload: Int
    /// A longer DATA frame is `.frameTooLong`: what the body limit allows,
    /// since a peer may send a whole body as one frame (aioquic does).
    var maxData: Int

    init(maxPayload: Int, maxData: Int? = nil) {
        self.maxPayload = maxPayload
        self.maxData = maxData ?? maxPayload
    }

    mutating func decode(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: HTTP3RawFrame, consumed: Int)? {
        guard let base = bytes.baseAddress, bytes.count >= 2 else { return nil }
        var r = QUICReader(base.assumingMemoryBound(to: UInt8.self), bytes.count)
        guard let type = r.varint(), let length = r.varint() else { return nil }
        if type == HTTP3FrameType.data {
            guard length <= UInt64(maxData) else { throw .frameTooLong(Int(clamping: length)) }
        } else {
            guard length <= UInt64(maxPayload) else { throw .malformed("HTTP/3 frame of \(length) bytes") }
        }
        let n = Int(length)
        guard r.remaining >= n else { return nil }
        let payload = Array(UnsafeRawBufferPointer(rebasing: bytes[r.offset..<(r.offset + n)]))
        return (HTTP3RawFrame(type: type, payload: payload), r.offset + n)
    }
}

/// A variable-length integer (RFC 9000 section 16).
func h3Varint(_ value: UInt64) -> [UInt8] {
    var out = [UInt8](repeating: 0, count: 8)
    let n = out.withUnsafeMutableBufferPointer { quicWriteVarint(value, $0.baseAddress!) }
    return Array(out[0..<n])
}

/// A frame, encoded.
func h3Frame(_ type: UInt64, _ payload: [UInt8]) -> [UInt8] {
    h3Varint(type) + h3Varint(UInt64(payload.count)) + payload
}

/// A SETTINGS frame's payload.
func h3Settings(_ settings: [(UInt64, UInt64)]) -> [UInt8] {
    settings.flatMap { h3Varint($0.0) + h3Varint($0.1) }
}

/// Parses a SETTINGS payload; nil for a malformed or forbidden one.
func h3ParseSettings(_ payload: [UInt8]) -> [UInt64: UInt64]? {
    var settings: [UInt64: UInt64] = [:]
    let ok = payload.withUnsafeBufferPointer { b -> Bool in
        guard let base = b.baseAddress else { return true }
        var r = QUICReader(base, b.count)
        while !r.isEmpty {
            guard let id = r.varint(), let value = r.varint() else { return false }
            // RFC 9114 section 7.2.4.1: HTTP/2's settings are errors here,
            // and so is any setting twice.
            if HTTP3Setting.isReservedFromHTTP2(id) || settings[id] != nil { return false }
            settings[id] = value
        }
        return true
    }
    return ok ? settings : nil
}

/// A field section, QPACK-encoded with the static table only, as an
/// HTTP/3 HEADERS frame: `pseudo` first, then `fields` lowercased, without
/// the connection-specific ones.
func h3HeadersFrame(status: Int? = nil, pseudo: [(String, String)] = [], _ fields: HTTPFields) -> [UInt8] {
    var out = ByteBuffer(capacity: 256)
    defer { out.destroy() }
    let encoder = QPACKEncoder()
    encoder.begin(into: &out)
    if let status { encoder.encodeStatus(status, into: &out) }
    func add(_ name: String, _ value: String) {
        var name = name, value = value
        name.withUTF8 { n in
            value.withUTF8 { v in
                encoder.encode(name: n.baseAddress ?? QPACKStatic.entry(0)!.name, nameLength: n.count,
                               value: v.baseAddress ?? QPACKStatic.entry(0)!.name, valueLength: v.count, into: &out)
            }
        }
    }
    for (name, value) in pseudo { add(name, value) }
    for (name, value) in fields {
        let lower = name.lowercased()
        if connectionSpecific.contains(lower) || (lower == "te" && value.lowercased() != "trailers") { continue }
        add(lower, value)
    }
    let block = Array(UnsafeBufferPointer(start: out.readPointer, count: out.readableBytes))
    return h3Frame(HTTP3FrameType.headers, block)
}

/// Decodes a HEADERS payload into checked fields.
func h3DecodeFields(_ payload: [UInt8], maxSize: Int) -> DecodedFields? {
    var decoder = QPACKDecoder()
    decoder.maximumFieldSectionSize = maxSize
    defer { decoder.destroy() }
    var fields = DecodedFields()
    do {
        try payload.withUnsafeBufferPointer { b in
            guard let base = b.baseAddress else { throw QPACKError.truncated }
            try decoder.decode(base, b.count) { span in
                fields.add(UnsafeRawBufferPointer(start: span.name, count: span.nameLength),
                           UnsafeRawBufferPointer(start: span.value, count: span.valueLength))
            }
        }
    } catch {
        return nil
    }
    return fields
}
#endif
