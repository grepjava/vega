import CVegaCompress
import VegaHTTP1

/// What permessage-deflate (RFC 7692) was agreed as, from either end's view.
///
/// A client lists what it would accept in Sec-WebSocket-Extensions, maybe
/// several offers in order of preference. The server takes the first it can
/// honour exactly and says what it agreed to; an offer with a parameter it
/// doesn't know, one given twice, or a value out of range is passed over,
/// not repaired.
///
/// A server here wants memory it can predict: zlib's default 15-bit window
/// costs about a quarter of a megabyte per connection for as long as it keeps
/// its context, gigabytes at ten thousand connections. So it compresses with
/// a 12-bit window at memory level 5, about 40 KiB and most of the ratio for
/// the small, similar messages this extension is for, and asks the client
/// to stay within 12 bits too when the client says it may be asked.
public struct PerMessageDeflate: Sendable, Equatable {
    /// The server resets its compression context after each message.
    public var serverNoContextTakeover = false
    /// The client resets its compression context after each message.
    public var clientNoContextTakeover = false
    /// The server compresses within a window this size.
    public var serverMaxWindowBits: Int?
    /// The client compresses within a window this size.
    public var clientMaxWindowBits: Int?

    public init() {}

    /// The window a server here compresses with, and asks clients for.
    static let serverWindowBits = 12
    static let serverMemoryLevel: Int32 = 5
    /// Shorter messages go out as they are: the extension lets any message,
    /// and below this the deflate framing is most of it.
    static let minimumMessage = 64

    /// What a client here offers.
    static let clientOffer = "permessage-deflate; client_max_window_bits"

    /// The Sec-WebSocket-Extensions value saying this was agreed.
    public var headerValue: String {
        var out = "permessage-deflate"
        if serverNoContextTakeover { out += "; server_no_context_takeover" }
        if clientNoContextTakeover { out += "; client_no_context_takeover" }
        if let bits = serverMaxWindowBits { out += "; server_max_window_bits=\(bits)" }
        if let bits = clientMaxWindowBits { out += "; client_max_window_bits=\(bits)" }
        return out
    }

    /// A server's answer to these Sec-WebSocket-Extensions values: the first
    /// offer it can honour, or nil to agree to nothing.
    static func negotiate(_ values: [String]) -> PerMessageDeflate? {
        for value in values {
            for offer in split(value, on: ",") {
                if let agreement = parseOffer(offer) { return agreement }
            }
        }
        return nil
    }

    private static func parseOffer(_ offer: [UInt8]) -> PerMessageDeflate? {
        guard let params = parameters(offer) else { return nil }
        var agreement = PerMessageDeflate()
        var clientMayBeTold = false
        var clientLimit: Int?
        for (key, value) in params {
            switch key {
            case "server_no_context_takeover":
                guard value == nil else { return nil }
                agreement.serverNoContextTakeover = true
            case "client_no_context_takeover":
                guard value == nil else { return nil }
                agreement.clientNoContextTakeover = true
            case "server_max_window_bits":
                // zlib can't compress with an 8-bit window, so an offer that
                // insists on one is one this server can't keep.
                guard let value, let bits = windowBits(value), bits > 8 else { return nil }
                agreement.serverMaxWindowBits = bits
            case "client_max_window_bits":
                clientMayBeTold = true
                if let value {
                    guard let bits = windowBits(value) else { return nil }
                    clientLimit = bits
                }
            default:
                return nil
            }
        }
        if clientMayBeTold { agreement.clientMaxWindowBits = min(clientLimit ?? serverWindowBits, serverWindowBits) }
        return agreement
    }

    /// What a server's Sec-WebSocket-Extensions answer to `clientOffer`
    /// agreed, nil if it agreed to nothing; throws if it isn't an answer to
    /// that offer.
    static func accepted(_ values: [String]) throws(WebSocketError) -> PerMessageDeflate? {
        let answers = values.flatMap { split($0, on: ",") }
        guard !answers.isEmpty else { return nil }
        guard answers.count == 1, let params = parameters(answers[0]) else {
            throw .handshake("an extension that wasn't offered")
        }
        var agreement = PerMessageDeflate()
        for (key, value) in params {
            switch key {
            case "server_no_context_takeover" where value == nil:
                agreement.serverNoContextTakeover = true
            case "client_no_context_takeover" where value == nil:
                agreement.clientNoContextTakeover = true
            case "server_max_window_bits":
                guard let value, let bits = windowBits(value) else { throw .handshake("bad server_max_window_bits") }
                agreement.serverMaxWindowBits = bits
            case "client_max_window_bits":
                guard let value, let bits = windowBits(value) else { throw .handshake("bad client_max_window_bits") }
                agreement.clientMaxWindowBits = bits
            default:
                throw .handshake("bad permessage-deflate parameter \(key)")
            }
        }
        return agreement
    }

    /// An offer's parameters, keys lowercased, if it is permessage-deflate
    /// with none given twice or empty.
    private static func parameters(_ offer: [UInt8]) -> [(String, [UInt8]?)]? {
        let parts = split(offer, on: ";")
        guard let name = parts.first, String(decoding: name, as: UTF8.self).lowercased() == "permessage-deflate" else {
            return nil
        }
        var out: [(String, [UInt8]?)] = []
        for part in parts.dropFirst() {
            guard !part.isEmpty else { return nil }
            let eq = part.firstIndex(of: UInt8(ascii: "="))
            let key = String(decoding: trimmed(Array(part[..<(eq ?? part.endIndex)])), as: UTF8.self).lowercased()
            let value = eq.map { trimmed(Array(part[($0 + 1)...])) }
            guard !out.contains(where: { $0.0 == key }) else { return nil }
            out.append((key, value))
        }
        return out
    }

    /// A window size parameter's value: 8 to 15, bare or quoted.
    private static func windowBits(_ raw: [UInt8]) -> Int? {
        var v = raw
        if v.count >= 2 && v.first == UInt8(ascii: "\"") && v.last == UInt8(ascii: "\"") { v = Array(v.dropFirst().dropLast()) }
        guard v.count == 1 || v.count == 2, v.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return nil }
        // No leading zero.
        if v.count == 2 && v[0] == 0x30 { return nil }
        let n = v.reduce(0) { $0 * 10 + Int($1 - 0x30) }
        return (8...15).contains(n) ? n : nil
    }

    /// `s` split at `separator` outside quoted strings, each piece trimmed.
    private static func split(_ s: some StringProtocol, on separator: Character) -> [[UInt8]] {
        split(Array(s.utf8), on: separator)
    }

    private static func split(_ bytes: [UInt8], on separator: Character) -> [[UInt8]] {
        let sep = separator.asciiValue!
        var out: [[UInt8]] = []
        var piece: [UInt8] = []
        var quoted = false
        for c in bytes {
            if c == UInt8(ascii: "\"") { quoted.toggle() }
            if c == sep && !quoted {
                out.append(trimmed(piece))
                piece = []
            } else {
                piece.append(c)
            }
        }
        out.append(trimmed(piece))
        // A value with nothing in it lists nothing.
        return out.count == 1 && out[0].isEmpty ? [] : out
    }

    private static func trimmed(_ s: [UInt8]) -> [UInt8] {
        var lo = 0, hi = s.count
        while lo < hi && (s[lo] == 0x20 || s[lo] == 0x09) { lo += 1 }
        while hi > lo && (s[hi - 1] == 0x20 || s[hi - 1] == 0x09) { hi -= 1 }
        return Array(s[lo..<hi])
    }
}

/// One connection's compressor and decompressor, as agreed.
final class DeflateContext {
    private let deflater: UnsafeMutableRawPointer?
    private let inflater: UnsafeMutableRawPointer
    private let resetDeflater: Bool
    private let resetInflater: Bool
    private let scratch = UnsafeMutableRawPointer.allocate(byteCount: 16 * 1024, alignment: 16)
    private static let tail: [UInt8] = [0x00, 0x00, 0xFF, 0xFF]

    init?(_ agreement: PerMessageDeflate, role: WebSocketRole) {
        let isServer = role == .server
        let sendWindow = isServer
            ? min(agreement.serverMaxWindowBits ?? 15, PerMessageDeflate.serverWindowBits)
            : agreement.clientMaxWindowBits ?? 15
        let receiveWindow = isServer ? agreement.clientMaxWindowBits ?? 15 : agreement.serverMaxWindowBits ?? 15
        guard let inflater = cv_ws_inflate_new(Int32(receiveWindow)) else {
            scratch.deallocate()
            return nil
        }
        self.inflater = inflater
        // zlib can't compress within 8 bits: then nothing goes out compressed,
        // which the extension allows.
        deflater = sendWindow < 9 ? nil
            : cv_ws_deflate_new(Int32(sendWindow), isServer ? PerMessageDeflate.serverMemoryLevel : 8)
        resetDeflater = isServer ? agreement.serverNoContextTakeover : agreement.clientNoContextTakeover
        resetInflater = isServer ? agreement.clientNoContextTakeover : agreement.serverNoContextTakeover
    }

    deinit {
        cv_ws_deflate_free(deflater)
        cv_ws_inflate_free(inflater)
        scratch.deallocate()
    }

    /// `payload` compressed for a message, or nil to send it as it is.
    func compress(_ payload: [UInt8]) -> [UInt8]? {
        guard let deflater, payload.count >= PerMessageDeflate.minimumMessage else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(payload.count / 2 + 16)
        let ok = payload.withUnsafeBufferPointer { input -> Bool in
            var offset = 0
            while true {
                var consumed = 0, produced = 0
                let rc = cv_ws_deflate_run(deflater, input.baseAddress! + offset, input.count - offset,
                                           scratch.assumingMemoryBound(to: UInt8.self), 16 * 1024, &consumed, &produced)
                offset += consumed
                out.append(contentsOf: UnsafeRawBufferPointer(start: scratch, count: produced))
                if rc < 0 { return false }
                if rc == 0 && offset == input.count { return true }
            }
        }
        if resetDeflater { _ = cv_ws_deflate_reset(deflater) }
        // A sync flush ends with an empty stored block, which isn't sent.
        guard ok, out.count >= 4, Array(out.suffix(4)) == Self.tail else { return nil }
        out.removeLast(4)
        return out
    }

    /// A compressed message's payload, decompressed to at most `limit`
    /// bytes. nil if it would be more; throws `.invalidPayload` if it isn't
    /// deflate.
    func decompress(_ payload: [UInt8], limit: Int) throws(WebSocketError) -> [UInt8]? {
        var out: [UInt8] = []
        var tooLarge = false
        let rc = (payload + Self.tail).withUnsafeBufferPointer { input -> Int32 in
            var offset = 0
            while true {
                var consumed = 0, produced = 0
                let rc = cv_ws_inflate_run(inflater, input.baseAddress! + offset, input.count - offset,
                                           scratch.assumingMemoryBound(to: UInt8.self), 16 * 1024, &consumed, &produced)
                offset += consumed
                if produced > limit - out.count {
                    tooLarge = true
                    return 0
                }
                out.append(contentsOf: UnsafeRawBufferPointer(start: scratch, count: produced))
                // 2: the peer ended its deflate stream (a final block),
                // which ends the message too; the tail we added is left over.
                if rc != 1 && (rc != 0 || offset == input.count) { return rc }
            }
        }
        if tooLarge { return nil }
        guard rc == 0 || rc == 2 else { throw .protocolViolation(.invalidPayload) }
        // After a final block the next message starts a new stream.
        if resetInflater || rc == 2 { _ = cv_ws_inflate_reset(inflater) }
        return out
    }
}
