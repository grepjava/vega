import VegaHTTP1

/// The opening handshake (RFC 6455 section 4): an HTTP/1.1 GET with
/// `Upgrade: websocket`, answered with 101 and a key derived from the
/// client's.
public enum WebSocketHandshake {
    static let guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    /// The Sec-WebSocket-Accept value for a client's Sec-WebSocket-Key.
    public static func acceptValue(for key: String) -> String {
        base64(sha1(Array((key + guid).utf8)))
    }

    /// A fresh Sec-WebSocket-Key: 16 random bytes, base64.
    public static func makeKey() -> String {
        var rng = SystemRandomNumberGenerator()
        return base64((0..<16).map { _ in UInt8.random(in: 0...255, using: &rng) })
    }

    /// Why `request` isn't a WebSocket upgrade, or nil if it is one. The
    /// status to answer with goes with the reason.
    public static func check(_ request: HTTPRequestHead) -> (status: Int, reason: String)? {
        let f = request.fields
        guard request.method == .get, request.version == .http1_1 else { return (400, "not an HTTP/1.1 GET") }
        guard f.containsToken("websocket", in: "upgrade") else { return (400, "no Upgrade: websocket") }
        guard f.containsToken("upgrade", in: "connection") else { return (400, "no Connection: upgrade") }
        guard f["sec-websocket-version"] == "13" else { return (426, "Sec-WebSocket-Version must be 13") }
        guard let key = f["sec-websocket-key"], f.values(for: "sec-websocket-key").count == 1,
              decodedBase64Count(key) == 16 else { return (400, "bad Sec-WebSocket-Key") }
        return nil
    }

    /// The 101 answering a request `check` passed, with `fields` added.
    public static func response(to request: HTTPRequestHead, fields: HTTPFields = [:]) -> HTTPResponseHead {
        var out = fields
        out["upgrade"] = "websocket"
        out["connection"] = "Upgrade"
        out["sec-websocket-accept"] = acceptValue(for: request.fields["sec-websocket-key"] ?? "")
        return HTTPResponseHead(status: 101, fields: out)
    }

    /// The client's request for `target` on `host`.
    public static func request(host: String, target: String, key: String, fields: HTTPFields = [:]) -> HTTPRequestHead {
        var out = fields
        out["host"] = host
        out["upgrade"] = "websocket"
        out["connection"] = "Upgrade"
        out["sec-websocket-key"] = key
        out["sec-websocket-version"] = "13"
        return HTTPRequestHead(method: .get, target: target, fields: out)
    }

    /// Whether `response` accepts the upgrade asked for with `key`.
    public static func accepts(_ response: HTTPResponseHead, key: String) -> Bool {
        response.status == 101
            && response.fields.containsToken("websocket", in: "upgrade")
            && response.fields.containsToken("upgrade", in: "connection")
            && response.fields["sec-websocket-accept"] == acceptValue(for: key)
    }
}

// MARK: - SHA-1 and base64, enough for the handshake

/// SHA-1 (FIPS 180-4). Used only for the handshake's key derivation,
/// which RFC 6455 fixes; it protects nothing.
func sha1(_ message: [UInt8]) -> [UInt8] {
    var h: [UInt32] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    var data = message
    let bits = UInt64(message.count) * 8
    data.append(0x80)
    while data.count % 64 != 56 { data.append(0) }
    for shift in stride(from: 56, through: 0, by: -8) { data.append(UInt8(truncatingIfNeeded: bits >> UInt64(shift))) }
    var w = [UInt32](repeating: 0, count: 80)
    for chunk in stride(from: 0, to: data.count, by: 64) {
        for i in 0..<16 {
            let j = chunk + i * 4
            w[i] = UInt32(data[j]) << 24 | UInt32(data[j + 1]) << 16 | UInt32(data[j + 2]) << 8 | UInt32(data[j + 3])
        }
        for i in 16..<80 {
            let x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            w[i] = x << 1 | x >> 31
        }
        var (a, b, c, d, e) = (h[0], h[1], h[2], h[3], h[4])
        for i in 0..<80 {
            let (f, k): (UInt32, UInt32) = switch i {
            case 0..<20: (b & c | ~b & d, 0x5A827999)
            case 20..<40: (b ^ c ^ d, 0x6ED9EBA1)
            case 40..<60: (b & c | b & d | c & d, 0x8F1BBCDC)
            default: (b ^ c ^ d, 0xCA62C1D6)
            }
            let t = (a << 5 | a >> 27) &+ f &+ e &+ k &+ w[i]
            (e, d, c, b, a) = (d, c, b << 30 | b >> 2, a, t)
        }
        h[0] &+= a; h[1] &+= b; h[2] &+= c; h[3] &+= d; h[4] &+= e
    }
    return h.flatMap { v in [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: v >> $0) } }
}

private let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)

func base64(_ bytes: [UInt8]) -> String {
    var out: [UInt8] = []
    for i in stride(from: 0, to: bytes.count, by: 3) {
        let n = min(3, bytes.count - i)
        let v = UInt32(bytes[i]) << 16 | (n > 1 ? UInt32(bytes[i + 1]) << 8 : 0) | (n > 2 ? UInt32(bytes[i + 2]) : 0)
        for k in 0..<4 {
            out.append(k <= n ? alphabet[Int(v >> UInt32(18 - 6 * k) & 0x3F)] : UInt8(ascii: "="))
        }
    }
    return String(decoding: out, as: UTF8.self)
}

/// How many bytes `s` decodes to, or nil if it isn't padded base64.
func decodedBase64Count(_ s: String) -> Int? {
    let chars = Array(s.utf8)
    guard !chars.isEmpty, chars.count % 4 == 0 else { return nil }
    let padding = chars.reversed().prefix { $0 == UInt8(ascii: "=") }.count
    guard padding <= 2 else { return nil }
    guard chars.dropLast(padding).allSatisfy({ alphabet.contains($0) }) else { return nil }
    return chars.count / 4 * 3 - padding
}
