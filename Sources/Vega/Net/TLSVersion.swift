/// A TLS protocol version, as its wire code: what `TLSConfiguration` and
/// `NetworkTLS` take as a minimum, and what a handshake settled on.
public struct TLSVersion: RawRepresentable, Sendable, Hashable, Comparable, CustomStringConvertible {
    /// The code on the wire: 0x0303 for TLS 1.2, 0x0304 for TLS 1.3.
    public let rawValue: UInt16

    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    public static let v1_2 = TLSVersion(rawValue: 0x0303)
    public static let v1_3 = TLSVersion(rawValue: 0x0304)

    public static func < (a: TLSVersion, b: TLSVersion) -> Bool { a.rawValue < b.rawValue }

    public var description: String {
        rawValue >> 8 == 3 && rawValue & 0xff >= 1 ? "TLS 1.\((rawValue & 0xff) - 1)" : "0x" + String(rawValue, radix: 16)
    }
}
