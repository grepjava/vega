// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
//===----------------------------------------------------------------------===//
// TLS 1.3, client side, for QUIC.
//
// The mirror of TLSServerHandshake (TLS13.swift): the message flow written
// out over VegaCrypto's primitives, with QUIC carrying the bytes in CRYPTO
// frames and turning the secrets into packet keys (RFC 9001 section 4).
//
// The client speaks first and commits to less than the server does: it offers
// every cipher suite QUIC allows, a key share for X25519 and one for P-256 --
// between them every deployed server's choice, so no HelloRetryRequest is ever
// needed, and one is refused -- and learns which the server picked from the
// ServerHello. Only then is the hash known, so the transcript starts late, with
// the ClientHello kept until it can be hashed.
//
// What the server proves is checked, not trusted: its chain against the
// trust roots and the name asked for (CertificateVerifier, or the caller's
// own check), its CertificateVerify signature over the transcript with the
// leaf's key, and its Finished. A client certificate is never sent; a server
// that asks for one gets the empty Certificate RFC 8446 section 4.4.2 allows,
// and decides for itself. No session resumption, no 0-RTT.
//===----------------------------------------------------------------------===//

@_spi(Garuda) import VegaWire
import VegaCrypto

/// A traffic secret pair, as either side's handshake produces it.
package typealias TLSSecrets = TLSServerHandshake.Secrets

/// What a QUICConnectionState needs of its TLS handshake, whichever side of it
/// the connection is.
protocol QUICHandshake: AnyObject {
    var alert: UInt8? { get }
    var isComplete: Bool { get }
    var initialOut: ByteBuffer { get set }
    var handshakeOut: ByteBuffer { get set }
    var selectedALPN: [UInt8] { get }
    var serverName: [UInt8] { get }
    var peerParameters: QUICTransportParameters { get }
    func receive(_ p: UnsafePointer<UInt8>, _ n: Int, level: QUICLevel)
    func takePendingSecrets() -> [TLSSecrets]
}

extension TLSServerHandshake: QUICHandshake {
    var isComplete: Bool { state == .complete }
}

package final class TLSClientHandshake: QUICHandshake {
    public enum State {
        case start
        case waitingServerHello
        case waitingEncryptedExtensions
        case waitingCertificate
        case waitingCertificateVerify
        case waitingFinished
        case complete
        case failed
    }

    /// The schemes offered for the server's CertificateVerify, which are
    /// every one VegaCrypto verifies. RSA PKCS #1 is not among them: TLS 1.3
    /// forbids it there (RFC 8446 section 4.4.3).
    static let signatureSchemes: [UInt16] = [0x0403, 0x0804, 0x0807, 0x0503, 0x0805, 0x0806, 0x0603]
    /// What the ServerHello's random is when it is a HelloRetryRequest
    /// (RFC 8446 section 4.1.3): SHA-256 of "HelloRetryRequest".
    static let helloRetryRandom: [UInt8] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ]

    // Configuration.
    private let name: String
    private let alpnOffers: [[UInt8]]
    private let localParameters: QUICTransportParameters
    /// The chain check: nil when the chain is acceptable, the reason when it
    /// is not. No check at all when nil.
    private let verifyChain: (([[UInt8]], String) -> String?)?

    // Negotiated.
    public private(set) var state: State = .start
    public private(set) var alert: UInt8?
    public private(set) var cipher: QUICCipher = .aes128GCMSHA256
    public private(set) var selectedALPN: [UInt8] = []
    public private(set) var peerParameters = QUICTransportParameters()
    /// The server's chain, DER, leaf first.
    public private(set) var peerCertificates: [[UInt8]] = []
    /// Why the server's chain was refused, when it was.
    public private(set) var certificateError: String?
    /// Whether the server asked for a client certificate (and was sent none).
    public private(set) var certificateRequested = false

    public var serverName: [UInt8] { Array(name.utf8) }
    var isComplete: Bool { state == .complete }

    // Output, per encryption level, as the server's.
    public var initialOut = ByteBuffer()
    public var handshakeOut = ByteBuffer()
    public private(set) var pendingSecrets: [TLSSecrets] = []

    // Working state.
    private var transcript: UnsafeMutablePointer<Hash>?
    /// Our key shares, out of line because KeyExchange is ~Copyable, and
    /// freed as soon as the ServerHello has used one.
    private var x25519: UnsafeMutablePointer<KeyExchange>?
    private var p256: UnsafeMutablePointer<KeyExchange>?
    /// The ClientHello, until the ServerHello says which hash to put it in.
    private var clientHello: [UInt8] = []
    private var certificateRequestContext: [UInt8] = []
    private var handshakeSecret: [UInt8] = []
    private var clientHandshakeSecret: [UInt8] = []
    private var serverHandshakeSecret: [UInt8] = []
    private var incoming = [ByteBuffer](repeating: ByteBuffer(), count: 3)

    /// `serverName` goes in the SNI extension unless it is an IP address,
    /// which RFC 6066 section 3 does not allow there; `verify` checks the
    /// server's chain for it.
    init(serverName: String, alpn: [[UInt8]], parameters: QUICTransportParameters,
         verify: (([[UInt8]], String) -> String?)?) {
        self.name = serverName
        self.alpnOffers = alpn
        self.localParameters = parameters
        self.verifyChain = verify
    }

    deinit {
        if let transcript {
            transcript.deinitialize(count: 1)
            transcript.deallocate()
        }
        releaseKeyShares()
        for i in 0..<incoming.count { incoming[i].destroy() }
        initialOut.destroy()
        handshakeOut.destroy()
        scrubSecrets()
    }

    private func releaseKeyShares() {
        if let x25519 {
            x25519.deinitialize(count: 1)
            x25519.deallocate()
        }
        if let p256 {
            p256.deinitialize(count: 1)
            p256.deallocate()
        }
        x25519 = nil
        p256 = nil
    }

    private func scrubSecrets() {
        quicScrub(&handshakeSecret)
        quicScrub(&clientHandshakeSecret)
        quicScrub(&serverHandshakeSecret)
    }

    public func takePendingSecrets() -> [TLSSecrets] {
        let out = pendingSecrets
        pendingSecrets.removeAll(keepingCapacity: true)
        return out
    }

    private func fail(_ code: UInt8) {
        if alert == nil { alert = code }
        state = .failed
    }

    /// Whether `host` is an IP address, which is not sent as SNI and is
    /// checked against a certificate's IP names rather than its DNS ones.
    static func isIPAddress(_ host: String) -> Bool {
        if host.contains(":") { return true }       // IPv6: no DNS name has a colon
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { part in
            !part.isEmpty && part.count <= 3 && part.allSatisfy { $0.isASCII && $0.isNumber }
        }
    }

    // MARK: ClientHello

    /// Writes the ClientHello into `initialOut`. Called once, by the
    /// connection, before anything is sent.
    func start() {
        guard state == .start else { return }
        guard let x = try? KeyExchange(.x25519), let p = try? KeyExchange(.p256) else {
            return fail(TLSAlert.internalError)
        }
        let xp = UnsafeMutablePointer<KeyExchange>.allocate(capacity: 1)
        xp.initialize(to: x)
        x25519 = xp
        let pp = UnsafeMutablePointer<KeyExchange>.allocate(capacity: 1)
        pp.initialize(to: p)
        p256 = pp

        var message = ByteBuffer(capacity: 512)
        defer { message.destroy() }

        message.writeByte(HandshakeType.clientHello)
        let bodyLength = message.openLength(3)
        message.writeUInt16BE(0x0303)                    // legacy_version
        let random = SecureRandom.bytes(32)
        random.withUnsafeBufferPointer { message.write($0.baseAddress!, 32) }
        // legacy_session_id: empty. QUIC has no middlebox compatibility mode
        // (RFC 9001 section 8.4), which is the only reason to send one.
        message.writeByte(0)
        // Every suite QUIC allows, AES-128 first for the same reason the
        // server prefers it.
        message.writeUInt16BE(6)
        message.writeUInt16BE(QUICCipher.aes128GCMSHA256.rawValue)
        message.writeUInt16BE(QUICCipher.chacha20Poly1305SHA256.rawValue)
        message.writeUInt16BE(QUICCipher.aes256GCMSHA384.rawValue)
        message.writeByte(1)                             // legacy_compression_methods
        message.writeByte(0)

        let extensions = message.openLength(2)
        if !name.isEmpty && !TLSClientHandshake.isIPAddress(name) {
            let host = Array(name.utf8)
            if host.count <= 0xFFFF - 5 {
                message.writeUInt16BE(ExtensionType.serverName)
                let extLength = message.openLength(2)
                let listLength = message.openLength(2)
                message.writeByte(0)                     // host_name
                message.writeUInt16BE(UInt16(host.count))
                host.withUnsafeBufferPointer { message.write($0.baseAddress!, $0.count) }
                message.closeLength(listLength, 2)
                message.closeLength(extLength, 2)
            }
        }

        message.writeUInt16BE(ExtensionType.supportedGroups)
        message.writeUInt16BE(6)
        message.writeUInt16BE(4)
        message.writeUInt16BE(NamedGroup.x25519)
        message.writeUInt16BE(NamedGroup.secp256r1)

        message.writeUInt16BE(ExtensionType.signatureAlgorithms)
        let schemes = TLSClientHandshake.signatureSchemes
        message.writeUInt16BE(UInt16(2 + 2 * schemes.count))
        message.writeUInt16BE(UInt16(2 * schemes.count))
        for scheme in schemes { message.writeUInt16BE(scheme) }

        if !alpnOffers.isEmpty {
            message.writeUInt16BE(ExtensionType.alpn)
            let extLength = message.openLength(2)
            let listLength = message.openLength(2)
            for protocolName in alpnOffers where !protocolName.isEmpty && protocolName.count <= 255 {
                message.writeByte(UInt8(protocolName.count))
                protocolName.withUnsafeBufferPointer { message.write($0.baseAddress!, $0.count) }
            }
            message.closeLength(listLength, 2)
            message.closeLength(extLength, 2)
        }

        // TLS 1.3 and nothing else: QUIC is not defined over anything older.
        message.writeUInt16BE(ExtensionType.supportedVersions)
        message.writeUInt16BE(3)
        message.writeByte(2)
        message.writeUInt16BE(0x0304)

        message.writeUInt16BE(ExtensionType.keyShare)
        let keyShareLength = message.openLength(2)
        let sharesLength = message.openLength(2)
        for (group, key) in [(NamedGroup.x25519, xp.pointee.publicKey), (NamedGroup.secp256r1, pp.pointee.publicKey)] {
            message.writeUInt16BE(group)
            message.writeUInt16BE(UInt16(key.count))
            key.withUnsafeBufferPointer { message.write($0.baseAddress!, $0.count) }
        }
        message.closeLength(sharesLength, 2)
        message.closeLength(keyShareLength, 2)

        message.writeUInt16BE(ExtensionType.quicTransportParameters)
        let paramsLength = message.openLength(2)
        localParameters.encode(into: &message, isServer: false)
        message.closeLength(paramsLength, 2)

        message.closeLength(extensions, 2)
        message.closeLength(bodyLength, 3)

        clientHello = [UInt8](UnsafeBufferPointer(start: message.readPointer, count: message.readableBytes))
        initialOut.write(message.readPointer, message.readableBytes)
        state = .waitingServerHello
    }

    // MARK: Input

    /// Contiguous CRYPTO bytes at one level, as the server's. What arrives
    /// once the handshake is over -- a NewSessionTicket, at the application
    /// level -- is dropped: there is no resumption to use it for.
    public func receive(_ p: UnsafePointer<UInt8>, _ n: Int, level: QUICLevel) {
        if state == .failed || state == .complete { return }
        incoming[level.rawValue].write(p, n)
        processMessages(level: level)
    }

    private func processMessages(level: QUICLevel) {
        while state != .failed && state != .complete {
            let available = incoming[level.rawValue].readableBytes
            if available < 4 { return }
            let head = incoming[level.rawValue].readPointer
            let type = head[0]
            let length = (Int(head[1]) << 16) | (Int(head[2]) << 8) | Int(head[3])
            if available < 4 + length { return }
            let total = 4 + length

            // Each message is legal at one level and in one state; anything
            // else is out of order, which in a handshake is an attack until
            // proved otherwise.
            switch (type, level, state) {
            case (HandshakeType.serverHello, .initial, .waitingServerHello):
                handleServerHello(head, total)
            case (HandshakeType.encryptedExtensions, .handshake, .waitingEncryptedExtensions):
                handleEncryptedExtensions(head, total)
            case (HandshakeType.certificateRequest, .handshake, .waitingCertificate):
                handleCertificateRequest(head, total)
            case (HandshakeType.certificate, .handshake, .waitingCertificate):
                handleCertificate(head, total)
            case (HandshakeType.certificateVerify, .handshake, .waitingCertificateVerify):
                handleCertificateVerify(head, total)
            case (HandshakeType.finished, .handshake, .waitingFinished):
                handleFinished(head, total)
            default:
                fail(TLSAlert.unexpectedMessage)
                return
            }
            incoming[level.rawValue].consume(total)
        }
    }

    // MARK: ServerHello

    private func handleServerHello(_ message: UnsafePointer<UInt8>, _ total: Int) {
        var r = QUICReader(message, total)
        _ = r.skip(4)
        guard let legacyVersion = r.uint16(), let random = r.take(32) else { return fail(TLSAlert.decodeError) }
        if legacyVersion != 0x0303 { return fail(TLSAlert.protocolVersion) }
        // A HelloRetryRequest is a ServerHello with a fixed random. Both
        // groups a server could want were offered with shares, so one asking
        // again wants something we do not have.
        var isRetry = true
        for i in 0..<32 where random[i] != TLSClientHandshake.helloRetryRandom[i] { isRetry = false }
        if isRetry { return fail(TLSAlert.handshakeFailure) }

        // The echo of an empty legacy_session_id is empty.
        guard let sessionIDLength = r.byte() else { return fail(TLSAlert.decodeError) }
        if sessionIDLength != 0 { return fail(TLSAlert.illegalParameter) }
        guard let suite = r.uint16(), let compression = r.byte() else { return fail(TLSAlert.decodeError) }
        guard let chosen = QUICCipher(rawValue: suite) else { return fail(TLSAlert.illegalParameter) }
        if compression != 0 { return fail(TLSAlert.illegalParameter) }
        guard let extensionsLength = r.uint16(), let extensions = r.take(Int(extensionsLength)), r.isEmpty
        else { return fail(TLSAlert.decodeError) }

        var version13 = false
        var share: (group: UInt16, key: UnsafePointer<UInt8>, length: Int)?
        var e = QUICReader(extensions, Int(extensionsLength))
        while !e.isEmpty {
            guard let extType = e.uint16(), let extLength = e.uint16(), let body = e.take(Int(extLength))
            else { return fail(TLSAlert.decodeError) }
            var b = QUICReader(body, Int(extLength))
            switch extType {
            case ExtensionType.supportedVersions:
                guard let v = b.uint16(), b.isEmpty else { return fail(TLSAlert.decodeError) }
                if v != 0x0304 { return fail(TLSAlert.illegalParameter) }
                version13 = true
            case ExtensionType.keyShare:
                guard let group = b.uint16(), let keyLength = b.uint16(), let key = b.take(Int(keyLength)),
                      b.isEmpty
                else { return fail(TLSAlert.decodeError) }
                share = (group, key, Int(keyLength))
            default:
                // pre_shared_key is the only other a ServerHello may carry,
                // and only in answer to an offer we never make.
                return fail(TLSAlert.unsupportedExtension)
            }
        }
        if !version13 { return fail(TLSAlert.protocolVersion) }
        guard let share else { return fail(TLSAlert.missingExtension) }
        cipher = chosen

        // The transcript starts now: the hash was the cipher suite's to pick.
        guard let hash = try? Hash(cipher.hash) else { return fail(TLSAlert.internalError) }
        let t = UnsafeMutablePointer<Hash>.allocate(capacity: 1)
        t.initialize(to: hash)
        transcript = t
        clientHello.withUnsafeBytes { t.pointee.update($0) }
        quicScrub(&clientHello)
        clientHello = []
        t.pointee.update(UnsafeRawBufferPointer(start: message, count: total))

        let exchange: UnsafeMutablePointer<KeyExchange>?
        switch share.group {
        case NamedGroup.x25519: exchange = x25519
        case NamedGroup.secp256r1: exchange = p256
        default: exchange = nil
        }
        // A group we sent no share for is one the server had no business
        // choosing.
        guard let exchange else { return fail(TLSAlert.illegalParameter) }
        let peerKey = [UInt8](UnsafeBufferPointer(start: share.key, count: share.length))
        guard var shared = try? exchange.pointee.sharedSecret(with: peerKey), !shared.isEmpty else {
            return fail(TLSAlert.illegalParameter)
        }
        defer { quicScrub(&shared) }
        releaseKeyShares()

        if !deriveHandshakeSecrets(shared) { return fail(TLSAlert.internalError) }
        state = .waitingEncryptedExtensions
    }

    // MARK: The server's encrypted flight

    private func handleEncryptedExtensions(_ message: UnsafePointer<UInt8>, _ total: Int) {
        var r = QUICReader(message, total)
        _ = r.skip(4)
        guard let extensionsLength = r.uint16(), let extensions = r.take(Int(extensionsLength)), r.isEmpty
        else { return fail(TLSAlert.decodeError) }

        var parametersSeen = false
        var e = QUICReader(extensions, Int(extensionsLength))
        while !e.isEmpty {
            guard let extType = e.uint16(), let extLength = e.uint16(), let body = e.take(Int(extLength))
            else { return fail(TLSAlert.decodeError) }
            var b = QUICReader(body, Int(extLength))
            switch extType {
            case ExtensionType.alpn:
                // Exactly one protocol, and one we offered (RFC 7301 section 3.1).
                guard let listLength = b.uint16(), let nameLength = b.byte(), nameLength > 0,
                      Int(listLength) == 1 + Int(nameLength), let name = b.take(Int(nameLength)), b.isEmpty
                else { return fail(TLSAlert.decodeError) }
                let chosen = [UInt8](UnsafeBufferPointer(start: name, count: Int(nameLength)))
                if !alpnOffers.contains(chosen) { return fail(TLSAlert.illegalParameter) }
                selectedALPN = chosen
            case ExtensionType.quicTransportParameters:
                guard let parsed = QUICTransportParameters.decode(body, Int(extLength), fromServer: true)
                else { return fail(TLSAlert.illegalParameter) }
                peerParameters = parsed
                parametersSeen = true
            default:
                // server_name's empty acknowledgement, and anything else an
                // extension of ours might be answered with.
                break
            }
        }
        if !parametersSeen { return fail(TLSAlert.missingExtension) }
        // RFC 9001 section 8.1: QUIC requires an application protocol, and a
        // server that agreed to none has not agreed to ours.
        if !alpnOffers.isEmpty && selectedALPN.isEmpty { return fail(TLSAlert.noApplicationProtocol) }

        transcript?.pointee.update(UnsafeRawBufferPointer(start: message, count: total))
        state = .waitingCertificate
    }

    private func handleCertificateRequest(_ message: UnsafePointer<UInt8>, _ total: Int) {
        var r = QUICReader(message, total)
        _ = r.skip(4)
        guard let contextLength = r.byte(), let context = r.take(Int(contextLength)),
              let extensionsLength = r.uint16(), r.skip(Int(extensionsLength)), r.isEmpty
        else { return fail(TLSAlert.decodeError) }
        if certificateRequested { return fail(TLSAlert.unexpectedMessage) }
        certificateRequested = true
        certificateRequestContext = [UInt8](UnsafeBufferPointer(start: context, count: Int(contextLength)))
        transcript?.pointee.update(UnsafeRawBufferPointer(start: message, count: total))
    }

    private func handleCertificate(_ message: UnsafePointer<UInt8>, _ total: Int) {
        var r = QUICReader(message, total)
        _ = r.skip(4)
        // A server's Certificate answers no request, so its context is empty.
        guard let contextLength = r.byte() else { return fail(TLSAlert.decodeError) }
        if contextLength != 0 { return fail(TLSAlert.illegalParameter) }
        guard let listLength = r.uint24(), let list = r.take(Int(listLength)), r.isEmpty
        else { return fail(TLSAlert.decodeError) }

        var chain: [[UInt8]] = []
        var l = QUICReader(list, Int(listLength))
        while !l.isEmpty {
            guard let certLength = l.uint24(), certLength > 0, let der = l.take(Int(certLength)),
                  let extLength = l.uint16(), l.skip(Int(extLength))
            else { return fail(TLSAlert.decodeError) }
            chain.append([UInt8](UnsafeBufferPointer(start: der, count: Int(certLength))))
        }
        if chain.isEmpty { return fail(TLSAlert.decodeError) }
        peerCertificates = chain

        if let verifyChain, let reason = verifyChain(chain, name) {
            certificateError = reason
            return fail(TLSAlert.badCertificate)
        }
        transcript?.pointee.update(UnsafeRawBufferPointer(start: message, count: total))
        state = .waitingCertificateVerify
    }

    private func handleCertificateVerify(_ message: UnsafePointer<UInt8>, _ total: Int) {
        var r = QUICReader(message, total)
        _ = r.skip(4)
        guard let scheme = r.uint16(), let signatureLength = r.uint16(),
              let signature = r.take(Int(signatureLength)), r.isEmpty
        else { return fail(TLSAlert.decodeError) }
        if !TLSClientHandshake.signatureSchemes.contains(scheme) { return fail(TLSAlert.illegalParameter) }

        // What the server signed: the fixed preamble and the transcript
        // through its Certificate, which is what ties the key in that
        // certificate to this handshake rather than to a recording.
        var content = [UInt8](repeating: 0x20, count: 64)
        content += Array("TLS 1.3, server CertificateVerify".utf8)
        content.append(0)
        guard let digest = transcriptHash() else { return fail(TLSAlert.internalError) }
        content += digest

        guard let key = try? PublicKey(certificateDER: peerCertificates[0]) else {
            return fail(TLSAlert.badCertificate)
        }
        let bytes = [UInt8](UnsafeBufferPointer(start: signature, count: Int(signatureLength)))
        if !key.isValidSignature(bytes, for: content, scheme: TLSSignatureScheme(rawValue: scheme)) {
            return fail(TLSAlert.decryptError)
        }
        transcript?.pointee.update(UnsafeRawBufferPointer(start: message, count: total))
        state = .waitingFinished
    }

    private func handleFinished(_ message: UnsafePointer<UInt8>, _ total: Int) {
        let length = total - 4
        guard length == cipher.hashLength,
              let expected = finishedValue(secret: serverHandshakeSecret)
        else { return fail(TLSAlert.decryptError) }
        // Constant time, as the server compares ours.
        var difference: UInt8 = 0
        for i in 0..<length { difference |= expected[i] ^ message[4 + i] }
        if difference != 0 { return fail(TLSAlert.decryptError) }
        transcript?.pointee.update(UnsafeRawBufferPointer(start: message, count: total))

        // The application secrets come from the transcript through the
        // server's Finished, whatever the client sends after it.
        if !deriveApplicationSecrets() { return fail(TLSAlert.internalError) }

        var out = ByteBuffer(capacity: 128)
        defer { out.destroy() }
        if certificateRequested {
            // No certificate: an empty list, under the request's context.
            out.writeByte(HandshakeType.certificate)
            let body = out.openLength(3)
            out.writeByte(UInt8(certificateRequestContext.count))
            certificateRequestContext.withUnsafeBufferPointer {
                if $0.count > 0 { out.write($0.baseAddress!, $0.count) }
            }
            out.writeUInt24BE(0)
            out.closeLength(body, 3)
            emit(&out)
            out.clear()
        }
        out.writeByte(HandshakeType.finished)
        let body = out.openLength(3)
        guard let verify = finishedValue(secret: clientHandshakeSecret) else { return fail(TLSAlert.internalError) }
        verify.withUnsafeBufferPointer { out.write($0.baseAddress!, $0.count) }
        out.closeLength(body, 3)
        emit(&out)

        state = .complete
        scrubSecrets()
    }

    /// Appends a message to the Handshake level's output and to the
    /// transcript, together and in that order.
    private func emit(_ message: inout ByteBuffer) {
        transcript?.pointee.update(UnsafeRawBufferPointer(start: message.readPointer, count: message.readableBytes))
        handshakeOut.write(message.readPointer, message.readableBytes)
    }

    // MARK: Key schedule (RFC 8446 section 7.1), as the server's

    private func expand(_ secret: [UInt8], _ label: StaticString, context: [UInt8], length: Int) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: length)
        let ok = secret.withUnsafeBufferPointer { s in
            out.withUnsafeMutableBufferPointer { o in
                context.withUnsafeBufferPointer { c in
                    quicExpandLabel(hash: cipher.hash, secret: s.baseAddress!, secretLen: s.count, label: label,
                                    context: c.count > 0 ? c.baseAddress : nil, contextLen: c.count,
                                    out: o.baseAddress!, outLen: length)
                }
            }
        }
        return ok ? out : nil
    }

    private func extract(salt: [UInt8], ikm: [UInt8]) -> [UInt8]? {
        let out = HKDF.extract(cipher.hash, salt: salt, inputKeyMaterial: ikm)
        return out.count == cipher.hashLength ? out : nil
    }

    private func transcriptHash() -> [UInt8]? {
        guard let transcript else { return nil }
        let digest = transcript.pointee.snapshot()
        return digest.count == cipher.hashLength ? digest : nil
    }

    private func emptyHash() -> [UInt8]? {
        let digest = Hash.digest(cipher.hash, [])
        return digest.count == cipher.hashLength ? digest : nil
    }

    private func deriveHandshakeSecrets(_ shared: [UInt8]) -> Bool {
        let zeros = [UInt8](repeating: 0, count: cipher.hashLength)
        guard let early = extract(salt: [], ikm: zeros),
              let empty = emptyHash(),
              let derived = expand(early, "derived", context: empty, length: cipher.hashLength),
              let handshake = extract(salt: derived, ikm: shared),
              let hash = transcriptHash(),
              let client = expand(handshake, "c hs traffic", context: hash, length: cipher.hashLength),
              let server = expand(handshake, "s hs traffic", context: hash, length: cipher.hashLength)
        else { return false }
        handshakeSecret = handshake
        clientHandshakeSecret = client
        serverHandshakeSecret = server
        pendingSecrets.append(TLSSecrets(level: .handshake, client: client, server: server, cipher: cipher))
        return true
    }

    private func deriveApplicationSecrets() -> Bool {
        let zeros = [UInt8](repeating: 0, count: cipher.hashLength)
        guard let empty = emptyHash(),
              let derived = expand(handshakeSecret, "derived", context: empty, length: cipher.hashLength),
              let master = extract(salt: derived, ikm: zeros),
              let hash = transcriptHash(),
              let client = expand(master, "c ap traffic", context: hash, length: cipher.hashLength),
              let server = expand(master, "s ap traffic", context: hash, length: cipher.hashLength)
        else { return false }
        pendingSecrets.append(TLSSecrets(level: .application, client: client, server: server, cipher: cipher))
        return true
    }

    private func finishedValue(secret: [UInt8]) -> [UInt8]? {
        guard let key = expand(secret, "finished", context: [], length: cipher.hashLength),
              let hash = transcriptHash()
        else { return nil }
        let out = HMAC.authenticationCode(cipher.hash, key: key, data: hash)
        return out.count == cipher.hashLength ? out : nil
    }
}
#endif
