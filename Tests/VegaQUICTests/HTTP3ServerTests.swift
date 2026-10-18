// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
//===----------------------------------------------------------------------===//
// HTTP3Server over a real socket, against the tests' QUIC client speaking
// HTTP/3 by hand: a control stream with SETTINGS, and requests as HEADERS
// and DATA frames.
//===----------------------------------------------------------------------===//

import Testing
import Vega
import VegaIO
import VegaCrypto
import VegaTLS
import VegaHTTP1
import VegaHTTP3Core
import QUICTestPeer
import VegaQUIC
@testable import VegaHTTP3
@testable import VegaQUICCore

/// The frames in `bytes`, in order.
private func frames(_ bytes: [UInt8]) throws -> [HTTP3RawFrame] {
    var decoder = HTTP3FrameDecoder(maxPayload: 1 << 20)
    var out: [HTTP3RawFrame] = []
    var at = 0
    while at < bytes.count {
        let next = try bytes.withUnsafeBytes { b in try decoder.decode(UnsafeRawBufferPointer(rebasing: b[at...])) }
        guard let next else { throw QUICTestPeerError("a frame cut short") }
        out.append(next.item)
        at += next.consumed
    }
    return out
}

/// A response's head and body from the frames on its stream.
private func response(_ bytes: [UInt8]) throws -> (HTTPResponseHead, [UInt8]) {
    var head: HTTPResponseHead?
    var body: [UInt8] = []
    for frame in try frames(bytes) {
        if frame.type == HTTP3FrameType.headers {
            head = h3DecodeFields(frame.payload, maxSize: 1 << 16)?.responseHead(version: .http3)
        } else if frame.type == HTTP3FrameType.data {
            body += frame.payload
        }
    }
    guard let head else { throw QUICTestPeerError("no response head") }
    return (head, body)
}

private func request(_ method: String, _ path: String, fields: HTTPFields = [:], body: [UInt8] = []) -> [UInt8] {
    var out = h3HeadersFrame(pseudo: [(":method", method), (":scheme", "https"), (":authority", "localhost"),
                                      (":path", path)], fields)
    if !body.isEmpty { out += h3Frame(HTTP3FrameType.data, body) }
    return out
}

@Suite("HTTP3Server")
struct HTTP3ServerTests {
    @Test func servesRequests() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let identity = try TLSIdentity.selfSigned(names: ["localhost"])
        let certificate = try CertificateKey(chainPEM: identity.certificateChain, keyPEM: identity.privateKey)
        let result = try rt.block { () async throws -> ([UInt8]?, (HTTPResponseHead, [UInt8]), (HTTPResponseHead, [UInt8])) in
            let endpoint = try QUICEndpoint.bind(host: "127.0.0.1", port: 0,
                                                   configuration: HTTP3Server.quicConfiguration(certificate: certificate),
                                                   runtime: rt)
            let server = rt.spawn {
                await HTTP3Server.serve(endpoint) { request in
                    HTTPResponse(status: 200, fields: ["x-method": request.head.method.rawValue],
                                 body: "\(request.head.target) \(request.body.count) \(request.head.fields["host"] ?? "-")")
                }
            }
            let wire = Wire(socket: try UDPSocket.bind(host: "127.0.0.1", port: 0),
                            server: try SocketAddress(host: "127.0.0.1", port: endpoint.localPort))
            let client = try QUICTestPeer()
            try await handshake(client, wire, alpn: "h3")
            // Our control stream (client uni: ID 2), and two requests.
            let control = h3Varint(HTTP3StreamType.control) + h3Frame(HTTP3FrameType.settings, [])
            try await wire.send(try client.packet(.application, client.ack(.application)
                                                   + streamFrame(2, control, fin: false)
                                                   + streamFrame(0, request("GET", "/hello"), fin: true)
                                                   + streamFrame(4, request("POST", "/upload", body: Array(repeating: 7, count: 300)),
                                                                 fin: true)))
            try await wire.pump(into: client) { client.finished.contains(0) && client.finished.contains(4) }
            let first = try response(client.streams[0] ?? [])
            let second = try response(client.streams[4] ?? [])
            await endpoint.close(grace: .milliseconds(100))
            await server.value
            return (client.streams[3], first, second)
        }
        let (serverControl, first, second) = result
        // The server's control stream (server uni: ID 3) opens with SETTINGS.
        #expect(serverControl?.prefix(2) == [0x00, 0x04])
        #expect(first.0.status == 200)
        #expect(first.0.fields["x-method"] == "GET")
        #expect(String(decoding: first.1, as: UTF8.self) == "/hello 0 localhost")
        #expect(second.0.status == 200)
        #expect(String(decoding: second.1, as: UTF8.self) == "/upload 300 localhost")
    }

    /// A request without :path is malformed: the stream is reset with
    /// H3_MESSAGE_ERROR, and the connection goes on.
    @Test func malformedRequestIsAStreamError() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let identity = try TLSIdentity.selfSigned(names: ["localhost"])
        let certificate = try CertificateKey(chainPEM: identity.certificateChain, keyPEM: identity.privateKey)
        let (reset, after) = try rt.block { () async throws -> (UInt64?, Int?) in
            let endpoint = try QUICEndpoint.bind(host: "127.0.0.1", port: 0,
                                                   configuration: HTTP3Server.quicConfiguration(certificate: certificate),
                                                   runtime: rt)
            let server = rt.spawn { await HTTP3Server.serve(endpoint) { _ in HTTPResponse(status: 204) } }
            let wire = Wire(socket: try UDPSocket.bind(host: "127.0.0.1", port: 0),
                            server: try SocketAddress(host: "127.0.0.1", port: endpoint.localPort))
            let client = try QUICTestPeer()
            try await handshake(client, wire, alpn: "h3")
            let bad = h3HeadersFrame(pseudo: [(":method", "GET"), (":scheme", "https")], [:])
            try await wire.send(try client.packet(.application, client.ack(.application)
                                                   + streamFrame(2, h3Varint(HTTP3StreamType.control)
                                                                 + h3Frame(HTTP3FrameType.settings, []), fin: false)
                                                   + streamFrame(0, bad, fin: true)
                                                   + streamFrame(4, request("GET", "/ok"), fin: true)))
            try await wire.pump(into: client) { client.resets[0] != nil && client.finished.contains(4) }
            let after = try? response(client.streams[4] ?? []).0.status
            await endpoint.close(grace: .milliseconds(100))
            await server.value
            return (client.resets[0], after)
        }
        #expect(reset == HTTP3Error.messageError)
        #expect(after == 204)
    }
}
#endif
