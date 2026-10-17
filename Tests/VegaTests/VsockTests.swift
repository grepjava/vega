#if os(Linux)
import CVega
import Glibc
import Testing
@testable import Vega
import VegaIO

/// Whether the kernel has vsock at all (a socket opens).
private let vsockPresent: Bool = {
    let fd = socket(40 /* AF_VSOCK */, Int32(SOCK_STREAM.rawValue), 0)
    guard fd >= 0 else { return false }
    close(fd)
    return true
}()

/// Whether this machine can reach itself over vsock: the vsock_loopback
/// module, which serves VMADDR_CID_LOCAL. Without it a bind to that context
/// id fails with EADDRNOTAVAIL (and a connect with ENETUNREACH or ENODEV).
private let vsockLoopback: Bool = {
    let fd = socket(40 /* AF_VSOCK */, Int32(SOCK_STREAM.rawValue), 0)
    guard fd >= 0 else { return false }
    defer { close(fd) }
    var address = cv_sockaddr()
    cv_vsock_sockaddr(VsockAddress.localCID, VsockAddress.anyPort, &address)
    return cv_bind_address(fd, &address) == 0
}()

/// Echo until end of stream, through the stream protocols.
private func echo<S: AsyncReader & AsyncWriter & ~Copyable>(_ stream: borrowing S) async {
    var buf = IOBuffer(capacity: 4096)
    while let n = try? await stream.read(into: &buf), n > 0 {
        try? await stream.write(buf)
        buf.clear()
    }
}

@Suite("Vsock")
struct VsockTests {
    @Test func addressesRoundTripThroughSocketAddress() {
        let vsock = VsockAddress(cid: 3, port: 5000)
        let address = SocketAddress(vsock: vsock)
        #expect(address.vsock == vsock)
        #expect(address.port == nil)
        #expect(address.ipBytes == nil)
        #expect(address.host == "")
        #expect(address.description == "vsock:3:5000")
        #expect(address == SocketAddress(vsock: VsockAddress(cid: 3, port: 5000)))
        #expect(SocketAddress(numericHost: "127.0.0.1", port: 80)!.vsock == nil)
    }

    /// A listener on every context id gets a port of its own.
    @Test(.enabled(if: vsockPresent, "no AF_VSOCK in this kernel"))
    func listenerBindsAFreePort() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let local = try rt.block { () async throws(IOError) -> VsockAddress in
            let listener = try VsockListener.bind(port: VsockAddress.anyPort)
            return try listener.localAddress
        }
        #expect(local.cid == VsockAddress.anyCID)
        #expect(local.port != VsockAddress.anyPort)
    }

    /// Echo over loopback: VMADDR_CID_LOCAL, through vsock_loopback.
    @Test(.enabled(if: vsockLoopback, "vsock_loopback is not loaded (no VMADDR_CID_LOCAL)"))
    func echoOverLoopback() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (echoed, peer) = try rt.block { () async throws(IOError) -> (String, VsockAddress) in
            let listener = try VsockListener.bind(port: VsockAddress.anyPort)
            let port = try listener.localAddress.port
            rt.spawn(with: listener) { listener in
                guard let stream = try? await listener.accept() else { return }
                await echo(stream)
                try? stream.shutdownWrite()
            }
            let client = try await VsockStream.connect(cid: VsockAddress.localCID, port: port)
            let peer = try client.peerAddress
            var out = IOBuffer(capacity: 64)
            _ = Array("hello vsock".utf8).withUnsafeBytes { out.append($0) }
            try await client.write(out)
            try client.shutdownWrite()
            var got = IOBuffer(capacity: 4096)
            while try await client.read(into: &got) > 0 {}
            return (got.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }, peer)
        }
        #expect(echoed == "hello vsock")
        #expect(peer.cid == VsockAddress.localCID)
    }
}
#endif
