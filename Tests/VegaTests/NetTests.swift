#if os(Linux) || canImport(Darwin) || os(Windows)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif
import Testing
@testable import Vega

/// Echo everything until the peer closes, then drop the connection.
func echo(_ conn: borrowing TCPStream) async {
    var buf = IOBuffer(capacity: 64 * 1024)
    while (try? await conn.read(into: &buf)) ?? 0 > 0 {
        if (try? await conn.write(buf)) == nil { return }
        buf.clear()
    }
}

/// Sockets open on the current runtime's driver.
func registered() throws(IOError) -> Int {
    guard let raw = try IODriver.current().raw else {
        return Int(cv_count_load(Worker.currentScheduler!.socketCount))
    }
    // Network.framework sockets count with the uring driver's (IOBackend.network).
    let network = Worker.currentScheduler!.usesNetwork ? Int(cv_count_load(Worker.currentScheduler!.socketCount)) : 0
    return Int(cv_driver_registered(raw)) + network
}

/// Where tests put scratch files: %TEMP% on Windows, /tmp elsewhere.
func testTempDirectory() -> String {
    #if os(Windows)
    var dir = getenv("TEMP").map { String(cString: $0) } ?? #"C:\Windows\Temp"#
    while dir.hasSuffix("\\") { dir.removeLast() }
    return dir
    #else
    return "/tmp"
    #endif
}

func tempSocketPath() -> String {
    "\(testTempDirectory())/vega-test-\(getpid())-\(UInt32.random(in: 0...UInt32.max)).sock"
}

@Suite struct SplitTests {
    /// 4 MB through an echo server: far more than the socket buffers hold, so
    /// writing it all before reading would deadlock. The halves run at once.
    @Test func halvesReadAndWriteConcurrently() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let total = 4 << 20
        let (received, intact) = try rt.block { () async throws(IOError) -> (Int, Bool) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            rt.spawn(with: try await listener.accept()) { conn in await echo(conn) }

            let halves = client.split()
            rt.spawn(with: halves.writer) { writer in
                var chunk = IOBuffer(capacity: 64 * 1024)
                var sent = 0
                while sent < total {
                    chunk.clear()
                    chunk.withUnsafeSpareCapacity { room in
                        for i in 0..<room.count { room[i] = UInt8(truncatingIfNeeded: (sent + i) % 251) }
                        return room.count
                    }
                    if (try? await writer.write(chunk)) == nil { return }
                    sent += chunk.count
                }
                // Dropping the writer sends FIN; the server then closes.
            }
            let reader = halves.reader
            var buf = IOBuffer(capacity: 64 * 1024)
            var got = 0, intact = true
            while true {
                buf.clear()
                let n = try await reader.read(into: &buf)
                if n == 0 { break }
                buf.withUnsafeBytes { bytes in
                    for i in 0..<n where bytes[i] != UInt8(truncatingIfNeeded: (got + i) % 251) {
                        intact = false
                    }
                }
                got += n
            }
            return (got, intact)
        }
        #expect(received == total)
        #expect(intact)
    }

    /// Dropping the write half sends end-of-stream but keeps reading; the
    /// socket is unregistered only when the second half goes.
    @Test func droppingTheWriteHalfShutsDownSendingOnly() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (eof, reply, before, withReader, after) = try rt.block {
            () async throws(IOError) -> (Int, String, Int, Int, Int) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let server = try await listener.accept()
            let before = try registered()

            let halves = client.split()
            let reader = halves.reader
            _ = consume halves.writer

            var buf = IOBuffer(capacity: 64)
            let eof = try await server.read(into: &buf) // FIN from the dropped writer
            buf.append("still open")
            try await server.write(buf)
            var back = IOBuffer(capacity: 64)
            while back.count < 10, try await reader.read(into: &back) > 0 {}
            let withReader = try registered()
            _ = consume reader
            return (eof, back.string, before, withReader, try registered())
        }
        #expect(eof == 0)
        #expect(reply == "still open")
        #expect(withReader == before)
        #expect(after == before - 1)
    }
}

@Suite struct LookupTests {
    /// `.invalid` never resolves (RFC 6761). Without a network the lookup
    /// may fail instead of finding nothing; either is named, not an errno.
    @Test func anUnknownHostIsNotFound() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let error = rt.block { () async -> IOError? in
            do throws(IOError) {
                _ = try await SocketAddress.lookup(host: "no-such-host.invalid", port: 80)
                return nil
            } catch {
                return error
            }
        }
        #expect(error == .hostNotFound || error == .lookupFailed, "\(String(describing: error))")
    }
}

@Suite struct UDPTests {
    @Test func sendToAndReceiveFrom() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (text, from, expected) = try rt.block {
            () async throws(IOError) -> (String, SocketAddress, SocketAddress) in
            let a = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let b = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            var out = IOBuffer(capacity: 64)
            out.append("datagram")
            try await a.send(out, to: try b.localAddress)
            var buf = IOBuffer(capacity: 64)
            let (n, from) = try await b.receiveFrom(into: &buf)
            #expect(n == 8)
            return (buf.string, from, try a.localAddress)
        }
        #expect(text == "datagram")
        #expect(from == expected)
    }

    /// A connected pair trading many datagrams, each a separate message.
    @Test func connectedPingPong() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let rounds = 1000
        let last = try rt.block { () async throws(IOError) -> Int in
            let server = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let port = try server.localAddress.port!
            rt.spawn(with: server) { server in
                var buf = IOBuffer(capacity: 16)
                for _ in 0..<rounds {
                    buf.clear()
                    guard let (_, from) = try? await server.receiveFrom(into: &buf) else { return }
                    _ = try? await server.send(buf, to: from)
                }
            }
            let client = try await UDPSocket.connect(host: "127.0.0.1", port: port)
            var buf = IOBuffer(capacity: 16)
            var out = IOBuffer(capacity: 4)
            var value = 0
            for i in 0..<rounds {
                out.clear()
                out.withUnsafeSpareCapacity { room in
                    room.storeBytes(of: UInt32(i), as: UInt32.self)
                    return 4
                }
                try await client.send(out)
                buf.clear()
                #expect(try await client.receive(into: &buf) == 4)
                value = Int(buf.withUnsafeBytes { $0.load(as: UInt32.self) })
            }
            return value
        }
        #expect(last == rounds - 1)
    }

    /// Cancelled receives leave no waiter behind: once a datagram is there,
    /// the cancelled task still gets it.
    @Test func cancelledReceiveLeavesTheSocketUsable() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (first, text) = try rt.block { () async throws(IOError) -> (IOError?, String) in
            let socket = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            let address = try socket.localAddress
            let receiver = rt.spawn(with: socket) { socket -> String in
                var buf = IOBuffer(capacity: 64)
                do throws(IOError) {
                    _ = try await socket.receive(into: &buf) // nothing sent yet
                    UDPOutcome.set(nil)
                } catch {
                    UDPOutcome.set(error)
                }
                // Still cancelled, so every wait gives up at once; keep trying
                // until the datagram is there to read without one.
                for _ in 0..<1_000_000 {
                    if (try? await socket.receive(into: &buf)) != nil { return buf.string }
                    await Task.yield()
                }
                return ""
            }
            try? await Runtime.sleep(for: .milliseconds(20))
            receiver.cancel()
            let sender = try UDPSocket.bind(host: "127.0.0.1", port: 0)
            var out = IOBuffer(capacity: 64)
            out.append("after cancel")
            try await sender.send(out, to: address)
            let text = await receiver.value
            return (UDPOutcome.get(), text)
        }
        #expect(first == .cancelled)
        #expect(text == "after cancel")
    }
}

@Suite struct UnixTests {
    @Test func listenerAndConnect() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let path = tempSocketPath()
        defer { unlink(path) }
        let reply = try rt.block { () async throws(IOError) -> String in
            let listener = try UnixListener.bind(path: path)
            let client = try await UnixStream.connect(path: path)
            let conn = try await listener.accept()
            var out = IOBuffer(capacity: 64)
            out.append("over unix")
            try await client.write(out)
            var buf = IOBuffer(capacity: 64)
            while buf.count < 9, try await conn.read(into: &buf) > 0 {}
            try await conn.write(buf)
            var back = IOBuffer(capacity: 64)
            while back.count < 9, try await client.read(into: &back) > 0 {}
            return back.string
        }
        #expect(reply == "over unix")
    }

    @Test func connectToMissingPathFails() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let error = rt.block { () async -> IOError? in
            do throws(IOError) {
                _ = try await UnixStream.connect(path: tempSocketPath())
                return nil
            } catch {
                return error
            }
        }
        #expect(error == IOError(code: ENOENT))
    }

    @Test func pairAndSplit() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let text = try rt.block { () async throws(IOError) -> String in
            let pair = try UnixStream.pair()
            let halves = pair.first.split()
            let other = pair.second
            var out = IOBuffer(capacity: 64)
            out.append("ping")
            try await halves.writer.write(out)
            var buf = IOBuffer(capacity: 64)
            while buf.count < 4, try await other.read(into: &buf) > 0 {}
            buf.append(" pong")
            try await other.write(buf)
            var back = IOBuffer(capacity: 64)
            while back.count < 9, try await halves.reader.read(into: &back) > 0 {}
            return back.string
        }
        #expect(text == "ping pong")
    }
}

@Suite struct SocketAddressTests {
    @Test func formatsAndCompares() throws {
        let v4 = try SocketAddress(host: "127.0.0.1", port: 8080)
        #expect(v4.description == "127.0.0.1:8080")
        #expect(v4.port == 8080)
        #expect(!v4.isIPv6)
        let v6 = try SocketAddress(host: "::1", port: 443)
        #expect(v6.description == "[::1]:443")
        #expect(v6.isIPv6)
        #expect(v4 == (try SocketAddress(host: "127.0.0.1", port: 8080)))
        #expect(v4 != (try SocketAddress(host: "127.0.0.1", port: 8081)))
        #expect(Set([v4, v6, v4]).count == 2)
    }
}

private enum UDPOutcome {
    nonisolated(unsafe) static var value: IOError??
    static func set(_ e: IOError?) { value = .some(e) }
    static func get() -> IOError? { value ?? nil }
}
#endif
