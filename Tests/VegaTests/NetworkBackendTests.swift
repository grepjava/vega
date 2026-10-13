#if canImport(Network)
import Darwin
import Synchronization
import Testing
@testable import Vega

/// IOBackend.network (Network.framework) on its own runtime, whatever
/// VEGA_DRIVER says. The TCP and server suites also run on it with
/// VEGA_DRIVER=network.
@Suite struct NetworkBackendTests {
    private func runtime() -> Runtime { Runtime(workers: 2, io: .network) }

    @Test func reportsTheBackend() {
        let rt = runtime()
        defer { rt.shutdown() }
        #expect(rt.ioBackend == .network)
        #expect(Runtime(workers: 1, io: .readiness).ioBackend == .readiness)
        #if !os(macOS)
        // The default on iOS, tvOS, watchOS and visionOS.
        if getenv("VEGA_DRIVER") == nil {
            let auto = Runtime(workers: 1)
            #expect(auto.ioBackend == .network)
            auto.shutdown()
        }
        #endif
    }

    /// An echo through split halves, both ends Network.framework sockets.
    @Test func echoesThroughSplitHalves() throws {
        let rt = runtime()
        defer { rt.shutdown() }
        let reply = try rt.block { () async throws(IOError) -> String in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            #expect(listener.localPort > 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let server = try await listener.accept()
            rt.spawn(with: server) { conn in
                let halves = conn.split()
                var buf = IOBuffer(capacity: 64)
                while let n = try? await halves.reader.read(into: &buf), n > 0 {
                    try? await halves.writer.write(buf)
                    buf.clear()
                }
            }
            #expect(try client.peerAddress.port == listener.localPort)
            #expect(try client.localAddress.port != nil)
            var out = IOBuffer(capacity: 16)
            out.append("ping")
            try await client.write(out)
            try client.shutdownWrite()
            var back = IOBuffer(capacity: 16)
            while try await client.read(into: &back) > 0 {}
            return back.string
        }
        #expect(reply == "ping")
    }

    /// A read cancelled while Network.framework is receiving: the bytes that
    /// arrive afterwards go to the next read, not nowhere.
    @Test func cancelledReadLosesNothing() throws {
        let rt = runtime()
        defer { rt.shutdown() }
        let (first, second) = try rt.block { () async throws(IOError) -> (IOError?, String) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let server = try await listener.accept()
            let halves = server.split()
            let reader = rt.spawn(with: halves.reader) { r -> (IOError?, ReadHalfBox) in
                var buf = IOBuffer(capacity: 16)
                do throws(IOError) {
                    _ = try await r.read(into: &buf)
                    return (nil, ReadHalfBox(r))
                } catch {
                    return (error, ReadHalfBox(r))
                }
            }
            try? await Runtime.sleep(for: .milliseconds(20))
            reader.cancel()
            let (error, box) = await reader.value
            var out = IOBuffer(capacity: 16)
            out.append("late")
            try await client.write(out)
            let r = box.take()
            var buf = IOBuffer(capacity: 16)
            while buf.count < 4 {
                if try await r.read(into: &buf) == 0 { break }
            }
            _ = halves.writer
            return (error, buf.string)
        }
        #expect(first == .cancelled)
        #expect(second == "late")
    }

    /// Options are fixed when Network.framework makes a connection: the
    /// client's and the server's go in then, and read back.
    @Test func optionsApplyWhenTheConnectionIsMade() throws {
        let rt = runtime()
        defer { rt.shutdown() }
        let (client, served) = try rt.block { () async throws -> (Int, Int) in
            let seen = Atomic<Int>(-1)
            let server = try TCPServer.bind(host: "127.0.0.1", port: 0,
                                            configuration: .init(connectionOptions: [.keepAlive: 1])) { stream in
                seen.store((try? stream.option(.keepAlive)) ?? -2, ordering: .relaxed)
            }
            let stream = try await TCPClient(options: [.keepAliveIdle: 30]).connect(host: "127.0.0.1",
                                                                                   port: server.port)
            #expect(try stream.option(.noDelay) == 1)
            #expect(throws: IOError.unsupported) { try stream.setOption(.keepAliveIdle, to: 60) }
            try stream.setOption(.keepAliveIdle, to: 30) // as made: nothing to change
            #expect(throws: IOError.unsupported) { try stream.setOption(.receiveBufferSize, to: 1 << 20) }
            var buf = IOBuffer(capacity: 4)
            _ = try await stream.read(into: &buf) // the handler returned: end of stream
            await server.shutdown(gracePeriod: .seconds(1))
            return (try stream.option(.keepAliveIdle), seen.load(ordering: .relaxed))
        }
        #expect(client == 30)
        #expect(served == 1)
    }

    /// Dropping a listener stops it before the next line runs, as close(2).
    @Test func aClosedListenerRefuses() throws {
        let rt = runtime()
        defer { rt.shutdown() }
        let error = try rt.block { () async throws(IOError) -> IOError? in
            let port = try TCPListener.bind(host: "127.0.0.1", port: 0).localPort
            do throws(IOError) {
                _ = try await TCPStream.connect(host: "127.0.0.1", port: port)
                return nil
            } catch {
                return error
            }
        }
        #expect(error == .connectionRefused)
    }

    /// Everything but TCP keeps the kqueue driver.
    @Test func pipesStillWork() throws {
        let rt = runtime()
        defer { rt.shutdown() }
        let got = try rt.block { () async throws(IOError) -> String in
            let pipe = try makePipe()
            var out = IOBuffer(capacity: 8)
            out.append("pipe")
            try await pipe.writer.write(out)
            var buf = IOBuffer(capacity: 8)
            _ = try await pipe.reader.read(into: &buf)
            return buf.string
        }
        #expect(got == "pipe")
    }
}

/// Moves a read half out of a task.
private final class ReadHalfBox: @unchecked Sendable {
    private var half: ReadHalf?
    init(_ half: consuming ReadHalf) { self.half = consume half }
    func take() -> ReadHalf { half.take()! }
}
#endif
