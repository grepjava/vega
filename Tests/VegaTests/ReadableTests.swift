#if os(Linux) || canImport(Darwin) || os(Windows)
import Testing
@testable import Vega

/// `readable()` and `peerClosed()`: waiting on a connection without reading.
@Suite struct ReadableTests {
    @Test func peerClosedSeesTheClientHangUp() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let closed = try rt.block { () async throws(IOError) -> Bool in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let conn = try await listener.accept()
            rt.spawn(with: client) { client async in
                try? await Runtime.sleep(for: .milliseconds(20))
                _ = consume client
            }
            return try await Runtime.withIOTimeout(for: .seconds(5)) { () async throws(IOError) -> Bool in
                try await conn.peerClosed()
            }
        }
        #expect(closed)
    }

    @Test func peerClosedIsFalseWhenInputArrivesAndLeavesItToRead() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (closed, text) = try rt.block { () async throws(IOError) -> (Bool, String) in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let conn = try await listener.accept()
            rt.spawn(with: client) { client async in
                try? await Runtime.sleep(for: .milliseconds(20))
                try? await client.write(IOBuffer(copying: Array("next".utf8)))
                try? await Runtime.sleep(for: .seconds(1))
            }
            let closed = try await conn.peerClosed()
            var buf = IOBuffer(capacity: 16)
            try await readExactly(conn, 4, into: &buf)
            return (closed, buf.string)
        }
        #expect(!closed)
        #expect(text == "next")
    }

    @Test func aReadAfterAReadableWaitDoesNotWaitForAnEdgeItTook() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let text = try rt.block { () async throws(IOError) -> String in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let conn = try await listener.accept()
            try await client.write(IOBuffer(copying: Array("a".utf8)))
            // A short read: the socket is drained, and the next read would
            // wait for a readiness edge before asking it.
            var first = IOBuffer(capacity: 16)
            _ = try await conn.read(into: &first)
            rt.spawn(with: client) { client async in
                try? await Runtime.sleep(for: .milliseconds(20))
                try? await client.write(IOBuffer(copying: Array("b".utf8)))
                try? await Runtime.sleep(for: .seconds(1))
            }
            try await conn.readable()
            return try await Runtime.withIOTimeout(for: .seconds(2)) { () async throws(IOError) -> String in
                var second = IOBuffer(capacity: 16)
                _ = try await conn.read(into: &second)
                return first.string + second.string
            }
        }
        #expect(text == "ab")
    }

    @Test func aDeadlineEndsTheWait() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let outcome = try rt.block { () async throws(IOError) -> IOError? in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let client = try await TCPStream.connect(host: "127.0.0.1", port: listener.localPort)
            let conn = try await listener.accept()
            var outcome: IOError?
            do throws(IOError) {
                _ = try await Runtime.withIOTimeout(for: .milliseconds(50)) { () async throws(IOError) -> Bool in
                    try await conn.peerClosed()
                }
            } catch {
                outcome = error
            }
            // The client stays connected and silent until the wait is over.
            _ = consume client
            return outcome
        }
        #expect(outcome == .timedOut)
    }

    @Test func unixStreamsToo() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (input, closed) = try rt.block { () async throws(IOError) -> (Bool, Bool) in
            let pair = try UnixStream.pair()
            let a = pair.first, b = pair.second
            try await a.write(IOBuffer(copying: Array("x".utf8)))
            let input = try await b.peerClosed()
            var buf = IOBuffer(capacity: 4)
            _ = try await b.read(into: &buf)
            _ = consume a
            return (input, try await b.peerClosed())
        }
        #expect(!input)
        #expect(closed)
    }
}
#endif
