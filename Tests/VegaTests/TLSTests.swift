#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import Synchronization
import Testing
import Vega
import VegaIO
import VegaTest
import VegaTLS

private let serverIdentity = try! TLSIdentity.selfSigned(names: ["vega.test", "127.0.0.1"])

private func serverContext(_ configure: (inout TLSConfiguration) -> Void = { _ in }) throws -> TLSContext {
    var c = TLSConfiguration.server(identity: serverIdentity, applicationProtocols: ["h2", "http/1.1"])
    configure(&c)
    return try TLSContext(c)
}

private func clientContext(_ configure: (inout TLSConfiguration) -> Void = { _ in }) throws -> TLSContext {
    var c = TLSConfiguration.client(trustRoots: .certificates(serverIdentity.certificateChain),
                                    applicationProtocols: ["http/1.1", "h2"])
    configure(&c)
    return try TLSContext(c)
}

private func bytes(_ s: String) -> IOBuffer {
    var b = IOBuffer(capacity: max(s.utf8.count, 1))
    b.append(s)
    return b
}

/// What the server side saw: its error, or the agreed protocol.
private typealias ServerResult = Result<String?, IOError>

/// A handshake over an in-memory pipe: the server echoes one message and
/// closes. Returns what the client read back, and the server's result.
private func exchange(server: TLSContext, client: TLSContext, name: String? = "vega.test",
                      message: String = "hello over TLS") throws -> (Result<String, IOError>, ServerResult) {
    let rt = Runtime(workers: 2)
    defer { rt.shutdown() }
    return try rt.block { () async throws -> (Result<String, IOError>, ServerResult) in
        let pair = duplex(capacity: 64 * 1024)
        let serverTask = rt.spawn(with: pair.second) { transport async -> ServerResult in
            do throws(IOError) {
                let tls = try await TLSStream.accept(transport, context: server)
                let alpn = tls.applicationProtocol
                var buf = IOBuffer(capacity: 1024)
                _ = try await tls.read(into: &buf)
                try await tls.write(buf)
                _ = try await tls.close()
                return .success(alpn)
            } catch {
                return .failure(error)
            }
        }
        let clientResult: Result<String, IOError>
        do throws(IOError) {
            let tls = try await TLSStream.connect(pair.first, serverName: name, context: client)
            try await tls.write(bytes(message))
            var buf = IOBuffer(capacity: 1024)
            while try await tls.read(into: &buf) > 0 {}
            clientResult = .success(buf.string)
        } catch {
            clientResult = .failure(error)
        }
        return (clientResult, await serverTask.value)
    }
}

@Suite struct TLSTests {
    @Test func handshakeAndEcho() throws {
        let (client, server) = try exchange(server: serverContext(), client: clientContext())
        #expect(try client.get() == "hello over TLS")
        // The server's preference wins.
        #expect(try server.get() == "h2")
    }

    @Test func agreedParameters() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let server = try serverContext(), client = try clientContext()
        let (version, name, alpn, cert) = try rt.block { () async throws -> (TLSConfiguration.Version?, String?, String?, Bool) in
            let pair = duplex(capacity: 64 * 1024)
            let s = rt.spawn(with: pair.second) { t async -> String? in
                guard let tls = try? await TLSStream.accept(t, context: server) else { return nil }
                return tls.serverName
            }
            let tls = try await TLSStream.connect(pair.first, serverName: "vega.test", context: client)
            return (tls.version, await s.value, tls.applicationProtocol, tls.peerCertificate != nil)
        }
        #expect(version == .v1_3)
        #expect(name == "vega.test")
        #expect(alpn == "h2")
        #expect(cert)
    }

    @Test func untrustedCertificateIsRefused() throws {
        // The system's roots don't include a fresh self-signed certificate.
        let (client, _) = try exchange(server: serverContext(), client: clientContext { $0.trustRoots = .system })
        guard case .failure(let e) = client else { Issue.record("connected"); return }
        #expect(e == .tls)
        #expect(e.message?.contains("certificate verify failed") == true, "\(e)")
    }

    @Test func wrongNameIsRefused() throws {
        let (client, _) = try exchange(server: serverContext(), client: clientContext(), name: "other.test")
        guard case .failure(let e) = client else { Issue.record("connected"); return }
        #expect(e.message?.contains("certificate verify failed") == true, "\(e)")
    }

    @Test func anIPAddressIsCheckedAsOne() throws {
        let (client, _) = try exchange(server: serverContext(), client: clientContext(), name: "127.0.0.1")
        #expect(try client.get() == "hello over TLS")
        let (wrong, _) = try exchange(server: serverContext(), client: clientContext(), name: "127.0.0.2")
        #expect(throws: IOError.tls) { try wrong.get() }
    }

    @Test func verificationCanBeTurnedOff() throws {
        let (client, _) = try exchange(server: serverContext(),
                                       client: clientContext { $0.trustRoots = .system; $0.verification = .none },
                                       name: "anything")
        #expect(try client.get() == "hello over TLS")
    }

    @Test func noCommonProtocolIsRefused() throws {
        let (client, server) = try exchange(server: serverContext(),
                                            client: clientContext { $0.applicationProtocols = ["spdy/3"] })
        #expect(throws: IOError.tls) { try client.get() }
        #expect(throws: IOError.tls) { try server.get() }
    }

    @Test func mutualTLS() throws {
        let clientIdentity = try TLSIdentity.selfSigned(names: ["client.vega.test"])
        let server = try serverContext {
            $0.verification = .required
            $0.trustRoots = .certificates(clientIdentity.certificateChain)
        }
        let (anonymous, refused) = try exchange(server: server, client: clientContext())
        #expect(throws: IOError.self) { try anonymous.get() }
        #expect(throws: IOError.tls) { try refused.get() }
        let (known, accepted) = try exchange(server: server, client: clientContext { $0.identity = clientIdentity })
        #expect(try known.get() == "hello over TLS")
        #expect(try accepted.get() == "h2")
    }

    @Test func serverNameSelectsTheCertificate() throws {
        let other = try TLSIdentity.selfSigned(names: ["*.other.test"])
        let server = try serverContext { $0.serverNames = ["*.other.test": other] }
        let toOther = try clientContext { $0.trustRoots = .certificates(other.certificateChain) }
        let (matched, _) = try exchange(server: server, client: toOther, name: "a.other.test")
        #expect(try matched.get() == "hello over TLS")
        // The default certificate for everything else.
        let (unmatched, _) = try exchange(server: server, client: toOther, name: "vega.test")
        #expect(throws: IOError.tls) { try unmatched.get() }
    }

    @Test func tls12Works() throws {
        let (client, _) = try exchange(server: serverContext { $0.maximumVersion = .v1_2 }, client: clientContext())
        #expect(try client.get() == "hello over TLS")
    }

    @Test func aCipherListLimitsTLS12() throws {
        let server = try serverContext {
            $0.maximumVersion = .v1_2
            $0.cipherList = "ECDHE+AESGCM"
        }
        let (client, _) = try exchange(server: server, client: clientContext())
        #expect(try client.get() == "hello over TLS")
        // A client offering only suites outside the list finds nothing in common.
        let (refused, _) = try exchange(server: server, client: clientContext { $0.cipherList = "ECDHE+CHACHA20" })
        #expect(throws: IOError.tls) { try refused.get() }
        #expect(throws: IOError.tls) { _ = try serverContext { $0.cipherList = "NO-SUCH-CIPHER" } }
    }

    @Test func sessionsAreResumed() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let server = try serverContext(), client = try clientContext()
        let resumed = try rt.block { () async throws -> [Bool] in
            var resumed: [Bool] = []
            for _ in 0..<3 {
                let pair = duplex(capacity: 64 * 1024)
                rt.spawn(with: pair.second) { t async in
                    guard let tls = try? await TLSStream.accept(t, context: server) else { return }
                    var buf = IOBuffer(capacity: 64)
                    _ = try? await tls.read(into: &buf)
                    try? await tls.write(buf)
                    _ = try? await tls.close()
                }
                let tls = try await TLSStream.connect(pair.first, serverName: "vega.test", context: client)
                try await tls.write(bytes("x"))
                var buf = IOBuffer(capacity: 64)
                while try await tls.read(into: &buf) > 0 {} // takes the session tickets in too
                resumed.append(tls.isResumed)
            }
            return resumed
        }
        #expect(resumed == [false, true, true])
    }

    @Test func theClientHelloHookChoosesTheContext() throws {
        let challenge = try TLSIdentity.selfSigned(names: ["vega.test"])
        let acme = try TLSContext(.server(identity: challenge, applicationProtocols: ["acme-tls/1"]))
        let seen = Mutex<[ClientHello]>([])
        let server = try serverContext { c in
            c.selectContext = { hello in
                seen.withLock { $0.append(hello) }
                return hello.applicationProtocols.contains("acme-tls/1") ? acme : nil
            }
        }
        // An ordinary client gets the ordinary certificate and protocols.
        let (plain, plainServer) = try exchange(server: server, client: clientContext())
        #expect(try plain.get() == "hello over TLS")
        #expect(try plainServer.get() == "h2")
        // One offering acme-tls/1 gets the challenge context: its
        // certificate, which the ordinary trust root does not cover, and its
        // protocol.
        let prober = try clientContext {
            $0.trustRoots = .certificates(challenge.certificateChain)
            $0.applicationProtocols = ["acme-tls/1"]
        }
        let (probe, probeServer) = try exchange(server: server, client: prober)
        #expect(try probe.get() == "hello over TLS")
        #expect(try probeServer.get() == "acme-tls/1")
        let hellos = seen.withLock { $0 }
        #expect(hellos.count == 2)
        #expect(hellos.first == ClientHello(serverName: "vega.test", applicationProtocols: ["http/1.1", "h2"]))
        #expect(hellos.last?.applicationProtocols == ["acme-tls/1"])
    }

    @Test func serversSharingATicketKeyResumeEachOthersSessions() throws {
        let key = (0..<80).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 11) }
        let a = try serverContext { $0.ticketKey = key }
        let b = try serverContext { $0.ticketKey = key }
        let stranger = try serverContext()
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let client = try clientContext()
        let resumed = try rt.block { () async throws -> [Bool] in
            var resumed: [Bool] = []
            for server in [a, b, stranger] {
                let pair = duplex(capacity: 64 * 1024)
                rt.spawn(with: pair.second) { t async in
                    guard let tls = try? await TLSStream.accept(t, context: server) else { return }
                    var buf = IOBuffer(capacity: 64)
                    _ = try? await tls.read(into: &buf)
                    try? await tls.write(buf)
                    _ = try? await tls.close()
                }
                let tls = try await TLSStream.connect(pair.first, serverName: "vega.test", context: client)
                try await tls.write(bytes("x"))
                var buf = IOBuffer(capacity: 64)
                while try await tls.read(into: &buf) > 0 {}
                resumed.append(tls.isResumed)
            }
            return resumed
        }
        // b resumes a's session; a server with its own key cannot.
        #expect(resumed == [false, true, false])
        #expect(throws: IOError.self) { _ = try serverContext { $0.ticketKey = [1, 2, 3] } }
    }

    /// A peer that just stops (no close_notify) can't pass for a clean end.
    @Test func truncationIsAnError() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let server = try serverContext(), client = try clientContext()
        let error = try rt.block { () async throws -> IOError? in
            let pair = duplex(capacity: 64 * 1024)
            rt.spawn(with: pair.second) { t async in
                guard let tls = try? await TLSStream.accept(t, context: server) else { return }
                try? await tls.write(bytes("partial"))
                // Dropped: the transport closes with no close_notify.
            }
            let tls = try await TLSStream.connect(pair.first, serverName: "vega.test", context: client)
            var buf = IOBuffer(capacity: 64)
            do throws(IOError) {
                while try await tls.read(into: &buf) > 0 {}
                return nil
            } catch {
                return error
            }
        }
        #expect(error == .tlsTruncated)
    }

    /// Megabytes each way over TCP, read and written at once by both ends.
    @Test func bulkOverTCP() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let server = try serverContext(), client = try clientContext()
        let total = 3 << 20
        let received = try rt.block { () async throws -> Int in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            rt.spawn(with: listener) { l async in
                guard let conn = try? await l.accept(),
                      let tls = try? await TLSStream.accept(conn, context: server) else { return }
                // Echo in 64 KB steps.
                var buf = IOBuffer(capacity: 64 * 1024)
                while true {
                    buf.clear()
                    guard let n = try? await tls.read(into: &buf), n > 0 else { break }
                    guard (try? await tls.write(buf)) != nil else { break }
                }
                _ = try? await tls.close()
            }
            let tcp = try await TCPStream.connect(host: "127.0.0.1", port: port)
            let tls = try await TLSStream.connect(tcp, serverName: "127.0.0.1", context: client)
            // Alternate writes and reads so neither side's buffers fill.
            var chunk = IOBuffer(capacity: 256 * 1024)
            chunk.withUnsafeSpareCapacity { room in
                for i in 0..<room.count { room[i] = UInt8(truncatingIfNeeded: i % 251) }
                return room.count
            }
            var got = 0, sent = 0
            var buf = IOBuffer(capacity: 256 * 1024)
            while sent < total {
                try await tls.write(chunk)
                sent += chunk.count
                while got < sent {
                    buf.clear()
                    let n = try await tls.read(into: &buf)
                    if n == 0 { return got }
                    got += n
                }
            }
            return got
        }
        #expect(received == total)
    }

    @Test func badConfigurations() throws {
        #expect(throws: IOError.tls) { _ = try TLSContext(.init(role: .server)) }
        #expect(throws: IOError.tls) {
            _ = try TLSContext(.server(identity: .init(certificateChain: "not PEM", privateKey: serverIdentity.privateKey)))
        }
        let mismatched = try TLSIdentity.selfSigned(names: ["x"])
        #expect(throws: IOError.tls) {
            _ = try TLSContext(.server(identity: .init(certificateChain: serverIdentity.certificateChain,
                                                       privateKey: mismatched.privateKey)))
        }
        #expect(throws: IOError.tls) { _ = try TLSContext(.client(trustRoots: .certificates("nothing"))) }
    }
}
#endif
