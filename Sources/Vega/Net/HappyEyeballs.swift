#if os(Linux) || canImport(Darwin) || os(Windows)
import CVega
import Synchronization
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

// Happy Eyeballs v2 (RFC 8305): connection attempts to a host's addresses
// race, staggered, so a dead address family or a black-holed address costs
// a short delay instead of a full connect timeout.

extension TCPStream {
    /// Connect to `host` and `port`. A name is looked up on the blocking pool
    /// (see `SocketAddress.lookup`), and its addresses are raced with Happy
    /// Eyeballs v2 (see `connect(to:attemptDelay:)`). Call from a task on a
    /// Vega runtime.
    public static func connect(host: String, port: Int,
                               attemptDelay: Duration = .milliseconds(250)) async throws(IOError) -> TCPStream {
        #if canImport(Network)
        // Network.framework resolves and races the addresses itself, and
        // knows the device's interfaces, VPN and proxies.
        if NetworkIO.active { return TCPStream(reg: try await NetworkIO.connect(host: host, port: port)) }
        #endif
        _ = try IODriver.current()
        return try await connect(to: try await SocketAddress.lookup(host: host, port: port),
                                 attemptDelay: attemptDelay)
    }

    /// Connect to `host` and `port`, looking a name up with `resolver`
    /// (`Resolver.system` asks the system's nameservers without blocking a
    /// thread), then racing its addresses as `connect(host:port:)` does.
    public static func connect(host: String, port: Int, resolver: Resolver,
                               attemptDelay: Duration = .milliseconds(250)) async throws(IOError) -> TCPStream {
        _ = try IODriver.current()
        let addresses: [SocketAddress]
        do {
            addresses = try await resolver.lookup(host: host, port: port)
        } catch {
            throw error.ioError
        }
        return try await connect(to: addresses, attemptDelay: attemptDelay)
    }

    /// Connect to the first of `addresses` that answers, Happy Eyeballs v2
    /// style (RFC 8305): IPv6 and IPv4 addresses are interleaved, IPv6
    /// first, and tried one after another. The next attempt starts when the
    /// previous one fails, or after `attemptDelay` (clamped to 100 ms–2 s),
    /// whichever comes first, while earlier attempts keep going. The first
    /// connection wins and the others are cancelled and closed. If all
    /// fail, the last failure is thrown. Call from a task on a Vega runtime.
    public static func connect(to addresses: [SocketAddress],
                               attemptDelay: Duration = .milliseconds(250)) async throws(IOError) -> TCPStream {
        _ = try IODriver.current()
        guard let scheduler = Worker.currentScheduler else { throw .notOnRuntime }
        let ordered = HappyEyeballs.interleave(addresses)
        guard !ordered.isEmpty else { throw IOError(code: EADDRNOTAVAIL) }
        if ordered.count == 1 { return try await connect(to: ordered[0]) }
        let delay = min(max(attemptDelay, .milliseconds(100)), .seconds(2))

        let race = HappyEyeballs.Race()
        let failure: IOError? = await withTaskGroup(of: HappyEyeballs.Outcome.self) { group in
            var next = 0, running = 0, generation = 0
            var last = IOError(code: EADDRNOTAVAIL)
            // Start the next attempt, and the delay after which the one
            // after it starts if this one is still pending.
            func startNext() {
                let address = ordered[next]
                next += 1
                running += 1
                group.addTask(executorPreference: scheduler) {
                    do throws(IOError) {
                        let stream = try await TCPStream.connect(to: address)
                        return race.offer(stream) ? .connected : .lost
                    } catch {
                        return .failed(error)
                    }
                }
                guard next < ordered.count else { return }
                generation += 1
                let mine = generation
                group.addTask(executorPreference: scheduler) {
                    do {
                        try await Runtime.sleep(for: delay)
                        return .delayElapsed(generation: mine)
                    } catch {
                        return .stale
                    }
                }
            }
            startNext()
            while let outcome = await group.next() {
                switch outcome {
                case .connected:
                    group.cancelAll() // the rest give up; the group waits for them
                    return nil
                case .lost, .stale:
                    continue
                case .failed(let error):
                    running -= 1
                    if error == .cancelled { last = error } // the caller was cancelled
                    else if last != .cancelled { last = error }
                    if Task.isCancelled { group.cancelAll(); return .cancelled }
                    if next < ordered.count { startNext() }
                    else if running == 0 { group.cancelAll(); return last }
                case .delayElapsed(let g):
                    // Only the delay of the newest attempt counts: one that
                    // failed early already started its successor.
                    if g == generation && next < ordered.count { startNext() }
                }
            }
            return Task.isCancelled ? .cancelled : last
        }
        if let failure { throw failure }
        return race.take()
    }
}

enum HappyEyeballs {
    /// RFC 8305 §4: alternate the families, IPv6 first, each keeping the
    /// resolver's order.
    static func interleave(_ addresses: [SocketAddress]) -> [SocketAddress] {
        let v6 = addresses.filter { $0.isIPv6 }, v4 = addresses.filter { !$0.isIPv6 }
        var out: [SocketAddress] = []
        out.reserveCapacity(addresses.count)
        for i in 0..<max(v6.count, v4.count) {
            if i < v6.count { out.append(v6[i]) }
            if i < v4.count { out.append(v4[i]) }
        }
        return out
    }

    enum Outcome: Sendable {
        case connected, lost, stale
        case failed(IOError)
        case delayElapsed(generation: Int)
    }

    /// Holds the winning stream. Only the attempt that claims it writes
    /// `winner`, and the caller reads it once every attempt has finished.
    final class Race: @unchecked Sendable {
        private let claimed = Atomic<Bool>(false)
        private var winner: TCPStream?

        /// Keep `stream` if it is the first; otherwise it is dropped (closed).
        func offer(_ stream: consuming TCPStream) -> Bool {
            guard claimed.compareExchange(expected: false, desired: true, ordering: .acquiringAndReleasing).exchanged
            else { return false }
            winner = consume stream
            return true
        }

        func take() -> TCPStream { winner.take()! }
    }
}
#endif
