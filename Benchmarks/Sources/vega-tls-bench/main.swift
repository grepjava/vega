// VegaTLS's per-record cost, in one process: N connections over loopback
// TCP, each a client and a server task doing request/response rounds of
// small messages (an HTTP/1.1 keep-alive load's shape). Reports rounds per
// second and the process's CPU time per round, both ends' together.
//
//   vega-tls-bench [--connections 64] [--seconds 5] [--workers N] [--size 200] [--plain] [--deadline]
//
// --plain runs the same rounds over plain TCP: the difference in CPU per
// round is what TLS costs. --deadline runs each server round inside
// `Runtime.withIOTimeout`, as a server with a request timeout does.
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import Synchronization
import Vega
import VegaIO
import VegaTLS

var connections = 64
var seconds = 5
var workers: Int?
var size = 200
var plain = false
var deadline = false
var args = CommandLine.arguments.dropFirst()
while let a = args.popFirst() {
    switch a {
    case "--connections": connections = Int(args.popFirst()!)!
    case "--seconds": seconds = Int(args.popFirst()!)!
    case "--workers": workers = Int(args.popFirst()!)!
    case "--size": size = Int(args.popFirst()!)!
    case "--plain": plain = true
    case "--deadline": deadline = true
    default: fatalError("unknown option \(a)")
    }
}

let messageSize = size, isPlain = plain, withDeadline = deadline, connectionCount = connections, runSeconds = seconds
let rounds = Atomic<Int>(0)
let stopping = Atomic<Bool>(false)

/// Read exactly `count` bytes into `buf` (cleared first); false at the end.
func readMessage<S: AsyncReader & ~Copyable>(_ s: borrowing S, _ buf: inout IOBuffer, _ count: Int) async throws(IOError) -> Bool {
    buf.clear()
    while buf.count < count {
        if try await s.read(into: &buf) == 0 { return false }
    }
    return true
}

func message() -> IOBuffer {
    var b = IOBuffer(capacity: messageSize)
    b.withUnsafeSpareCapacity { room in
        for i in 0..<room.count { room[i] = UInt8(truncatingIfNeeded: 65 + i % 26) }
        return room.count
    }
    return b
}

/// The server's side: answer each request with a message of the same size.
func serve<S: AsyncReader & AsyncWriter & ~Copyable>(_ s: borrowing S) async throws(IOError) {
    var buf = IOBuffer(capacity: max(messageSize, 16 * 1024))
    let answer = message()
    if withDeadline {
        while try await Runtime.withIOTimeout(for: .seconds(30), { () async throws(IOError) -> Bool in
            guard try await readMessage(s, &buf, messageSize) else { return false }
            try await s.write(answer)
            return true
        }) {}
        return
    }
    while try await readMessage(s, &buf, messageSize) {
        try await s.write(answer)
    }
}

/// The client's side: rounds until told to stop.
func drive<S: AsyncReader & AsyncWriter & ~Copyable>(_ s: borrowing S) async throws(IOError) {
    var buf = IOBuffer(capacity: max(messageSize, 16 * 1024))
    let request = message()
    while !stopping.load(ordering: .relaxed) {
        try await s.write(request)
        guard try await readMessage(s, &buf, messageSize) else { return }
        rounds.add(1, ordering: .relaxed)
    }
}

/// Process CPU seconds: user and system together, and user alone.
func cpuSeconds() -> (all: Double, user: Double) {
    var u = rusage()
    #if os(Linux)
    getrusage(__rusage_who_t(RUSAGE_SELF.rawValue), &u)
    #else
    getrusage(RUSAGE_SELF, &u)
    #endif
    func secs(_ t: timeval) -> Double { Double(t.tv_sec) + Double(t.tv_usec) / 1e6 }
    return (secs(u.ru_utime) + secs(u.ru_stime), secs(u.ru_utime))
}

let identity = try! TLSIdentity.selfSigned(names: ["localhost", "127.0.0.1"])
let serverContext = try! TLSContext(.server(identity: identity))
let clientContext = try! TLSContext(.client(trustRoots: .certificates(identity.certificateChain)))

let rt = Runtime(workers: workers)
do {
    try rt.block { () async throws(IOError) -> Void in
        let listener = try TCPListener.bind(host: "127.0.0.1", port: 0, backlog: 4096)
        let port = listener.localPort
        rt.spawn(with: listener) { l async in
            while let conn = try? await l.accept() {
                rt.spawn(with: conn) { conn async in
                    if isPlain {
                        try? await serve(conn)
                    } else {
                        guard let tls = try? await TLSStream.accept(conn, context: serverContext) else { return }
                        try? await serve(tls)
                    }
                }
            }
        }
        var clients: [Task<Void, Never>] = []
        for _ in 0..<connectionCount {
            let tcp = try await TCPStream.connect(host: "127.0.0.1", port: port)
            clients.append(rt.spawn(with: tcp) { tcp async in
                if isPlain {
                    try? await drive(tcp)
                } else {
                    guard let tls = try? await TLSStream.connect(tcp, serverName: "127.0.0.1",
                                                                 context: clientContext) else { return }
                    try? await drive(tls)
                }
            })
        }
        // A second's warm-up, then the measured run.
        try? await Runtime.sleep(for: .seconds(1))
        let r0 = rounds.load(ordering: .relaxed), c0 = cpuSeconds(), t0 = ContinuousClock.now
        try? await Runtime.sleep(for: .seconds(runSeconds))
        let r1 = rounds.load(ordering: .relaxed), c1 = cpuSeconds(), elapsed = ContinuousClock.now - t0
        stopping.store(true, ordering: .relaxed)
        let wall = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
        let n = Double(r1 - r0)
        let perSecond = Int(n / wall), cpuPerRound = (c1.all - c0.all) / n * 1e6
        let userPerRound = (c1.user - c0.user) / n * 1e6
        print("\(isPlain ? "plain" : "tls")\(withDeadline ? "+deadline" : "") connections \(connectionCount) size \(messageSize) workers \(rt.workerCount): "
              + "\(perSecond) rounds/s, \((cpuPerRound * 100).rounded() / 100) us CPU/round "
              + "(\((userPerRound * 100).rounded() / 100) us user), "
              + "\(Int(((c1.all - c0.all) / wall * 100).rounded()))% CPU")
        for c in clients { await c.value }
    }
} catch {
    fatalError("vega-tls-bench: \(error)")
}
