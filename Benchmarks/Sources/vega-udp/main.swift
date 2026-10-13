// UDP echo server on Vega, for packets-per-second runs driven by
// tokio-bench's udp-load. One SO_REUSEPORT socket per worker (the kernel
// spreads flows across them), each served by one task that sends every
// datagram back to its sender.
//
//   vega-udp [--port 7100] [--workers N] [--mode single|batch|gso]
//
// Modes:
//   single  one receiveFrom and one send per datagram
//   batch   DatagramBatch: recvmmsg up to 64, then sendmmsg them back
//   gso     UDP GRO receive, UDP GSO send: one syscall per coalesced burst
import Glibc
import Vega

var port = 7100
var workers: Int?
var mode = "single"
var args = CommandLine.arguments.dropFirst()
while let a = args.popFirst() {
    switch a {
    case "--port": port = Int(args.popFirst()!)!
    case "--workers": workers = Int(args.popFirst()!)!
    case "--mode": mode = args.popFirst()!
    default: fatalError("unknown option \(a)")
    }
}
guard ["single", "batch", "gso"].contains(mode) else { fatalError("unknown mode \(mode)") }

let rt = Runtime(workers: workers)

func say(_ line: String, fd: Int32) {
    var s = line
    s.withUTF8 { _ = write(fd, $0.baseAddress, $0.count) }
}

let listenPort = port, echoMode = mode

@Sendable func serveSingle(_ socket: borrowing UDPSocket) async throws(IOError) {
    var buf = IOBuffer(capacity: 2048)
    while true {
        buf.clear()
        let (_, from) = try await socket.receiveFrom(into: &buf)
        _ = try await socket.send(buf, to: from)
    }
}

@Sendable func serveBatch(_ socket: borrowing UDPSocket) async throws(IOError) {
    // After a receive the batch holds each sender's address: sending it
    // returns every datagram where it came from.
    var batch = DatagramBatch(capacity: 64, slotSize: 2048)
    while true {
        _ = try await socket.receive(&batch)
        try await socket.send(batch)
    }
}

@Sendable func serveSegments(_ socket: borrowing UDPSocket) async throws(IOError) {
    try socket.setOption(.udpGRO, to: true)
    var buf = IOBuffer(capacity: 65_536)
    // The storage doesn't move while buf lives.
    let base = buf.withUnsafeBytes { UnsafeRawPointer($0.baseAddress!) }
    while true {
        buf.clear()
        let r = try await socket.receiveSegments(into: &buf)
        let segment = r.segmentSize == 0 ? r.count : r.segmentSize
        // GSO takes at most 64 segments per send.
        var at = 0
        while at < r.count {
            let n = min(r.count - at, 64 * segment)
            try await socket.send(segments: UnsafeRawBufferPointer(start: base + at, count: n),
                                  segmentSize: segment, to: r.from)
            at += n
        }
    }
}

try rt.block { () async throws(IOError) in
    for _ in 0..<rt.workerCount {
        let socket = try UDPSocket.bind(host: "127.0.0.1", port: listenPort, reusePort: true)
        rt.spawn(with: socket) { socket in
            do {
                switch echoMode {
                case "batch": try await serveBatch(socket)
                case "gso": try await serveSegments(socket)
                default: try await serveSingle(socket)
                }
            } catch {
                say("vega-udp: \(error)\n", fd: 2)
            }
        }
    }
    say("vega-udp: \(echoMode) on 127.0.0.1:\(listenPort), \(rt.workerCount) workers, \(rt.ioBackend)\n", fd: 1)
    while true { try? await Runtime.sleep(for: .seconds(3600)) }
}
