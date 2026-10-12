// TCP echo server on Vega: the same shape as tokio-bench's echo-server. One
// task per connection, a 4 KiB buffer, echo until EOF.
//
//   vega-echo [--port 7000] [--workers N] [--global] [--stats]
//
// --stats prints, every 2 s to stderr, the jobs each worker ran and what the
// I/O driver did over the interval.
import Glibc
import Vega

var port = 7000
var workers: Int?
var global = false
var stats = false
var args = CommandLine.arguments.dropFirst()
while let a = args.popFirst() {
    switch a {
    case "--port": port = Int(args.popFirst()!)!
    case "--workers": workers = Int(args.popFirst()!)!
    case "--global": global = true
    case "--stats": stats = true
    default: fatalError("unknown option \(a)")
    }
}

let listenPort = port, isGlobal = global, printStats = stats
let rt = isGlobal ? Runtime.installGlobal(workers: workers) : Runtime(workers: workers)

@Sendable func serve(_ conn: consuming TCPStream) async {
    var buf = IOBuffer(capacity: 4096)
    while true {
        do throws(IOError) {
            if try await conn.read(into: &buf) == 0 { return }
            try await conn.write(buf)
            buf.clear()
        } catch {
            return
        }
    }
}

func printError(_ line: String) {
    var s = line
    s.withUTF8 { _ = write(2, $0.baseAddress, $0.count) }
}

func statsLoop() async {
    var io = rt.ioMetrics
    var m = rt.metrics
    while true {
        try? await Runtime.sleep(for: .seconds(2))
        let io2 = rt.ioMetrics, m2 = rt.metrics
        let parked = io2.parkedPolls - io.parkedPolls, busy = io2.busyPolls - io.busyPolls
        let events = io2.events - io.events
        let jobs = zip(m2, m).map { $0.jobs - $1.jobs }
        let steals = zip(m2, m).map { $0.steals - $1.steals }
        printError("jobs \(jobs) steals \(steals) | polls parked \(parked) busy \(busy) "
              + "events \(events) (\(parked + busy > 0 ? events / (parked + busy) : 0)/poll) "
              + "wakes \(io2.wakes - io.wakes) full \(io2.fullBatches - io.fullBatches)\n")
        io = io2
        m = m2
    }
}

do {
    try rt.block { () async throws(IOError) -> Void in
        let listener = try TCPListener.bind(port: listenPort, backlog: 4096)
        print("vega echo: port \(listenPort), \(rt.workerCount) workers\(isGlobal ? ", global" : "")")
        if printStats { rt.spawn { await statsLoop() } }
        while true {
            let conn = try await listener.accept()
            rt.spawn(with: conn) { conn in await serve(conn) }
        }
    }
} catch {
    fatalError("vega-echo: \(error)")
}
