#if VEGA_JOB_AUDIT
import CVega
import Synchronization

/// Debug aid (build with -Xswiftc -DVEGA_JOB_AUDIT): every job handed to the
/// scheduler must run exactly once per enqueue. Keeps a short event history
/// per job and prints it when the rule breaks.
enum JobAudit {
    struct Entry { var queued = false; var history: [String] = [] }
    static let jobs = Mutex<[UInt: Entry]>([:])

    static func id(_ job: UnownedJob) -> UInt { UInt(bitPattern: unsafeBitCast(job, to: Int.self)) }

    static func thread() -> String {
        guard let w = Worker.current else { return "foreign" }
        return "w\(w._withUnsafeGuaranteedRef { $0.index })"
    }

    static func note(_ job: UnownedJob, _ what: String) {
        let t = thread()
        jobs.withLock { j in
            j[id(job), default: Entry()].history.append("\(t):\(what)")
            if j[id(job)]!.history.count > 16 { j[id(job)]!.history.removeFirst() }
        }
    }

    static func enqueued(_ job: UnownedJob, _ site: StaticString) {
        let t = thread()
        let (fresh, h) = jobs.withLock { j -> (Bool, [String]) in
            var e = j[id(job), default: Entry()]
            e.history.append("\(t):enqueue")
            let fresh = !e.queued
            e.queued = true
            j[id(job)] = e
            return (fresh, e.history)
        }
        if !fresh { fatalError("vega audit: job \(String(id(job), radix: 16)) enqueued twice: \(h)") }
    }

    static func running(_ job: UnownedJob, _ source: StaticString) {
        let t = thread()
        let (was, h) = jobs.withLock { j -> (Bool, [String]) in
            var e = j[id(job), default: Entry()]
            e.history.append("\(t):run(\(source))")
            let was = e.queued
            e.queued = false
            j[id(job)] = e
            return (was, e.history)
        }
        if !was { fatalError("vega audit: job \(String(id(job), radix: 16)) run but not queued: \(h)") }
    }
}
#endif
