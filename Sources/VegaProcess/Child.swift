import CVega
import Vega
import VegaIO
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// A running (or finished, not yet waited for) child process: Tokio's
/// `tokio::process::Child`.
///
/// Take the pipes out to use them from other tasks (`child.stdout.take()`).
/// Waiting closes stdin first, so a child that reads its input to the end
/// can finish.
///
/// On Linux the exit is watched through a pidfd on the runtime's driver,
/// with no thread and no SIGCHLD handler. Elsewhere `wait` polls, backing
/// off to 50 ms.
///
/// A child dropped before it was waited for is reaped in the background
/// (and first killed, with `Command.killOnDrop`): it never stays a zombie.
public struct Child: ~Copyable, Sendable {
    public let pid: Int32
    /// The child's stdin, with `Stdio.pipe`.
    public var stdin: PipeWriter?
    /// The child's stdout, with `Stdio.pipe`.
    public var stdout: PipeReader?
    /// The child's stderr, with `Stdio.pipe`.
    public var stderr: PipeReader?
    /// The pidfd, where there is one, and its number (-1: none).
    private var exit: ReadinessWatch?
    private var pidfd: Int32 = -1
    private var status: ExitStatus?
    private let killOnDrop: Bool

    init(pid: Int32, killOnDrop: Bool) {
        self.pid = pid
        self.killOnDrop = killOnDrop
    }

    deinit {
        if status == nil {
            if killOnDrop { _ = Child.signal(pid, pidfd, SIGKILL) }
            Orphans.add(pid)
        }
    }

    mutating func watchExit() throws(IOError) {
        let fd = cv_pidfd_open(pid)
        guard fd >= 0 else { return } // no pidfds: poll
        exit = try ReadinessWatch(adopting: fd)
        pidfd = fd
    }

    /// Wait for the child to end (closing stdin first). Cancelling the task
    /// leaves the child running; wait again later, or kill it.
    public mutating func wait() async throws(IOError) -> ExitStatus {
        if let status { return status }
        stdin = nil
        var backoff = Duration.milliseconds(1)
        while true {
            if let status = try tryWait() { return status }
            switch exit {
            case .some(let watch):
                try await watch.readable()
            case .none:
                do {
                    try await Runtime.sleep(for: backoff)
                } catch {
                    throw .cancelled
                }
                backoff = min(backoff * 2, .milliseconds(50))
            }
        }
    }

    /// The status if the child has ended, else nil, without waiting.
    public mutating func tryWait() throws(IOError) -> ExitStatus? {
        if let status { return status }
        var raw: Int32 = 0
        let r = cv_waitpid(pid, 1, &raw)
        if r < 0 { throw IOError(code: -r) }
        guard r == 1 else { return nil }
        let status = ExitStatus(rawValue: raw)
        self.status = status
        return status
    }

    /// Send `signal` (SIGKILL by default). Does nothing once the child has
    /// been waited for: its pid may belong to another process by then.
    public func kill(signal: Int32 = SIGKILL) throws(IOError) {
        guard status == nil else { return }
        let e = Child.signal(pid, pidfd, signal)
        if e != 0 { throw IOError(code: e) }
    }

    /// Through the pidfd where there is one: it can't reach a recycled pid.
    private static func signal(_ pid: Int32, _ pidfd: Int32, _ sig: Int32) -> Int32 {
        if pidfd >= 0 {
            let e = cv_pidfd_signal(pidfd, sig)
            if e != ENOSYS { return e }
        }
        return Glibc_kill(pid, sig) == 0 ? 0 : errno
    }

    /// Collect stdout and stderr (whichever are pipes) to their ends, at
    /// once so neither fills up and stalls the child, then wait.
    public consuming func output() async throws(IOError) -> Output {
        stdin = nil
        let out = Transfer(stdout.take()), err = Transfer(stderr.take())
        async let outBytes = readAll(out)
        async let errBytes = readAll(err)
        let (o, e) = await (outBytes, errBytes)
        let status = try await wait()
        return Output(status: status, stdout: try o.get(), stderr: try e.get())
    }
}

private func Glibc_kill(_ pid: Int32, _ sig: Int32) -> Int32 { kill(pid, sig) }

/// Moves a non-copyable value into a child task.
private final class Transfer<Value: ~Copyable>: @unchecked Sendable {
    private var value: Value?

    init(_ value: consuming Value?) { self.value = value }

    func take() -> Value? { value.take() }
}

private func readAll(_ transfer: Transfer<PipeReader>) async -> Result<[UInt8], IOError> {
    guard let reader = transfer.take() else { return .success([]) }
    var bytes: [UInt8] = []
    var buffer = IOBuffer(capacity: 16 * 1024)
    while true {
        buffer.clear()
        let n: Int
        do throws(IOError) {
            n = try await reader.read(into: &buffer)
        } catch {
            return .failure(error)
        }
        if n == 0 { return .success(bytes) }
        buffer.withUnsafeBytes { bytes.append(contentsOf: $0) }
    }
}

/// Children dropped before they were waited for, reaped whenever a child
/// is spawned (as Tokio's orphan queue is).
enum Orphans {
    nonisolated(unsafe) private static let lock = cv_lock_new()!
    nonisolated(unsafe) private static var pids: [Int32] = []

    static func add(_ pid: Int32) {
        // Often it has ended already.
        var raw: Int32 = 0
        if cv_waitpid(pid, 1, &raw) != 0 { return }
        cv_lock_lock(lock)
        pids.append(pid)
        cv_lock_unlock(lock)
    }

    static func reap() {
        cv_lock_lock(lock)
        defer { cv_lock_unlock(lock) }
        guard !pids.isEmpty else { return }
        pids.removeAll { pid in
            var raw: Int32 = 0
            return cv_waitpid(pid, 1, &raw) != 0 // reaped, or not ours any more
        }
    }

    /// For tests.
    static var count: Int {
        cv_lock_lock(lock)
        defer { cv_lock_unlock(lock) }
        return pids.count
    }
}
