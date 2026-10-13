import CVega

/// Threads for work that blocks: file I/O, `getaddrinfo`, CPU-heavy or
/// foreign code. Tokio's `spawn_blocking` pool.
///
/// A worker thread that blocks stalls every task queued behind it, so this
/// work runs here instead. Threads start on demand, up to `maxThreads`, and
/// one that sits idle for `keepAlive` exits. Jobs beyond `maxThreads` queue
/// in FIFO order.
final class BlockingPool: @unchecked Sendable {
    typealias Job = @Sendable () -> Void

    private struct State {
        var jobs: [Job?] = []
        var head = 0
        /// Parkers of idle threads; a submit pops one and wakes it.
        var idle: [OpaquePointer] = []
        var threads = 0
        var isShutdown = false

        var hasJob: Bool { head < jobs.count }

        mutating func takeJob() -> Job {
            let job = jobs[head].take()!
            head += 1
            if head == jobs.count {
                jobs.removeAll(keepingCapacity: true)
                head = 0
            }
            return job
        }
    }

    private let lock = RawLock()
    private let state = Guarded(State())
    let maxThreads: Int
    private let keepAlive: Int64
    private let name: String

    init(maxThreads: Int, keepAlive: Duration, name: String) {
        precondition(maxThreads >= 1, "the blocking pool needs at least one thread")
        self.maxThreads = maxThreads
        self.keepAlive = max(1, Scheduler.nanoseconds(keepAlive))
        self.name = name
    }

    deinit {
        state.destroy()
        lock.destroy()
    }

    /// Threads alive now, busy or idle.
    var threadCount: Int { lock.withLock { state.pointer.pointee.threads } }

    /// Threads alive, those idle, and jobs waiting for a thread.
    var counts: (threads: Int, idle: Int, queued: Int) {
        lock.withLock {
            let s = state.pointer.pointee
            return (s.threads, s.idle.count, s.jobs.count - s.head)
        }
    }

    /// Run `job` on a pool thread.
    func submit(_ job: @escaping Job) {
        lock.lock()
        let s = state.pointer
        s.pointee.jobs.append(job)
        if let parker = s.pointee.idle.popLast() {
            lock.unlock()
            cv_unpark(parker)
            return
        }
        guard s.pointee.threads < maxThreads else {
            lock.unlock() // a busy thread takes it when done
            return
        }
        s.pointee.threads += 1
        let index = s.pointee.threads
        lock.unlock()
        let rc = cv_thread_spawn({ raw in
            Unmanaged<BlockingPool>.fromOpaque(raw!).takeRetainedValue().runThread()
        }, Unmanaged.passRetained(self).toOpaque(), "\(name)-blocking-\(index)", -1)
        precondition(rc == 0, "vega: cannot start blocking thread (errno \(rc))")
    }

    /// Let idle threads exit. Jobs still queued, or submitted later, run;
    /// each thread exits once it finds no work.
    func shutdown() {
        let parkers = lock.withLock {
            state.pointer.pointee.isShutdown = true
            return state.pointer.pointee.idle
        }
        for p in parkers { cv_unpark(p) }
    }

    private func runThread() {
        let parker = cv_parker_new()!
        let s = state.pointer
        lock.lock()
        while true {
            if s.pointee.hasJob {
                let job = s.pointee.takeJob()
                lock.unlock()
                job()
                lock.lock()
                continue
            }
            if s.pointee.isShutdown { break }
            // Idle: wait for a submit to claim this thread, or time out.
            s.pointee.idle.append(parker)
            let deadline = cv_now_ns() &+ UInt64(keepAlive)
            var claimed = false
            while true {
                lock.unlock()
                let now = cv_now_ns()
                if now < deadline { cv_park(parker, Int64(deadline - now)) }
                lock.lock()
                guard let i = s.pointee.idle.firstIndex(of: parker) else {
                    claimed = true // a submit popped us: there is a job
                    break
                }
                if s.pointee.isShutdown || s.pointee.hasJob || cv_now_ns() >= deadline {
                    s.pointee.idle.remove(at: i)
                    break
                }
                // Spurious wake (a stale unpark token): wait out the rest.
            }
            if !claimed && !s.pointee.hasJob { break }
        }
        s.pointee.threads -= 1
        lock.unlock()
        cv_parker_free(parker)
    }

    /// For calls off any runtime.
    static let shared = BlockingPool(maxThreads: 512, keepAlive: .seconds(10), name: "vega")
}

extension Runtime {
    /// Run `body` on the runtime's blocking pool and wait for its result,
    /// without holding up a worker thread: Tokio's `spawn_blocking`. Use it
    /// for anything that blocks (file I/O, `getaddrinfo`, long CPU work,
    /// libraries that wait on locks).
    ///
    /// `body` always runs to completion: cancelling the caller does not stop
    /// it, and the caller still waits for it. Off a Vega runtime it uses a
    /// process-wide pool.
    public static func blocking<T: Sendable, E: Error>(
        _ body: sending @escaping () throws(E) -> T
    ) async throws(E) -> T {
        let scheduler = Worker.currentScheduler
        let pool = scheduler?.blocking ?? BlockingPool.shared
        nonisolated(unsafe) let body = body
        scheduler?.blockingInFlight.add(1, ordering: .sequentiallyConsistent)
        let result = await withUnsafeContinuation { (c: UnsafeContinuation<Result<T, E>, Never>) in
            pool.submit {
                let r: Result<T, E>
                do throws(E) {
                    r = .success(try body())
                } catch {
                    r = .failure(error)
                }
                c.resume(returning: r)
                // Only once the resume has made the caller runnable: paused
                // time must see one or the other, or it could jump ahead.
                if let scheduler,
                   scheduler.blockingInFlight.subtract(1, ordering: .sequentiallyConsistent).oldValue == 1,
                   scheduler.clock.isPaused {
                    // The workers may all have parked while this job was
                    // out, the timer owner seeing it and declining to
                    // advance: have it look again.
                    scheduler.clockAdvanced()
                }
            }
        }
        // A quick job can resume us before we suspend; see cv_tsan_acquire.
        cv_tsan_acquire(cv_task_current())
        return try result.get()
    }
}
