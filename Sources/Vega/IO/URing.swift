import CVega
import Synchronization
#if canImport(Glibc)
import Glibc
#endif

/// Which I/O driver a runtime uses.
public enum IOBackend: Sendable, Equatable {
    /// `.ioUring` if `VEGA_DRIVER=uring`, else `.readiness`.
    case automatic
    /// One edge-triggered epoll (kqueue on Darwin) per runtime.
    case readiness
    /// Completion (Linux 6.7+): one io_uring per worker. Falls back to
    /// `.readiness` where the kernel can't run it (older, or io_uring
    /// blocked by seccomp or `kernel.io_uring_disabled`); `Runtime.ioBackend`
    /// says which runs.
    case ioUring
}

/// One operation for a worker's ring. Pointers stay valid until the
/// operation completes: the task waits for that, even when cancelled.
enum URingRequest: @unchecked Sendable {
    case recv(Int32, UnsafeMutableRawPointer, Int)
    case accept(Int32)
    /// One-shot readiness (`CV_IO_READ` / `CV_IO_WRITE`), for operations
    /// with no completion form here: writes that found the socket full,
    /// connect, datagram batches.
    case poll(Int32, Int32)
}

#if os(Linux)
/// The io_uring driver, task side. A task submits on the ring of the worker
/// running it and suspends; that worker reaps the completion (when it next
/// polls, runs out of work, or parks) and resumes the task.
enum URing {
    /// `run`'s answer when the task turned out not to be on a ring's worker.
    static let noRing = Int64.min

    /// Whether this kernel can run the driver (probed once).
    static let supported: Bool = cv_uring_probe() == 0

    /// Whether `backend` (with `VEGA_DRIVER` for `.automatic`) asks for rings.
    static func wanted(_ backend: IOBackend) -> Bool {
        switch backend {
        case .readiness: return false
        case .ioUring: return true
        case .automatic:
            guard let v = getenv("VEGA_DRIVER") else { return false }
            return String(cString: v) == "uring"
        }
    }

    /// The ring of the worker running the caller, if it has one.
    @inline(__always) static var current: OpaquePointer? {
        Worker.current?._withUnsafeGuaranteedRef { $0.ring }
    }

    @inline(__always)
    private static func submit(_ request: URingRequest, _ ring: OpaquePointer, _ waiter: UInt,
                               _ gen: UnsafeMutablePointer<UInt64>) -> OpaquePointer {
        switch request {
        case let .recv(fd, buf, len): return cv_uring_recv(ring, waiter, fd, buf, len, gen)
        case let .accept(fd): return cv_uring_accept(ring, waiter, fd, gen)
        case let .poll(fd, dir): return cv_uring_poll_ready(ring, waiter, fd, dir, gen)
        }
    }

    /// Run `request` on the current worker's ring: the result (>= 0) or
    /// -errno (-ECANCELED if the task was cancelled first), or `noRing`.
    @inline(__always)
    static func run(_ request: URingRequest) async -> Int64 {
        // The slot, once submitted (1: cancelled before that), and its
        // generation, for a canceller on another thread. They live in this
        // frame, which outlives the handler: removing it waits for a run.
        let handle = Atomic<UInt>(0)
        let ticket = Atomic<UInt64>(0)
        return await withTaskCancellationHandler {
            await withUnsafeContinuation { (c: UnsafeContinuation<Int64, Never>) in
                // Looked up here, on the thread that submits: the ring takes
                // submissions from its own worker only.
                guard let ring = current else {
                    c.resume(returning: noRing)
                    return
                }
                var gen: UInt64 = 0
                let op = submit(request, ring, unsafeBitCast(c, to: UInt.self), &gen)
                ticket.store(gen, ordering: .relaxed)
                if !handle.compareExchange(expected: 0, desired: UInt(bitPattern: op),
                                           ordering: .releasing).exchanged {
                    cv_uring_cancel(op, gen) // cancelled before we got here
                }
            }
        } onCancel: {
            let (first, op) = handle.compareExchange(expected: 0, desired: 1, ordering: .acquiring)
            if !first { cv_uring_cancel(OpaquePointer(bitPattern: op), ticket.load(ordering: .relaxed)) }
        }
    }

    /// Run `request` on a ring: this worker's, or, for a task elsewhere, one
    /// of `owner`'s workers (the uring runtime the socket belongs to). nil
    /// when neither applies: the caller uses the readiness driver.
    @inline(__always)
    static func perform(_ request: URingRequest, owner: UnsafeRawPointer?) async -> Int64? {
        if current != nil {
            let res = await run(request)
            if res != noRing { return res }
        }
        guard let owner else { return nil }
        return await hop(request, to: Unmanaged<Scheduler>.fromOpaque(owner).takeUnretainedValue())
    }

    /// Off the runtime's workers: run the operation in a task on them.
    @inline(never)
    private static func hop(_ request: URingRequest, to s: Scheduler) async -> Int64 {
        let task = Task(executorPreference: s) { () async -> Int64 in
            while true {
                let res = await run(request)
                if res != noRing { return res }
                await Task.yield()
            }
        }
        return await withTaskCancellationHandler { await task.value } onCancel: { task.cancel() }
    }

    /// Resume the `n` waiters a ring turn collected on `worker`, placed as
    /// the epoll driver places its wakes (see `IODriver.resume`).
    @inline(__always)
    static func deliver(_ n: Int32, _ ring: OpaquePointer, on worker: Worker, busy: Bool) -> Int {
        guard n > 0 else { return 0 }
        let wakes = cv_uring_wakes(ring)!
        @inline(__always) func resume(_ i: Int) {
            unsafeBitCast(wakes[i].waiter, to: UnsafeContinuation<Int64, Never>.self)
                .resume(returning: wakes[i].res)
        }
        if n == 1 {
            resume(0)
        } else if busy {
            let local = min(Int(n), max(0, worker.queue.remainingSlots - 1))
            worker.inOrder {
                for i in 0..<local { resume(i) }
            }
            if local < Int(n) {
                worker.viaInject(worker.scheduler.unsafelyUnwrapped) {
                    for i in local..<Int(n) { resume(i) }
                }
            }
        } else {
            worker.inOrder {
                for i in 0..<Int(n) { resume(i) }
            }
        }
        return Int(n)
    }
}
#else
/// No io_uring here: every operation takes the readiness path.
enum URing {
    @inline(__always)
    static func perform(_ request: URingRequest, owner: UnsafeRawPointer?) async -> Int64? { nil }
}
#endif
