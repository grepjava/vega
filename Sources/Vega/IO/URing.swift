import CVega
import Synchronization
#if canImport(Glibc)
import Glibc
#endif

/// Which I/O driver a runtime uses.
public enum IOBackend: Sendable, Equatable {
    /// `.ioUring` where the kernel can run it, else `.readiness`; on iOS,
    /// tvOS, watchOS and visionOS, `.network`. `VEGA_DRIVER=epoll`, `uring`,
    /// `kqueue` or `network` overrides.
    case automatic
    /// One edge-triggered epoll (kqueue on Darwin) per runtime.
    case readiness
    /// Completion (Linux 6.7+): one io_uring per worker. Falls back to
    /// `.readiness` where the kernel can't run it (older, or io_uring
    /// blocked by seccomp or `kernel.io_uring_disabled`); `Runtime.ioBackend`
    /// says which runs.
    case ioUring
    /// Apple's Network.framework (`NWConnection`, `NWListener`) for TCP; the
    /// readiness driver (kqueue) stays for everything else (UDP, Unix
    /// sockets, pipes, processes): see docs/PLAN.md for why UDP waits. The default on iOS-family platforms,
    /// where BSD sockets don't bring up the cellular radio or VPN on demand;
    /// opt-in on macOS. Elsewhere it means `.automatic`.
    case network
}

/// One operation for a worker's ring. Pointers stay valid until the
/// operation completes: the task waits for that, even when cancelled.
enum URingRequest: @unchecked Sendable {
    case recv(Int32, UnsafeMutableRawPointer, Int)
    /// A recv as a recvmsg through the arrival record, which says when the
    /// bytes arrived once `cv_arrival_settle` has read it.
    case recvStamped(Int32, UnsafeMutableRawPointer, Int, UnsafeMutablePointer<cv_arrival>)
    case accept(Int32)
    /// One-shot readiness (`CV_IO_READ` / `CV_IO_WRITE`), for operations
    /// with no completion form here: writes that found the socket full,
    /// connect, datagram batches.
    case poll(Int32, Int32)
    /// File reads and writes at an offset (-1: the file position).
    case fileRead(Int32, UnsafeMutableRawPointer, Int, Int64)
    case fileWrite(Int32, UnsafeRawPointer, Int, Int64)
    /// fsync; fdatasync when true.
    case fsync(Int32, Bool)
    case open(UnsafePointer<CChar>, Int32, UInt32)
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
        case .readiness, .network: return false
        case .ioUring: return true
        case .automatic:
            guard let v = getenv("VEGA_DRIVER") else { return true }
            return String(cString: v) != "epoll"
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
        case let .recvStamped(fd, buf, len, arrival):
            return cv_uring_recv_stamped(ring, waiter, fd, buf, len, arrival, gen)
        case let .accept(fd): return cv_uring_accept(ring, waiter, fd, gen)
        case let .poll(fd, dir): return cv_uring_poll_ready(ring, waiter, fd, dir, gen)
        case let .fileRead(fd, buf, len, off): return cv_uring_file_rw(ring, waiter, 0, fd, buf, len, off, gen)
        case let .fileWrite(fd, buf, len, off):
            return cv_uring_file_rw(ring, waiter, 1, fd, UnsafeMutableRawPointer(mutating: buf), len, off, gen)
        case let .fsync(fd, data): return cv_uring_fsync(ring, waiter, fd, data ? 1 : 0, gen)
        case let .open(path, flags, mode): return cv_uring_openat(ring, waiter, path, flags, mode, gen)
        }
    }

    /// Run `request` on the current worker's ring: the result (>= 0) or
    /// -errno (-ECANCELED if the task was cancelled first, -ETIMEDOUT if its
    /// I/O deadline passed), or `noRing`.
    @inline(__always)
    static func run(_ request: URingRequest) async -> Int64 {
        let res = await withIOInterrupt { arm in
            await withUnsafeContinuation { (c: UnsafeContinuation<Int64, Never>) in
                // Looked up here, on the thread that submits: the ring takes
                // submissions from its own worker only.
                guard let ring = current else {
                    c.resume(returning: noRing)
                    return
                }
                var gen: UInt64 = 0
                let op = submit(request, ring, unsafeBitCast(c, to: UInt.self), &gen)
                // Cancelled or past the deadline already: cancel it now.
                let cancel = IOInterrupt.uring(op, gen)
                if !arm(cancel) { cancel.fire() }
            }
        }
        // Given up at the deadline rather than by cancellation: say so.
        if res == -Int64(ECANCELED), !Task.isCancelled, IODeadline.active?.hasFired == true {
            return -Int64(ETIMEDOUT)
        }
        return res
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
        let task = s.task { () async -> Int64 in
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
