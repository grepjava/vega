#if os(Linux) || canImport(Darwin) || os(Windows)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// close(2), under a name that a type's own `close()` doesn't shadow.
#if os(Windows)
/// Every descriptor the driver sees on Windows is a socket.
@inline(__always) func closeDescriptor(_ fd: Int32) { cv_close_socket(fd) }
#else
@inline(__always) func closeDescriptor(_ fd: Int32) { _ = close(fd) }
#endif

/// The runtime's I/O driver: one edge-triggered epoll (Linux) or kqueue
/// (Darwin) instance, as in Tokio's multi-threaded runtime. The parked worker that owns the timers blocks in
/// it; busy workers poll it every `Worker.timerInterval` ticks. Trivial to
/// copy (no ARC); the scheduler frees it.
///
/// Under the uring driver there is no such object: `raw` is nil and `owner`
/// names the runtime whose workers' rings serve its sockets.
struct IODriver: @unchecked Sendable {
    let raw: OpaquePointer?
    /// The scheduler, unretained, when the runtime runs the uring driver.
    let owner: UnsafeRawPointer?

    init(raw: OpaquePointer?, owner: UnsafeRawPointer? = nil) {
        self.raw = raw
        self.owner = owner
    }

    static func make() -> IODriver? {
        cv_driver_new().map { IODriver(raw: $0) }
    }

    func destroy() { cv_driver_free(raw) }

    /// A parked worker's turn: block until an event, a notify or `timeout`.
    /// Resumes the tasks that became ready on `worker`; returns how many.
    func park(_ parker: OpaquePointer, timeout: Int64, on worker: Worker) -> Int {
        cv_driver_lock(raw) // contended only by a busy worker's zero-timeout poll
        defer { cv_driver_unlock(raw) }
        return resume(cv_driver_turn(raw, parker, timeout), on: worker, busy: false)
    }

    /// A busy worker's turn: collect what is ready, without blocking. Skipped
    /// when another worker is polling or nothing is registered.
    func poll(on worker: Worker) -> Int {
        guard cv_driver_registered(raw) > 0, cv_driver_try_lock(raw) != 0 else { return 0 }
        defer { cv_driver_unlock(raw) }
        return resume(cv_driver_turn(raw, nil, 0), on: worker, busy: true)
    }

    /// Resuming only enqueues the tasks, so it is done under the lock,
    /// straight from the driver's wake buffer.
    @inline(__always) private func resume(_ n: Int32, on worker: Worker, busy: Bool) -> Int {
        guard n > 0 else { return 0 }
        let wakes = cv_driver_wakes(raw)!
        if n == 1 {
            // One task: the LIFO slot, where it runs next with a hot cache.
            IOWaiter.resume(wakes[0])
        } else if busy {
            // A busy worker has a queue already. Fill only its free room, so
            // no older job is pushed out to the inject queue; the rest go
            // there in event order (see Worker.viaInject).
            let local = min(Int(n), max(0, worker.queue.remainingSlots - 1))
            worker.inOrder {
                for i in 0..<local { IOWaiter.resume(wakes[i]) }
            }
            if local < Int(n) {
                worker.viaInject(worker.scheduler.unsafelyUnwrapped) {
                    for i in local..<Int(n) { IOWaiter.resume(wakes[i]) }
                }
            }
        } else {
            // A worker leaving park: its queue was empty. In event order, and
            // idle workers get notified to steal.
            worker.inOrder {
                for i in 0..<Int(n) { IOWaiter.resume(wakes[i]) }
            }
        }
        return Int(n)
    }
}

/// A registered fd, as the driver and the task see it. Trivial to copy;
/// the owning socket deregisters it once.
struct IORegistration: @unchecked Sendable {
    let io: UnsafeMutablePointer<cv_io>
    /// The epoll driver; nil under the uring driver.
    let driver: OpaquePointer?
    /// Under the uring driver, the scheduler (unretained) whose workers'
    /// rings a task off them hops to.
    let owner: UnsafeRawPointer?
    /// Under `IOBackend.network`, the retained `NetworkHandle` (an
    /// `NWConnection` or `NWListener`) doing the I/O; `io` then has no fd and
    /// only counts the owners. nil for every fd-backed socket.
    let nw: UnsafeRawPointer?

    init(fd: Int32, driver: IODriver) throws(IOError) {
        if let raw = driver.raw {
            var err: Int32 = 0
            guard let io = cv_driver_register(raw, fd, &err) else {
                closeDescriptor(fd)
                throw IOError(code: err)
            }
            self.io = io
        } else {
            let s = Unmanaged<Scheduler>.fromOpaque(driver.owner.unsafelyUnwrapped).takeUnretainedValue()
            guard let io = cv_uring_io_new(fd, s.socketCount) else {
                closeDescriptor(fd)
                throw IOError(code: ENOMEM)
            }
            self.io = io
        }
        self.driver = driver.raw
        self.owner = driver.owner
        nw = nil
    }

    var fd: Int32 { io.pointee.fd }

    /// The driver this registration came from, for sockets it accepts.
    var home: IODriver { IODriver(raw: driver, owner: owner) }

    /// Unregister and close the fd.
    func close() {
        #if canImport(Network)
        if let nw {
            NetworkIO.release(io, nw)
            return
        }
        #endif
        if let driver {
            cv_driver_deregister(driver, io)
        } else {
            cv_uring_io_release(io)
        }
    }

    /// Wait until the driver reports `direction` ready (after a syscall said
    /// EAGAIN). Throws `.cancelled` if the task is cancelled first, or
    /// `.timedOut` if its I/O deadline passes: only this wait is abandoned,
    /// the fd stays usable.
    @inline(__always)
    func wait(_ direction: Int32) async throws(IOError) {
        if let res = await URing.perform(.poll(fd, direction), owner: owner) {
            // Any mask means "try again"; errors and hang-ups show up there.
            // A poll consumes nothing, so a cancelled task gives up even if
            // readiness beat the cancel to the ring (as the epoll path does).
            if res == -Int64(ETIMEDOUT) { throw .timedOut }
            if res == -Int64(ECANCELED) || Task.isCancelled { throw .interrupted }
            if res < 0 { throw IOError(code: Int32(-res)) }
            return
        }
        let ready = await withIOCancellation { deadline in
            await withUnsafeContinuation { (c: UnsafeContinuation<Bool, Never>) in
                let waiter = IOWaiter.bits(c)
                if cv_io_arm(io, direction, waiter) != 0 {
                    c.resume(returning: true) // an event beat us here: retry now
                    return
                }
                // The cancel handler may have run before we armed; it sets the
                // flag first, so one of the two sees the other. The same goes
                // for the deadline.
                if Task.isCancelled || deadline?.hasFired == true, cv_io_disarm(io, direction, waiter) != 0 {
                    c.resume(returning: false)
                    return
                }
                #if os(Windows)
                // Readiness there is a one-shot AFD poll, asked for now that
                // someone waits (it completes at once if already ready).
                cv_driver_want(io, direction)
                #endif
            }
        } onCancel: {
            let waiter = cv_io_take_waiter(io, direction)
            if waiter != 0 { IOWaiter.continuation(waiter).resume(returning: false) }
        }
        if !ready { throw .interrupted }
    }
}

/// A waiting task's continuation, stored in an I/O slot as an integer. It
/// resumes with true when ready, false when cancelled.
enum IOWaiter {
    @inline(__always) static func bits(_ c: UnsafeContinuation<Bool, Never>) -> UInt {
        unsafeBitCast(c, to: UInt.self)
    }

    @inline(__always) static func continuation(_ bits: UInt) -> UnsafeContinuation<Bool, Never> {
        unsafeBitCast(bits, to: UnsafeContinuation<Bool, Never>.self)
    }

    @inline(__always) static func resume(_ bits: UInt) {
        continuation(bits).resume(returning: true)
    }
}
#endif
