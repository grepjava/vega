#if os(Linux) || canImport(Darwin)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// close(2), under a name that a type's own `close()` doesn't shadow.
@inline(__always) func closeDescriptor(_ fd: Int32) { _ = close(fd) }

/// The runtime's I/O driver: one edge-triggered epoll (Linux) or kqueue
/// (Darwin) instance, as in Tokio's multi-threaded runtime. The parked worker that owns the timers blocks in
/// it; busy workers poll it every `Worker.timerInterval` ticks. Trivial to
/// copy (no ARC); the scheduler frees it.
struct IODriver: @unchecked Sendable {
    let raw: OpaquePointer

    static func make() -> IODriver? {
        cv_driver_new().map(IODriver.init(raw:))
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
    let driver: OpaquePointer

    init(fd: Int32, driver: IODriver) throws(IOError) {
        var err: Int32 = 0
        guard let io = cv_driver_register(driver.raw, fd, &err) else {
            closeDescriptor(fd)
            throw IOError(code: err)
        }
        self.io = io
        self.driver = driver.raw
    }

    var fd: Int32 { io.pointee.fd }

    /// Unregister and close the fd.
    func close() { cv_driver_deregister(driver, io) }

    /// Wait until the driver reports `direction` ready (after a syscall said
    /// EAGAIN). Throws `.cancelled` if the task is cancelled first: only this
    /// wait is abandoned, the fd stays usable.
    @inline(__always)
    func wait(_ direction: Int32) async throws(IOError) {
        let ready = await withTaskCancellationHandler {
            await withUnsafeContinuation { (c: UnsafeContinuation<Bool, Never>) in
                let waiter = IOWaiter.bits(c)
                if cv_io_arm(io, direction, waiter) != 0 {
                    c.resume(returning: true) // an event beat us here: retry now
                    return
                }
                // The cancel handler may have run before we armed; it sets the
                // flag first, so one of the two sees the other.
                if Task.isCancelled, cv_io_disarm(io, direction, waiter) != 0 {
                    c.resume(returning: false)
                }
            }
        } onCancel: {
            let waiter = cv_io_take_waiter(io, direction)
            if waiter != 0 { IOWaiter.continuation(waiter).resume(returning: false) }
        }
        if !ready { throw .cancelled }
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
