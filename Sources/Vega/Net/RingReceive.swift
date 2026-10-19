#if os(Linux)
import CVega
import Glibc

// `receive()` under the io_uring driver. The kernel picks the buffer from
// the worker's pool (`cv_uring_bufs_setup`) when bytes arrive, so a socket
// waiting for input holds none:
//
// - multishot (the default): the first `receive()` arms one RECV_MULTISHOT
//   on the worker's ring, which keeps receiving for the connection's life.
//   Its completions land on that ring and queue in the socket's `cv_rx`
//   for the task, wherever it runs; a buffer goes back to the ring it came
//   from, from any thread. A reader that falls behind pauses it, and the
//   next `receive()` that finds the queue empty arms it again, on the ring
//   of the worker it is on then.
// - single: one RECV with buffer select per `receive()`.
//
// `VEGA_RECV=multishot|single|readiness` picks (readiness: no pool; read
// into a receive block once the socket has bytes, as the epoll driver does).
// Once a multishot receive is armed, the socket's other reads take what it
// queued first, so bytes come out in order whichever read asks.

/// cv_rx_take's CV_RX_WAIT and CV_RX_IDLE (macros Swift doesn't import).
private let rxWait = Int64.min, rxIdle = Int64.min + 1

/// An encoded result's buffer id, if it came in one (see cvega.h).
@inline(__always)
private func bufferID(_ res: Int64) -> Int32? {
    let tag = Int32(truncatingIfNeeded: (res >> 32) & 0xffff)
    return tag == 0 ? nil : tag - 1
}

extension IORegistration {
    private var rx: OpaquePointer? {
        io.pointee.rx.map { OpaquePointer($0) }
    }

    /// `receive()` on the ring, or nil to receive another way: not a uring
    /// socket on a ring's worker, the pool short of buffers, or readiness
    /// asked for.
    func receiveOnRing() async throws(IOError) -> ReceivedBytes? {
        var rx = self.rx
        if rx == nil {
            guard driver == nil, let owner, let ring = URing.current, cv_uring_bufs_ready(ring) != 0 else {
                return nil
            }
            switch Unmanaged<Scheduler>.fromOpaque(owner)._withUnsafeGuaranteedRef({ $0.receiveMode }) {
            case .readiness: return nil
            case .single: return try await receiveSelect()
            case .multishot:
                guard let made = cv_rx_new() else { return nil }
                io.pointee.rx = UnsafeMutableRawPointer(made)
                rx = made
            }
        }
        let r = rx.unsafelyUnwrapped
        while true {
            var ring: OpaquePointer?
            var off: UInt32 = 0
            let res = cv_rx_take(r, 0, &ring, &off)
            if res == rxIdle {
                // Nothing armed, nothing queued: arm on this worker's ring.
                guard let current = URing.current, cv_uring_bufs_ready(current) != 0,
                      cv_rx_arm(r, current, fd) == 0 else { return nil }
                continue
            }
            if res == rxWait {
                try await waitReceived(r)
                continue
            }
            if res > 0, let bid = bufferID(res), let ring {
                let length = Int(res & 0xffff_ffff)
                var bytes = ReceivedBytes(ring: ring, bid: bid, storage: cv_uring_buf_addr(ring, bid), count: length)
                if off > 0 { bytes.removeFirst(Int(off)) }
                await Runtime.consumeBudget()
                return bytes
            }
            if res == 0 { return ReceivedBytes() }
            throw IOError(code: Int32(-res))
        }
    }

    /// Wait for `rx`'s next completion (or the end of the receive).
    private func waitReceived(_ rx: OpaquePointer) async throws(IOError) {
        let res = await withIOInterrupt { arm in
            await withUnsafeContinuation { (c: UnsafeContinuation<Int64, Never>) in
                let waiter = unsafeBitCast(c, to: UInt.self)
                // Something came, or the receive ended, meanwhile: go look.
                guard cv_rx_wait(rx, waiter) != 0 else {
                    c.resume(returning: 0)
                    return
                }
                let interrupt = IOInterrupt.rx(rx, waiter)
                if !arm(interrupt) { interrupt.fire() }
            }
        }
        if res == -Int64(ECANCELED) {
            if !Task.isCancelled, IODeadline.active?.hasFired == true { throw .timedOut }
            throw .cancelled
        }
    }

    /// One RECV with buffer select on the current worker's ring.
    private func receiveSelect() async throws(IOError) -> ReceivedBytes? {
        while true {
            var on: OpaquePointer?
            let res = await withIOInterrupt { arm in
                await withUnsafeContinuation { (c: UnsafeContinuation<Int64, Never>) in
                    // The ring is looked up on the thread that submits: the
                    // task may have moved since `receive()` checked.
                    guard let ring = URing.current, cv_uring_bufs_ready(ring) != 0 else {
                        c.resume(returning: URing.noRing)
                        return
                    }
                    on = ring
                    var gen: UInt64 = 0
                    let op = cv_uring_recv_select(ring, unsafeBitCast(c, to: UInt.self), fd, &gen)!
                    let cancel = IOInterrupt.uring(op, gen)
                    if !arm(cancel) { cancel.fire() }
                }
            }
            if res >= 0 {
                if let bid = bufferID(res), let on {
                    let length = Int(res & 0xffff_ffff)
                    let bytes = ReceivedBytes(ring: on, bid: bid, storage: cv_uring_buf_addr(on, bid), count: length)
                    if length == 0 { return ReceivedBytes() } // its buffer goes back with it
                    await Runtime.consumeBudget()
                    return bytes
                }
                return ReceivedBytes() // 0: the end of the stream
            }
            if res == URing.noRing || res == -Int64(ENOBUFS) { return nil }
            if res == -Int64(ECANCELED), !Task.isCancelled, IODeadline.active?.hasFired == true {
                throw .timedOut
            }
            try Self.retryable(res)
        }
    }

    /// Copy what the multishot receive queued into `buffer`'s spare
    /// capacity: the bytes copied, 0 at the end of the stream; -1 when it is
    /// armed with nothing queued (no other read may run meanwhile: bytes
    /// would come out of order); nil when there is no receive armed (read
    /// any way).
    func takeReceived(into buffer: inout IOBuffer) throws(IOError) -> Int? {
        guard let rx else { return nil }
        var ring: OpaquePointer?
        var off: UInt32 = 0
        let res = cv_rx_take(rx, 0, &ring, &off)
        if res == rxIdle { return nil }
        if res == rxWait { return -1 }
        if res > 0, let bid = bufferID(res), let ring {
            let length = Int(res & 0xffff_ffff)
            let start = cv_uring_buf_addr(ring, bid)! + Int(off)
            let n = min(length - Int(off), buffer.spareCapacity)
            (buffer.base + buffer.count).copyMemory(from: start, byteCount: n)
            buffer.readable += n
            if Int(off) + n < length {
                cv_rx_untake(rx, ring, res, off + UInt32(n))
            } else {
                cv_uring_buf_return(ring, bid)
            }
            return n
        }
        if res == 0 { return 0 }
        throw IOError(code: Int32(-res))
    }

    /// `read(into:)` on a socket with a multishot receive: from its queue,
    /// waiting on it while it is armed; nil once it isn't (read any way).
    func readReceived(into buffer: inout IOBuffer) async throws(IOError) -> Int? {
        guard let rx else { return nil }
        while true {
            guard let n = try takeReceived(into: &buffer) else { return nil }
            if n >= 0 {
                if n > 0 { await Runtime.consumeBudget() }
                return n
            }
            try await waitReceived(rx)
        }
    }

    /// `waitReadable` on a socket with a multishot receive: whether what is
    /// queued ends the stream, waiting on the queue while it is armed; nil
    /// once it isn't (wait any way).
    func waitReceivedReadable() async throws(IOError) -> Bool? {
        guard let rx else { return nil }
        while true {
            var eof: Int32 = 0
            if cv_rx_pending(rx, &eof) != 0 { return eof != 0 }
            var ring: OpaquePointer?
            var off: UInt32 = 0
            // Not a take: with nothing queued it only says whether one is
            // armed.
            let res = cv_rx_take(rx, 0, &ring, &off)
            if res == rxIdle { return nil }
            if res != rxWait {
                // Came in between: put it back for the read.
                cv_rx_untake(rx, ring, res, off)
                continue
            }
            try await waitReceived(rx)
        }
    }

    /// Whether the multishot receive has queued something.
    var hasReceived: Bool {
        guard let rx else { return false }
        var eof: Int32 = 0
        return cv_rx_pending(rx, &eof) != 0
    }
}
#endif
