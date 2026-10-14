#if os(Linux) || canImport(Darwin) || os(Windows)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

// The byte-stream operations TCP and Unix sockets (and their split halves)
// share. The readiness backends try the syscall first and wait only on EAGAIN.
// The uring driver submits reads and accepts on the ring (a read usually has
// to wait anyway); writes still try the syscall first.
/// A read on the current worker's ring by a task with an `IOTaskHook`, set
/// up by `IORegistration.ringRead`: the public reads run it inline, so the
/// caller suspends on the ring's completion directly. An async call into
/// the read would cost an executor hop on the way in and another on the
/// way back, each a look-up of the task's executor preference under its
/// status-record lock.
@usableFromInline
struct RingRead {
    #if os(Linux)
    fileprivate let ring: OpaquePointer
    fileprivate let hook: Unmanaged<IOTaskHook>
    fileprivate let deadline: Unmanaged<IODeadline>?
    fileprivate let base: UnsafeMutableRawPointer
    fileprivate let length: Int
    #endif
}

extension IORegistration {
    /// A read the caller can run inline (see `RingRead`), or nil: then it
    /// calls `readSlow`, which handles every case.
    @usableFromInline
    func ringRead(_ buffer: inout IOBuffer) -> RingRead? {
        #if os(Linux)
        guard buffer.spareCapacity > 0, let ring = URing.current, let hook = IOTaskHook.active else { return nil }
        return RingRead(ring: ring, hook: .passUnretained(hook), deadline: hook.deadline.map { .passUnretained($0) },
                        base: buffer.base + buffer.count, length: buffer.spareCapacity)
        #else
        return nil
        #endif
    }

    /// Submit `read` and arm its task's hook, from inside the continuation.
    @usableFromInline
    func submit(_ read: RingRead, _ c: UnsafeContinuation<Int64, Never>) {
        #if os(Linux)
        var gen: UInt64 = 0
        let op: OpaquePointer = cv_uring_recv(read.ring, unsafeBitCast(c, to: UInt.self), fd, read.base, read.length, &gen)
        // Cancelled or past the deadline already: cancel it now.
        let cancel = IOInterrupt.uring(op, gen)
        let armed = read.hook._withUnsafeGuaranteedRef { $0.arm(cancel) }
            && (read.deadline?._withUnsafeGuaranteedRef { $0.arm(cancel) } ?? true)
        if !armed { cancel.fire() }
        #endif
    }

    /// Settle `read` with the ring's result `res`: the bytes read, now in
    /// `buffer`, and whether the budget ran out (`yield`); or -1 when the
    /// read must be tried again (`readSlow`).
    @usableFromInline
    func finish(_ read: RingRead, _ res: Int64, _ buffer: inout IOBuffer, _ yield: inout Bool) throws(IOError) -> Int {
        #if os(Linux)
        read.hook._withUnsafeGuaranteedRef { $0.disarm() }
        read.deadline?._withUnsafeGuaranteedRef { $0.disarm() }
        if res >= 0 {
            buffer.count += Int(res)
            yield = Runtime.spendBudget()
            return Int(res)
        }
        // Given up at the deadline rather than by cancellation: say so.
        if res == -Int64(ECANCELED), !Task.isCancelled,
           read.deadline?._withUnsafeGuaranteedRef({ $0.hasFired }) == true {
            throw .timedOut
        }
        try Self.retryable(res)
        #endif
        return -1
    }

    /// `read(into:)`, out of line: for the public reads when `ringRead`
    /// says no.
    @usableFromInline
    func readSlow(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        try await read(into: &buffer)
    }

    /// Read into `buffer`'s spare capacity: bytes read, 0 at end of stream.
    @inline(__always)
    func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        guard buffer.spareCapacity > 0 else { return 0 }
        #if canImport(Network)
        if let nw { return try await nwRead(into: &buffer, nw) }
        #endif
        while let res = await URing.perform(.recv(fd, buffer.base + buffer.count, buffer.spareCapacity),
                                            owner: owner) {
            if res >= 0 {
                buffer.count += Int(res)
                await Runtime.consumeBudget()
                return Int(res)
            }
            try Self.retryable(res)
        }
        if io.pointee.read_drained != 0 {
            // The last read came up short, so the socket was empty: skip the
            // recv that would say EAGAIN and wait for the next event (Tokio
            // does the same). Data that arrived since has left READY. Not
            // once the peer has closed: that edge came already, and the next
            // recv returns end of stream.
            io.pointee.read_drained = 0
            if cv_io_read_closed(io) == 0, cv_io_take_ready(io, CV_IO_READ) == 0 {
                try await wait(CV_IO_READ)
            }
        }
        while true {
            let want = buffer.spareCapacity
            let n = cv_recv(fd, buffer.base + buffer.count, want)
            if n >= 0 {
                buffer.count += n
                if n > 0 && n < want { io.pointee.read_drained = 1 }
                await Runtime.consumeBudget()
                return n
            }
            let err = Int32(-n)
            switch err {
            case EAGAIN, EWOULDBLOCK: try await wait(CV_IO_READ)
            case EINTR: continue
            default: throw IOError(code: err)
            }
        }
    }

    /// `sendNow`'s status when it has sent everything but the task's budget
    /// ran out, and when the stream isn't a socket it can send on here.
    @usableFromInline static let sendYield: Int32 = -1, sendElsewhere: Int32 = -2

    /// The synchronous part of a write, for the public writes to inline into
    /// their caller: send what the socket takes of `bytes` and spend a unit
    /// of budget. Returns the bytes sent; `status` is 0 when that was all of
    /// them, else what `writeRest` has to deal with: EAGAIN (wait for room
    /// and go on), `sendYield`, `sendElsewhere`, or the error to throw.
    ///
    /// A write nearly always completes here, and inlined it is no call at
    /// all: an async call costs an executor hop on the way in and another on
    /// the way back, each a look-up of the task's executor preference under
    /// its status-record lock.
    @usableFromInline
    func sendNow(_ bytes: UnsafeRawBufferPointer, _ status: inout Int32) -> Int {
        #if canImport(Network)
        if nw != nil {
            status = Self.sendElsewhere
            return 0
        }
        #endif
        var done = 0
        while done < bytes.count {
            let n = cv_send(fd, bytes.baseAddress! + done, bytes.count - done)
            if n >= 0 {
                done += n
                continue
            }
            let err = Int32(-n)
            if err == EINTR { continue }
            status = err == EWOULDBLOCK ? EAGAIN : err
            return done
        }
        if Runtime.spendBudget() { status = Self.sendYield }
        return done
    }

    /// The rest of a write `sendNow` couldn't finish.
    @usableFromInline
    func writeRest(_ bytes: UnsafeRawBufferPointer, sent: Int, status: Int32) async throws(IOError) {
        switch status {
        case Self.sendYield:
            await Runtime.yieldSpent()
        case Self.sendElsewhere:
            try await write(bytes)
        case EAGAIN:
            try await wait(CV_IO_WRITE)
            try await write(UnsafeRawBufferPointer(rebasing: bytes[sent...]))
        default:
            throw IOError(code: status)
        }
    }

    /// `sendNow` for two buffers, gathered.
    @usableFromInline
    func sendNow(_ a: UnsafeRawBufferPointer, _ b: UnsafeRawBufferPointer, _ status: inout Int32) -> Int {
        sendNow(parts: 2, { $0 == 0 ? a : b }, &status)
    }

    /// `writeRest` for two buffers.
    @usableFromInline
    func writeRest(_ a: UnsafeRawBufferPointer, _ b: UnsafeRawBufferPointer, sent: Int,
                   status: Int32) async throws(IOError) {
        try await writeRest(parts: 2, { $0 == 0 ? a : b }, sent: sent, status: status)
    }

    /// `sendNow` for `parts`, gathered.
    @usableFromInline
    func sendNow(vectored parts: UnsafeBufferPointer<UnsafeRawBufferPointer>, _ status: inout Int32) -> Int {
        sendNow(parts: parts.count, { parts[$0] }, &status)
    }

    /// `writeRest` for `parts`.
    @usableFromInline
    func writeRest(vectored parts: UnsafeBufferPointer<UnsafeRawBufferPointer>, sent: Int,
                   status: Int32) async throws(IOError) {
        try await writeRest(parts: parts.count, { parts[$0] }, sent: sent, status: status)
    }

    /// `sendNow` for `count` buffers: `trySend`, with a full socket, an
    /// error or a spent budget said in `status`.
    @inline(__always)
    private func sendNow(parts count: Int, _ part: (Int) -> UnsafeRawBufferPointer,
                         _ status: inout Int32) -> Int {
        #if canImport(Network)
        if nw != nil {
            status = Self.sendElsewhere
            return 0
        }
        #endif
        var index = 0, offset = 0, sent = 0
        while true {
            while index < count && offset == part(index).count {
                index += 1
                offset = 0
            }
            if index == count { break }
            var offered = 0
            let n = withUnsafeTemporaryAllocation(of: cv_iovec.self, capacity: 64) { iov in
                var k = 0, i = index
                while k < 64 && i < count {
                    let p = part(i)
                    let skip = i == index ? offset : 0
                    if p.count > skip {
                        iov[k] = cv_iovec(base: p.baseAddress! + skip, len: p.count - skip)
                        offered += p.count - skip
                        k += 1
                    }
                    i += 1
                }
                return cv_sendv(fd, iov.baseAddress, Int32(k))
            }
            if n < 0 {
                let err = Int32(-n)
                if err == EINTR { continue }
                status = err == EWOULDBLOCK ? EAGAIN : err
                return sent
            }
            sent += n
            if n < offered {
                // Short: the socket is full, and another call would say so.
                status = EAGAIN
                return sent
            }
            (index, offset) = position(after: n, index, offset, part)
        }
        if Runtime.spendBudget() { status = Self.sendYield }
        return sent
    }

    /// The rest of a write of `count` buffers that `sendNow` couldn't
    /// finish, `sent` bytes in.
    private func writeRest(parts count: Int, _ part: (Int) -> UnsafeRawBufferPointer, sent: Int,
                           status: Int32) async throws(IOError) {
        switch status {
        case Self.sendYield:
            await Runtime.yieldSpent()
        case Self.sendElsewhere:
            try await write(parts: count, part)
        case EAGAIN:
            try await wait(CV_IO_WRITE)
            let (index, offset) = position(after: sent, 0, 0, part)
            try await write(parts: count - index) { j in
                j == 0 ? UnsafeRawBufferPointer(rebasing: part(index)[offset...]) : part(index + j)
            }
        default:
            throw IOError(code: status)
        }
    }

    /// Where a gathered write stands `n` bytes past buffer `index`, `offset`
    /// bytes in: the buffer and the offset in it.
    @inline(__always)
    private func position(after n: Int, _ index: Int, _ offset: Int,
                   _ part: (Int) -> UnsafeRawBufferPointer) -> (index: Int, offset: Int) {
        var left = n, index = index, offset = offset
        while left > 0 {
            let rest = part(index).count - offset
            if left < rest { return (index, offset + left) }
            left -= rest
            index += 1
            offset = 0
        }
        return (index, offset)
    }

    /// Write all of `bytes`.
    @inline(__always)
    func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        #if canImport(Network)
        if let nw { return try await nwWrite(nw, parts: 1) { _ in bytes } }
        #endif
        // On every driver: the socket almost always has room, and a send
        // through the ring would suspend the task for its completion (one
        // more trip through the scheduler per write). EAGAIN waits on the
        // ring's poll under the uring driver.
        var done = 0
        while done < bytes.count {
            let n = cv_send(fd, bytes.baseAddress! + done, bytes.count - done)
            if n >= 0 {
                done += n
                continue
            }
            let err = Int32(-n)
            switch err {
            case EAGAIN, EWOULDBLOCK: try await wait(CV_IO_WRITE)
            case EINTR: continue
            default: throw IOError(code: err)
            }
        }
        await Runtime.consumeBudget()
    }

    /// Send up to `count` bytes of the file `file` from `offset`, by the
    /// kernel where it can (sendfile), else read and written here. Returns
    /// the bytes sent: `count`, or fewer when the file ends first.
    func sendFile(_ file: Int32, offset: Int64, count: Int) async throws(IOError) -> Int {
        var sent = 0
        #if canImport(Network)
        if nw != nil { return try await copyFile(file, offset: offset, count: count) }
        #endif
        while sent < count {
            let n = cv_sendfile(fd, file, offset + Int64(sent), count - sent)
            if n > 0 {
                sent += n
                continue
            }
            if n == 0 { break } // the file ended
            let err = Int32(-n)
            switch err {
            case EAGAIN, EWOULDBLOCK: try await wait(CV_IO_WRITE)
            case EINTR: continue
            case ENOSYS, EINVAL, EOPNOTSUPP:
                // No sendfile here, or not for this kind of file.
                return sent + (try await copyFile(file, offset: offset + Int64(sent), count: count - sent))
            default: throw IOError(code: err)
            }
        }
        await Runtime.consumeBudget()
        return sent
    }

    /// `sendFile` without the kernel's help: positioned reads, then writes.
    private func copyFile(_ file: Int32, offset: Int64, count: Int) async throws(IOError) -> Int {
        let chunk = min(count, 256 * 1024)
        guard chunk > 0 else { return 0 }
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: chunk, alignment: 16)
        defer { buffer.deallocate() }
        var sent = 0
        while sent < count {
            let want = min(chunk, count - sent), at = offset + Int64(sent)
            #if os(Windows)
            let n = cv_file_read(file, buffer, want, at)
            #else
            let r = pread(file, buffer, want, off_t(at))
            let n = r >= 0 ? r : -Int(errno)
            #endif
            if n < 0 {
                if Int32(-n) == EINTR { continue }
                throw IOError(code: Int32(-n))
            }
            if n == 0 { break }
            try await write(UnsafeRawBufferPointer(start: buffer, count: n))
            sent += n
        }
        return sent
    }

    /// Write all of `count` buffers, `part(i)` being the i-th, with as few
    /// sendmsg calls as the kernel allows (up to 64 buffers each).
    @inline(__always)
    func write(parts count: Int, _ part: (Int) -> UnsafeRawBufferPointer) async throws(IOError) {
        #if canImport(Network)
        if let nw { return try await nwWrite(nw, parts: count, part) }
        #endif
        var index = 0, offset = 0 // the first unsent buffer, and how much of it went
        while true {
            while index < count && offset == part(index).count {
                index += 1
                offset = 0
            }
            if index == count { break }
            let n = withUnsafeTemporaryAllocation(of: cv_iovec.self, capacity: 64) { iov in
                var k = 0, i = index
                while k < 64 && i < count {
                    let p = part(i)
                    let skip = i == index ? offset : 0
                    if p.count > skip {
                        iov[k] = cv_iovec(base: p.baseAddress! + skip, len: p.count - skip)
                        k += 1
                    }
                    i += 1
                }
                return cv_sendv(fd, iov.baseAddress, Int32(k))
            }
            if n >= 0 {
                var left = n
                while left > 0 {
                    let rest = part(index).count - offset
                    if left < rest {
                        offset += left
                        break
                    }
                    left -= rest
                    index += 1
                    offset = 0
                }
                continue
            }
            let err = Int32(-n)
            switch err {
            case EAGAIN, EWOULDBLOCK: try await wait(CV_IO_WRITE)
            case EINTR: continue
            default: throw IOError(code: err)
            }
        }
        await Runtime.consumeBudget()
    }

    /// Send what the socket takes now of `count` buffers, without waiting:
    /// the bytes sent, 0 if it has no room. Always 0 on Network.framework,
    /// which has no synchronous send.
    func trySend(parts count: Int, _ part: (Int) -> UnsafeRawBufferPointer) throws(IOError) -> Int {
        #if canImport(Network)
        if nw != nil { return 0 }
        #endif
        var index = 0, offset = 0, sent = 0
        while true {
            while index < count && offset == part(index).count {
                index += 1
                offset = 0
            }
            if index == count { return sent }
            var offered = 0
            let n = withUnsafeTemporaryAllocation(of: cv_iovec.self, capacity: 64) { iov in
                var k = 0, i = index
                while k < 64 && i < count {
                    let p = part(i)
                    let skip = i == index ? offset : 0
                    if p.count > skip {
                        iov[k] = cv_iovec(base: p.baseAddress! + skip, len: p.count - skip)
                        offered += p.count - skip
                        k += 1
                    }
                    i += 1
                }
                return cv_sendv(fd, iov.baseAddress, Int32(k))
            }
            if n >= 0 {
                sent += n
                // Short: the socket is full, and another call would say so.
                if n < offered { return sent }
                var left = n
                while left > 0 {
                    let rest = part(index).count - offset
                    if left < rest {
                        offset += left
                        break
                    }
                    left -= rest
                    index += 1
                    offset = 0
                }
                continue
            }
            let err = Int32(-n)
            switch err {
            case EAGAIN, EWOULDBLOCK: return sent
            case EINTR: continue
            default: throw IOError(code: err)
            }
        }
    }

    /// Accept connections with `accept` (a cv_*_accept), registering each.
    @inline(__always)
    func accept(_ accept: (Int32, UnsafeMutablePointer<Int32>) -> Int32) async throws(IOError) -> IORegistration {
        #if canImport(Network)
        if let nw { return try await nwAccept(nw) }
        #endif
        while let res = await URing.perform(.accept(fd), owner: owner) {
            if res >= 0 {
                // As cv_tcp_accept; on a Unix socket it fails, harmlessly.
                cv_tcp_accepted(Int32(res))
                await Runtime.consumeBudget()
                return try IORegistration(fd: Int32(res), driver: home)
            }
            switch Int32(-res) {
            case ECONNABORTED, EPROTO, EINTR, EAGAIN: continue
            case ECANCELED: throw .cancelled
            default: throw IOError(code: Int32(-res))
            }
        }
        while true {
            var err: Int32 = 0
            let fd = accept(self.fd, &err)
            if fd >= 0 {
                await Runtime.consumeBudget()
                return try IORegistration(fd: fd, driver: home)
            }
            switch err {
            case EAGAIN, EWOULDBLOCK: try await wait(CV_IO_READ)
            // The peer gave up before we got to it, or a signal: try the next.
            case EINTR, ECONNABORTED, EPROTO: continue
            default: throw IOError(code: err)
            }
        }
    }

    /// Finish a non-blocking connect that said `err` (0 or EINPROGRESS).
    func connected(_ err: Int32) async throws(IOError) {
        guard err == EINPROGRESS else { return }
        try await wait(CV_IO_WRITE)
        let e = cv_socket_error(fd)
        if e != 0 { throw IOError(code: e) }
    }

    /// One datagram-style operation: retried on EINTR, waited on EAGAIN.
    @inline(__always)
    func perform(_ direction: Int32, _ op: () -> Int) async throws(IOError) -> Int {
        while true {
            let n = op()
            if n >= 0 {
                await Runtime.consumeBudget()
                return n
            }
            let err = Int32(-n)
            switch err {
            case EAGAIN, EWOULDBLOCK: try await wait(direction)
            case EINTR: continue
            default: throw IOError(code: err)
            }
        }
    }

    /// A failed ring operation: return to retry (EINTR, EAGAIN), else throw.
    @inline(__always)
    static func retryable(_ res: Int64) throws(IOError) {
        switch Int32(-res) {
        case EINTR, EAGAIN: return
        case ECANCELED: throw .cancelled
        default: throw IOError(code: Int32(-res))
        }
    }

    func shutdownWrite() throws(IOError) {
        #if canImport(Network)
        if let nw { return nwShutdownWrite(nw) }
        #endif
        #if os(Windows)
        let e = cv_shutdown_write(fd)
        if e != 0 { throw IOError(code: e) }
        #else
        if shutdown(fd, Int32(SHUT_WR)) != 0 { throw IOError(code: errno) }
        #endif
    }

    /// Wait until a read would return at once, without reading: false when
    /// input is waiting, true when the read would end the stream (the peer
    /// closed its side, or reset the connection).
    func waitReadable() async throws(IOError) -> Bool {
        #if canImport(Network)
        if let nw { return try await nwWaitReadable(nw) }
        #endif
        // This wait may take the readiness edge a drained read would wait
        // for: the next read must ask the socket first.
        defer { io.pointee.read_drained = 0 }
        while true {
            let n = cv_peek(fd)
            if n > 0 { return false }
            if n == 0 { return true }
            let err = Int32(-n)
            switch err {
            case EAGAIN, EWOULDBLOCK: try await wait(CV_IO_READ)
            case EINTR: continue
            case ECONNRESET, ECONNABORTED, EPIPE, ENOTCONN: return true
            default: throw IOError(code: err)
            }
        }
    }

    /// Whether a read would return at once, without reading or waiting.
    var hasPendingInput: Bool {
        #if canImport(Network)
        if let nw { return nwHasPendingInput(nw) }
        #endif
        return cv_input_waiting(fd) != 0
    }

    var localAddress: SocketAddress {
        get throws(IOError) {
            #if canImport(Network)
            if let nw { return try nwAddress(nw, local: true) }
            #endif
            var raw = cv_sockaddr()
            let e = cv_local_address(fd, &raw)
            if e != 0 { throw IOError(code: e) }
            return SocketAddress(raw: raw)
        }
    }

    var peerAddress: SocketAddress {
        get throws(IOError) {
            #if canImport(Network)
            if let nw { return try nwAddress(nw, local: false) }
            #endif
            var raw = cv_sockaddr()
            let e = cv_peer_address(fd, &raw)
            if e != 0 { throw IOError(code: e) }
            return SocketAddress(raw: raw)
        }
    }
}

/// A stream split in two (Swift has no tuples of `~Copyable` values). Move
/// the halves out to separate tasks:
///
/// ```swift
/// let halves = stream.split()
/// rt.spawn(with: halves.reader) { reader in ... }
/// let writer = halves.writer
/// ```
@frozen
public struct SplitStream: ~Copyable, Sendable {
    public var reader: ReadHalf
    public var writer: WriteHalf
}

/// The reading half of a split stream. Dropping both halves closes the socket.
public struct ReadHalf: ~Copyable, Sendable {
    @usableFromInline let reg: IORegistration

    init(reg: IORegistration) { self.reg = reg }

    deinit { reg.close() }

    /// Read into `buffer`'s spare capacity. Returns the bytes read: 0 means
    /// the peer closed its side (or the buffer has no room left).
    @inlinable
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        // Inlined, a read on the ring suspends the caller directly: see
        // `RingRead`.
        let reg = reg
        if let ring = reg.ringRead(&buffer) {
            let res = await withUnsafeContinuation { reg.submit(ring, $0) }
            var yield = false
            let n = try reg.finish(ring, res, &buffer, &yield)
            if n >= 0 {
                if yield { await Runtime.yieldSpent() }
                return n
            }
        }
        return try await reg.readSlow(into: &buffer)
    }

    /// Wait until a read would return at once, without reading: for input
    /// to arrive, or for the peer to close its side.
    public func readable() async throws(IOError) {
        _ = try await reg.waitReadable()
    }

    /// Wait until the peer closes its side of the connection, or resets it,
    /// and return true; or return false as soon as input arrives instead,
    /// since a close behind that input can't be seen until it is read. For a
    /// server that wants to stop work a client no longer waits for -- an
    /// HTTP/1 request whose client hung up -- while it reads nothing.
    /// Cancellation and `Runtime.withIODeadline` end the wait as they end a
    /// read.
    public func peerClosed() async throws(IOError) -> Bool {
        try await reg.waitReadable()
    }
}

/// The writing half of a split stream. Dropping it shuts down the sending
/// side (the peer reads end-of-stream); dropping both closes the socket.
public struct WriteHalf: ~Copyable, Sendable {
    @usableFromInline let reg: IORegistration

    init(reg: IORegistration) { self.reg = reg }

    deinit {
        try? reg.shutdownWrite()
        reg.close()
    }

    // The writes are inlinable so that one the socket takes at once (nearly
    // all of them) costs the caller no async call: see `sendNow`.

    /// Write all of `buffer`'s readable bytes.
    @inlinable
    public func write(_ buffer: borrowing IOBuffer) async throws(IOError) {
        try await write(buffer.withUnsafeBytes { $0 })
    }

    /// Write all of `bytes`. They must stay valid until this returns.
    @inlinable
    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        var status: Int32 = 0
        let sent = reg.sendNow(bytes, &status)
        if status != 0 { try await reg.writeRest(bytes, sent: sent, status: status) }
    }
    /// Write all of `head`, then all of `body`, in one system call where the
    /// socket has room (a header and a payload, say).
    @inlinable
    public func write(_ head: borrowing IOBuffer, _ body: borrowing IOBuffer) async throws(IOError) {
        let a = head.withUnsafeBytes { $0 }, b = body.withUnsafeBytes { $0 }
        var status: Int32 = 0
        let sent = reg.sendNow(a, b, &status)
        if status != 0 { try await reg.writeRest(a, b, sent: sent, status: status) }
    }

    /// Write all of `parts` in order, gathered into as few system calls as
    /// possible. They must stay valid until this returns.
    @inlinable
    public func write(vectored parts: UnsafeBufferPointer<UnsafeRawBufferPointer>) async throws(IOError) {
        var status: Int32 = 0
        let sent = reg.sendNow(vectored: parts, &status)
        if status != 0 { try await reg.writeRest(vectored: parts, sent: sent, status: status) }
    }


    /// Send as much of `parts` as the socket takes now, without waiting:
    /// the bytes sent, which may be fewer than offered, or 0 if it is full.
    /// For code that must not suspend (a NIO channel's flush, say); send the
    /// rest with `write(vectored:)`. Always 0 on Network.framework.
    public func tryWrite(vectored parts: UnsafeBufferPointer<UnsafeRawBufferPointer>) throws(IOError) -> Int {
        try reg.trySend(parts: parts.count) { parts[$0] }
    }

    /// Stop sending now rather than when the half is dropped.
    public func shutdownWrite() throws(IOError) { try reg.shutdownWrite() }
}
#endif
