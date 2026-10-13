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
extension IORegistration {
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
    let reg: IORegistration

    init(reg: IORegistration) { self.reg = reg }

    deinit { reg.close() }

    /// Read into `buffer`'s spare capacity. Returns the bytes read: 0 means
    /// the peer closed its side (or the buffer has no room left).
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        try await reg.read(into: &buffer)
    }
}

/// The writing half of a split stream. Dropping it shuts down the sending
/// side (the peer reads end-of-stream); dropping both closes the socket.
public struct WriteHalf: ~Copyable, Sendable {
    let reg: IORegistration

    init(reg: IORegistration) { self.reg = reg }

    deinit {
        try? reg.shutdownWrite()
        reg.close()
    }

    /// Write all of `buffer`'s readable bytes.
    public func write(_ buffer: borrowing IOBuffer) async throws(IOError) {
        try await reg.write(UnsafeRawBufferPointer(start: buffer.base, count: buffer.count))
    }

    /// Write all of `bytes`. They must stay valid until this returns.
    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        try await reg.write(bytes)
    }
    /// Write all of `head`, then all of `body`, in one system call where the
    /// socket has room (a header and a payload, say).
    public func write(_ head: borrowing IOBuffer, _ body: borrowing IOBuffer) async throws(IOError) {
        let a = UnsafeRawBufferPointer(start: head.base, count: head.count)
        let b = UnsafeRawBufferPointer(start: body.base, count: body.count)
        try await reg.write(parts: 2) { $0 == 0 ? a : b }
    }

    /// Write all of `parts` in order, gathered into as few system calls as
    /// possible. They must stay valid until this returns.
    public func write(vectored parts: UnsafeBufferPointer<UnsafeRawBufferPointer>) async throws(IOError) {
        try await reg.write(parts: parts.count) { parts[$0] }
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
