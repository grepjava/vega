#if os(Linux)
import CVega
import Glibc

/// A listening TCP socket.
///
/// ```swift
/// let listener = try TCPListener.bind(port: 8080)
/// while true {
///     let stream = try await listener.accept()
///     rt.spawn { await serve(stream) }
/// }
/// ```
///
/// Sockets belong to the runtime whose task created them and must not
/// outlive it. Closing is dropping: the fd is closed when the value goes away.
public struct TCPListener: ~Copyable, Sendable {
    let reg: IORegistration

    /// Listen on `host` (an address or name; empty for all interfaces) and
    /// `port` (0 picks a free one). Call from a task on a Vega runtime.
    public static func bind(host: String = "", port: Int, backlog: Int = 1024,
                            reusePort: Bool = false) throws(IOError) -> TCPListener {
        let driver = try IODriver.current()
        var err: Int32 = 0
        let fd = cv_tcp_listen(host, Int32(port), Int32(backlog), reusePort ? 1 : 0, &err)
        guard fd >= 0 else { throw IOError(code: err) }
        return TCPListener(reg: try IORegistration(fd: fd, driver: driver))
    }

    deinit { reg.close() }

    /// The port the listener is bound to.
    public var localPort: Int { Int(cv_local_port(reg.fd)) }

    /// Wait for the next connection.
    public func accept() async throws(IOError) -> TCPStream {
        while true {
            var err: Int32 = 0
            let fd = cv_tcp_accept(reg.fd, &err)
            if fd >= 0 {
                await Runtime.consumeBudget()
                return TCPStream(reg: try IORegistration(fd: fd, driver: IODriver(raw: reg.driver)))
            }
            switch err {
            case EAGAIN, EWOULDBLOCK: try await reg.wait(CV_IO_READ)
            // The peer gave up before we got to it, or a signal: try the next.
            case EINTR, ECONNABORTED, EPROTO: continue
            default: throw IOError(code: err)
            }
        }
    }
}

/// A TCP connection. One task reads and writes it at a time (it is
/// `~Copyable`; split halves come later).
public struct TCPStream: ~Copyable, Sendable {
    let reg: IORegistration

    init(reg: IORegistration) { self.reg = reg }

    /// Connect to `host` (an address, or a name resolved with a blocking
    /// lookup) and `port`. Call from a task on a Vega runtime.
    public static func connect(host: String, port: Int) async throws(IOError) -> TCPStream {
        let driver = try IODriver.current()
        var err: Int32 = 0
        let fd = cv_tcp_connect(host, Int32(port), &err)
        guard fd >= 0 else { throw IOError(code: err) }
        let stream = TCPStream(reg: try IORegistration(fd: fd, driver: driver))
        if err == EINPROGRESS {
            try await stream.reg.wait(CV_IO_WRITE)
            let e = cv_socket_error(fd)
            if e != 0 { throw IOError(code: e) }
        }
        return stream
    }

    deinit { reg.close() }

    /// Read into `buffer`'s spare capacity. Returns the bytes read: 0 means
    /// the peer closed its side (or the buffer has no room left).
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        guard buffer.spareCapacity > 0 else { return 0 }
        let io = reg.io
        if io.pointee.read_drained != 0 {
            // The last read came up short, so the socket was empty: skip the
            // recv that would say EAGAIN and wait for the next event (Tokio
            // does the same). Data that arrived since has left READY.
            io.pointee.read_drained = 0
            if cv_io_take_ready(io, CV_IO_READ) == 0 { try await reg.wait(CV_IO_READ) }
        }
        while true {
            let want = buffer.spareCapacity
            let n = cv_recv(reg.fd, buffer.base + buffer.count, want)
            if n >= 0 {
                buffer.count += n
                if n > 0 && n < want { io.pointee.read_drained = 1 }
                await Runtime.consumeBudget()
                return n
            }
            let err = Int32(-n)
            switch err {
            case EAGAIN, EWOULDBLOCK: try await reg.wait(CV_IO_READ)
            case EINTR: continue
            default: throw IOError(code: err)
            }
        }
    }

    /// Write all of `buffer`'s readable bytes.
    public func write(_ buffer: borrowing IOBuffer) async throws(IOError) {
        try await write(UnsafeRawBufferPointer(start: buffer.base, count: buffer.count))
    }

    /// Write all of `bytes`. They must stay valid until this returns.
    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        var done = 0
        while done < bytes.count {
            let n = cv_send(reg.fd, bytes.baseAddress! + done, bytes.count - done)
            if n >= 0 {
                done += n
                continue
            }
            let err = Int32(-n)
            switch err {
            case EAGAIN, EWOULDBLOCK: try await reg.wait(CV_IO_WRITE)
            case EINTR: continue
            default: throw IOError(code: err)
            }
        }
        await Runtime.consumeBudget()
    }

    /// Stop sending: the peer reads end-of-stream once it has the rest.
    public func shutdownWrite() throws(IOError) {
        if shutdown(reg.fd, Int32(SHUT_WR)) != 0 { throw IOError(code: errno) }
    }
}

extension IODriver {
    /// The driver of the runtime running the caller.
    static func current() throws(IOError) -> IODriver {
        guard let s = Worker.currentScheduler else { throw .notOnRuntime }
        guard let d = s.driver else { throw .unsupported }
        return d
    }
}
#endif
