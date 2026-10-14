#if os(Linux) || canImport(Darwin) || os(Windows)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// A listening Unix stream socket. The path must not exist yet, and is left
/// behind when the listener is dropped (remove it yourself, as with Tokio).
public struct UnixListener: ~Copyable, Sendable {
    let reg: IORegistration

    /// Call from a task on a Vega runtime.
    public static func bind(path: String, backlog: Int = 1024) throws(IOError) -> UnixListener {
        let driver = try IODriver.current()
        var err: Int32 = 0
        let fd = cv_unix_listen(path, Int32(backlog), &err)
        guard fd >= 0 else { throw IOError(code: err) }
        return UnixListener(reg: try IORegistration(fd: fd, driver: driver))
    }

    deinit { reg.close() }

    /// Wait for the next connection.
    public func accept() async throws(IOError) -> UnixStream {
        UnixStream(reg: try await reg.accept(cv_unix_accept))
    }
}

/// A Unix stream connection: the same API as `TCPStream`.
public struct UnixStream: ~Copyable, Sendable {
    let reg: IORegistration

    init(reg: IORegistration) { self.reg = reg }

    /// Call from a task on a Vega runtime.
    public static func connect(path: String) async throws(IOError) -> UnixStream {
        let driver = try IODriver.current()
        var err: Int32 = 0
        let fd = cv_unix_connect(path, &err)
        guard fd >= 0 else { throw IOError(code: err) }
        let stream = UnixStream(reg: try IORegistration(fd: fd, driver: driver))
        try await stream.reg.connected(err)
        return stream
    }

    /// Two connected streams (Swift has no tuples of `~Copyable` values).
    @frozen
    public struct Pair: ~Copyable, Sendable {
        public var first: UnixStream
        public var second: UnixStream
    }

    /// Two streams connected to each other. Call from a task on a Vega runtime.
    public static func pair() throws(IOError) -> Pair {
        let driver = try IODriver.current()
        var fds: (Int32, Int32) = (-1, -1)
        let e = withUnsafeMutablePointer(to: &fds) {
            $0.withMemoryRebound(to: Int32.self, capacity: 2) { cv_unix_pair($0) }
        }
        guard e == 0 else { throw IOError(code: e) }
        let a: IORegistration
        do { a = try IORegistration(fd: fds.0, driver: driver) } catch {
            closeDescriptor(fds.1)
            throw error
        }
        let first = UnixStream(reg: a)
        return Pair(first: first, second: UnixStream(reg: try IORegistration(fd: fds.1, driver: driver)))
    }

    deinit { reg.close() }

    /// Read into `buffer`'s spare capacity. Returns the bytes read: 0 means
    /// the peer closed its side (or the buffer has no room left).
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        try await reg.read(into: &buffer)
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


    /// Send up to `count` bytes of the open file `file` (a descriptor) from
    /// `offset`, without copying them through this process where the system
    /// allows (sendfile(2) on Linux and Darwin). Returns the bytes sent:
    /// `count`, or fewer when the file ends first. The file is not closed.
    public func sendFile(_ file: Int32, offset: Int64 = 0, count: Int) async throws(IOError) -> Int {
        try await reg.sendFile(file, offset: offset, count: count)
    }

    /// Stop sending: the peer reads end-of-stream once it has the rest.
    public func shutdownWrite() throws(IOError) { try reg.shutdownWrite() }

    /// Split into halves that different tasks can use at once (see
    /// `TCPStream.split()`).
    public consuming func split() -> SplitStream {
        let reg = self.reg
        discard self
        cv_io_split(reg.io)
        return SplitStream(reader: ReadHalf(reg: reg), writer: WriteHalf(reg: reg))
    }
}
#endif
