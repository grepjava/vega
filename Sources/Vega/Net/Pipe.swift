#if os(Linux) || canImport(Darwin)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// The read end of a pipe (or a FIFO, or a terminal): Tokio's
/// `pipe::Receiver`. A child process's stdout and stderr are these.
public struct PipeReader: ~Copyable, Sendable {
    let reg: IORegistration

    /// Take ownership of `descriptor`, making it non-blocking. Call from a
    /// task on a Vega runtime.
    public init(adopting descriptor: Int32) throws(IOError) {
        let driver = try IODriver.current()
        let e = cv_pipe_prepare(descriptor)
        if e != 0 {
            closeDescriptor(descriptor)
            throw IOError(code: e)
        }
        reg = try IORegistration(fd: descriptor, driver: driver)
    }

    deinit { reg.close() }

    /// The file descriptor, still owned by this value.
    public var descriptor: Int32 { reg.fd }

    /// Read into `buffer`'s spare capacity. Returns the bytes read: 0 once
    /// every writer has closed (or with a full buffer).
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        guard buffer.spareCapacity > 0 else { return 0 }
        let fd = reg.fd
        let n = try await reg.perform(CV_IO_READ) {
            cv_fd_read(fd, buffer.base + buffer.count, buffer.spareCapacity)
        }
        buffer.count += n
        return n
    }
}

/// The write end of a pipe: Tokio's `pipe::Sender`. A child process's
/// stdin is one. Writing after the reader has gone throws `.brokenPipe`
/// (never SIGPIPE).
public struct PipeWriter: ~Copyable, Sendable {
    let reg: IORegistration

    /// Take ownership of `descriptor`, making it non-blocking. Call from a
    /// task on a Vega runtime.
    public init(adopting descriptor: Int32) throws(IOError) {
        let driver = try IODriver.current()
        let e = cv_pipe_prepare(descriptor)
        if e != 0 {
            closeDescriptor(descriptor)
            throw IOError(code: e)
        }
        reg = try IORegistration(fd: descriptor, driver: driver)
    }

    deinit { reg.close() }

    /// The file descriptor, still owned by this value.
    public var descriptor: Int32 { reg.fd }

    /// Write all of `bytes`. They must stay valid until this returns.
    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        guard let base = bytes.baseAddress else { return }
        let fd = reg.fd
        var done = 0
        while done < bytes.count {
            done += try await reg.perform(CV_IO_WRITE) {
                cv_pipe_write(fd, base + done, bytes.count - done)
            }
        }
    }

    /// Write all of `buffer`'s readable bytes.
    public func write(_ buffer: borrowing IOBuffer) async throws(IOError) {
        try await write(UnsafeRawBufferPointer(start: buffer.base, count: buffer.count))
    }

    /// Close the pipe: the reader sees end of stream once it has the rest.
    public consuming func close() {}
}

/// A connected pipe (Swift has no tuples of `~Copyable` values).
@frozen
public struct PipePair: ~Copyable, Sendable {
    public var reader: PipeReader
    public var writer: PipeWriter
}

/// A new pipe, between tasks or to hand one end to a child process. Call
/// from a task on a Vega runtime.
public func makePipe() throws(IOError) -> PipePair {
    var fds: (Int32, Int32) = (-1, -1)
    let e = withUnsafeMutablePointer(to: &fds) {
        $0.withMemoryRebound(to: Int32.self, capacity: 2) { cv_pipe($0) }
    }
    guard e == 0 else { throw IOError(code: e) }
    let reader: PipeReader
    do {
        reader = try PipeReader(adopting: fds.0)
    } catch {
        closeDescriptor(fds.1)
        throw error
    }
    return PipePair(reader: reader, writer: try PipeWriter(adopting: fds.1))
}

/// An fd whose readability a task can wait for, for VegaProcess's pidfds.
/// Owns and closes the fd.
package struct ReadinessWatch: ~Copyable, Sendable {
    let reg: IORegistration

    /// Off a Vega runtime: `IOError.notOnRuntime`, and the fd is not taken.
    package init(adopting fd: Int32) throws(IOError) {
        let driver = try IODriver.current()
        reg = try IORegistration(fd: fd, driver: driver)
    }

    deinit { reg.close() }

    package var descriptor: Int32 { reg.fd }

    /// Wait until the fd reports readable (or an error or hang-up).
    package func readable() async throws(IOError) {
        try await reg.wait(CV_IO_READ)
    }
}

#if canImport(Darwin)
/// A child's exit that a task can wait for, through the runtime's kqueue
/// (EVFILT_PROC, NOTE_EXIT): VegaProcess's stand-in for a pidfd. It does not
/// reap the child.
package struct ProcessExitWatch: ~Copyable, Sendable {
    let reg: IORegistration
    let pid: Int32

    /// Off a Vega runtime: `IOError.notOnRuntime`. ESRCH: the child has
    /// exited already (reap it with waitpid).
    package init(pid: Int32) throws(IOError) {
        let driver = try IODriver.current()
        var err: Int32 = 0
        guard let raw = driver.raw, let io = cv_driver_watch_exit(raw, pid, &err) else {
            throw IOError(code: err == 0 ? ENOSYS : err)
        }
        reg = IORegistration(io: io, driver: driver)
        self.pid = pid
    }

    deinit { cv_driver_unwatch_exit(reg.driver, reg.io, pid) }

    /// Wait until the child has exited (at once if it has).
    package func exited() async throws(IOError) {
        try await reg.wait(CV_IO_READ)
    }
}

extension IORegistration {
    /// An io the driver made for something other than an fd.
    init(io: UnsafeMutablePointer<cv_io>, driver: IODriver) {
        self.io = io
        self.driver = driver.raw
        self.owner = driver.owner
    }
}
#endif
#endif
