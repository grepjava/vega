// POSIX for now; Windows comes with the IOCP driver.
#if os(Linux) || canImport(Darwin)
import Vega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

// Thin syscall wrappers. At file scope, so File's own `read`, `write` and
// `close` don't shadow them, and so they retry EINTR in one place.

/// `body` until it doesn't fail with EINTR; -1 throws errno.
@inline(__always)
func retrying<T: FixedWidthInteger>(_ body: () -> T) throws(IOError) -> T {
    while true {
        let r = body()
        if r != -1 { return r }
        if errno != EINTR { throw IOError(code: errno) }
    }
}

/// A ring result: the value, or the error it carries.
@inline(__always)
func ringResult(_ res: Int64) throws(IOError) -> Int {
    if res >= 0 { return Int(res) }
    if res == -Int64(ECANCELED) { throw .cancelled }
    throw IOError(code: Int32(-res))
}

/// Paths go to C as NUL-terminated strings: one with a NUL inside can't.
@inline(__always)
func checkPath(_ path: String) throws(IOError) {
    if path.utf8.contains(0) { throw IOError(code: EINVAL) }
}

func posixOpen(_ path: String, _ flags: Int32, _ mode: UInt32) throws(IOError) -> Int32 {
    try retrying { open(path, flags, mode_t(mode)) }
}

func posixClose(_ fd: Int32) -> Int32 { close(fd) }

/// read(2) at the file position when `offset` < 0, else pread(2).
func posixRead(_ fd: Int32, _ buf: UnsafeMutableRawPointer, _ count: Int, _ offset: Int64) throws(IOError) -> Int {
    try retrying { offset < 0 ? read(fd, buf, count) : pread(fd, buf, count, off_t(offset)) }
}

/// Write all `count` bytes, at the file position when `offset` < 0.
func posixWriteAll(_ fd: Int32, _ buf: UnsafeRawPointer, _ count: Int, _ offset: Int64) throws(IOError) {
    var done = 0
    while done < count {
        let n = try retrying {
            offset < 0 ? write(fd, buf + done, count - done)
                       : pwrite(fd, buf + done, count - done, off_t(offset + Int64(done)))
        }
        if n == 0 { throw IOError(code: EIO) }
        done += n
    }
}

/// fsync, or fdatasync. Darwin's fsync doesn't reach the disk's own cache;
/// F_FULLFSYNC does (as Rust's `sync_all` uses there).
func posixSync(_ fd: Int32, dataOnly: Bool) throws(IOError) {
    #if canImport(Darwin)
    _ = try retrying { fcntl(fd, F_FULLFSYNC) }
    #else
    _ = try retrying { dataOnly ? fdatasync(fd) : fsync(fd) }
    #endif
}

func posixStat(_ path: String, follow: Bool) throws(IOError) -> stat {
    var st = stat()
    _ = try retrying { follow ? stat(path, &st) : lstat(path, &st) }
    return st
}

func posixFstat(_ fd: Int32) throws(IOError) -> stat {
    var st = stat()
    _ = try retrying { fstat(fd, &st) }
    return st
}
#endif
