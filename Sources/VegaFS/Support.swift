import CVega
import Vega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

// The file system calls VegaFS makes, one function each, for POSIX and for
// Windows (Win32 handles in the descriptor, through CVega's cv_file_*).
// At file scope inside `Sys`, so File's own `read`, `write` and `close`
// don't shadow the C functions; POSIX calls retry EINTR here.

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

/// What to open a file for, before it becomes a platform's flags.
struct OpenRequest: Sendable {
    var read = false
    var write = false
    var append = false
    var create = false
    var exclusive = false
    var truncate = false
    var permissions: UInt32 = 0o666

    static let reading = OpenRequest(read: true)
    static let replacing = OpenRequest(write: true, create: true, truncate: true)

    #if !os(Windows)
    var posixFlags: Int32 {
        let writes = write || append
        var flags: Int32 = read && writes ? O_RDWR : writes ? O_WRONLY : O_RDONLY
        if append { flags |= O_APPEND }
        if create { flags |= O_CREAT }
        if exclusive { flags |= O_EXCL }
        if truncate { flags |= O_TRUNC }
        return flags | O_CLOEXEC
    }
    #endif
}

enum Sys {
    #if !os(Windows)
    /// `body` until it doesn't fail with EINTR; -1 throws errno.
    @inline(__always)
    static func retrying<T: FixedWidthInteger>(_ body: () -> T) throws(IOError) -> T {
        while true {
            let r = body()
            if r != -1 { return r }
            if errno != EINTR { throw IOError(code: errno) }
        }
    }
    #endif

    /// 0, or the errno value of a failure.
    @inline(__always)
    private static func check(_ e: Int32) throws(IOError) {
        if e != 0 { throw IOError(code: e) }
    }

    static func open(_ path: String, _ request: OpenRequest) throws(IOError) -> Int32 {
        #if os(Windows)
        var flags: Int32 = 0
        if request.read { flags |= CV_FILE_READ }
        if request.write { flags |= CV_FILE_WRITE }
        if request.append { flags |= CV_FILE_APPEND }
        if request.create { flags |= CV_FILE_CREATE }
        if request.exclusive { flags |= CV_FILE_EXCL }
        if request.truncate { flags |= CV_FILE_TRUNC }
        var fd: Int32 = -1
        try check(cv_file_open(path, flags, request.permissions, &fd))
        return fd
        #else
        let flags = request.posixFlags
        return try retrying { Glibc_open(path, flags, mode_t(request.permissions)) }
        #endif
    }

    /// 0, or the errno value close reported (the descriptor is gone either way).
    static func close(_ fd: Int32) -> Int32 {
        #if os(Windows)
        return cv_file_close(fd)
        #else
        if Glibc_close(fd) == 0 { return 0 }
        return errno == EINTR ? 0 : errno
        #endif
    }

    /// At the position (advancing it) when `offset` < 0, else at `offset`.
    static func read(_ fd: Int32, _ buf: UnsafeMutableRawPointer, _ count: Int, _ offset: Int64) throws(IOError) -> Int {
        #if os(Windows)
        let n = cv_file_read(fd, buf, count, offset)
        if n < 0 { throw IOError(code: Int32(-n)) }
        return n
        #else
        return try retrying { offset < 0 ? Glibc_read(fd, buf, count) : pread(fd, buf, count, off_t(offset)) }
        #endif
    }

    /// Write all `count` bytes, at the position when `offset` < 0.
    static func writeAll(_ fd: Int32, _ buf: UnsafeRawPointer, _ count: Int, _ offset: Int64) throws(IOError) {
        var done = 0
        while done < count {
            let at = offset < 0 ? offset : offset + Int64(done)
            #if os(Windows)
            let n = cv_file_write(fd, buf + done, count - done, at)
            if n < 0 { throw IOError(code: Int32(-n)) }
            #else
            let n = try retrying {
                at < 0 ? Glibc_write(fd, buf + done, count - done) : pwrite(fd, buf + done, count - done, off_t(at))
            }
            #endif
            if n == 0 { throw IOError(code: EIO) }
            done += n
        }
    }

    /// whence: 0 from the start, 1 from the position, 2 from the end.
    static func seek(_ fd: Int32, _ offset: Int, _ whence: Int32) throws(IOError) -> Int {
        #if os(Windows)
        let n = cv_file_seek(fd, Int64(offset), whence)
        if n < 0 { throw IOError(code: Int32(-n)) }
        return Int(n)
        #else
        let w = whence == 0 ? SEEK_SET : whence == 1 ? SEEK_CUR : SEEK_END
        return Int(try retrying { lseek(fd, off_t(offset), w) })
        #endif
    }

    /// fsync, or fdatasync. Darwin's fsync doesn't reach the disk's own
    /// cache; F_FULLFSYNC does (as Rust's `sync_all` uses there). Windows
    /// has one: FlushFileBuffers.
    static func sync(_ fd: Int32, dataOnly: Bool) throws(IOError) {
        #if os(Windows)
        try check(cv_file_sync(fd))
        #elseif canImport(Darwin)
        _ = try retrying { fcntl(fd, F_FULLFSYNC) }
        #else
        _ = try retrying { dataOnly ? fdatasync(fd) : fsync(fd) }
        #endif
    }

    static func setLength(_ fd: Int32, _ length: Int) throws(IOError) {
        #if os(Windows)
        try check(cv_file_set_length(fd, Int64(length)))
        #else
        _ = try retrying { ftruncate(fd, off_t(length)) }
        #endif
    }

    static func fstat(_ fd: Int32) throws(IOError) -> FileMetadata {
        #if os(Windows)
        var st = cv_file_stat()
        try check(cv_file_fstat(fd, &st))
        return FileMetadata(st)
        #else
        var st = Glibc_stat()
        _ = try retrying { Glibc_fstat(fd, &st) }
        return FileMetadata(st)
        #endif
    }

    static func stat(_ path: String, follow: Bool) throws(IOError) -> FileMetadata {
        #if os(Windows)
        var st = cv_file_stat()
        try check(cv_file_stat_path(path, follow ? 1 : 0, &st))
        return FileMetadata(st)
        #else
        var st = Glibc_stat()
        _ = try retrying { follow ? Glibc_statPath(path, &st) : lstat(path, &st) }
        return FileMetadata(st)
        #endif
    }

    static func chmod(_ fd: Int32, _ permissions: UInt32) throws(IOError) {
        #if os(Windows)
        try check(cv_file_chmod(fd, permissions))
        #else
        _ = try retrying { fchmod(fd, mode_t(permissions)) }
        #endif
    }

    static func chmod(_ path: String, _ permissions: UInt32) throws(IOError) {
        #if os(Windows)
        try check(cv_fs_chmod(path, permissions))
        #else
        _ = try retrying { Glibc_chmod(path, mode_t(permissions)) }
        #endif
    }

    static func duplicate(_ fd: Int32) throws(IOError) -> Int32 {
        #if os(Windows)
        var out: Int32 = -1
        try check(cv_file_dup(fd, &out))
        return out
        #else
        return try retrying { fcntl(fd, F_DUPFD_CLOEXEC, 0) }
        #endif
    }

    /// 0, or the errno value (the caller decides what EEXIST means).
    static func mkdir(_ path: String, _ permissions: UInt32) -> Int32 {
        #if os(Windows)
        return cv_fs_mkdir(path)
        #else
        return Glibc_mkdir(path, mode_t(permissions)) == 0 ? 0 : errno
        #endif
    }

    static func rmdir(_ path: String) throws(IOError) {
        #if os(Windows)
        try check(cv_fs_rmdir(path))
        #else
        _ = try retrying { Glibc_rmdir(path) }
        #endif
    }

    static func unlink(_ path: String) throws(IOError) {
        #if os(Windows)
        try check(cv_fs_unlink(path))
        #else
        _ = try retrying { Glibc_unlink(path) }
        #endif
    }

    static func rename(_ from: String, _ to: String) throws(IOError) {
        #if os(Windows)
        try check(cv_fs_rename(from, to))
        #else
        _ = try retrying { Glibc_rename(from, to) }
        #endif
    }

    static func link(_ existing: String, _ link: String) throws(IOError) {
        #if os(Windows)
        try check(cv_fs_link(existing, link))
        #else
        _ = try retrying { Glibc_link(existing, link) }
        #endif
    }

    static func symlink(_ target: String, _ link: String) throws(IOError) {
        #if os(Windows)
        try check(cv_fs_symlink(target, link))
        #else
        _ = try retrying { Glibc_symlink(target, link) }
        #endif
    }

    static func readlink(_ path: String) throws(IOError) -> String {
        var size = 256
        while true {
            var buf = [CChar](repeating: 0, count: size)
            #if os(Windows)
            let n = Int(cv_fs_readlink(path, &buf, Int32(size)))
            if n < 0 {
                if -n == ENAMETOOLONG && size < 1 << 16 { size *= 4; continue }
                throw IOError(code: Int32(-n))
            }
            return String(decoding: buf[..<n].map { UInt8(bitPattern: $0) }, as: UTF8.self)
            #else
            let n = try retrying { Glibc_readlink(path, &buf, size) }
            if n < size {
                return String(decoding: buf[..<n].map { UInt8(bitPattern: $0) }, as: UTF8.self)
            }
            size *= 2 // it may have been cut short
            #endif
        }
    }

    static func realpath(_ path: String) throws(IOError) -> String {
        #if os(Windows)
        var buf = [CChar](repeating: 0, count: 32768 * 3)
        let n = cv_fs_realpath(path, &buf, Int32(buf.count))
        if n < 0 { throw IOError(code: -n) }
        return String(cString: buf)
        #else
        guard let resolved = Glibc_realpath(path, nil) else { throw IOError(code: errno) }
        defer { free(resolved) }
        return String(cString: resolved)
        #endif
    }

    /// The names in a directory (no `.` or `..`) and what each is, itself.
    static func list(_ path: String) throws(IOError) -> [(name: String, kind: FileKind?)] {
        #if os(Windows)
        var entries: UnsafeMutablePointer<cv_dir_entry>?
        var count: Int32 = 0
        try check(cv_fs_list(path, &entries, &count))
        defer { cv_fs_list_free(entries, count) }
        return (0..<Int(count)).map { i in
            let e = entries![i]
            return (String(cString: e.name), FileKind(windowsKind: e.kind))
        }
        #else
        guard let dir = opendir(path) else { throw IOError(code: errno) }
        defer { closedir(dir) }
        var out: [(name: String, kind: FileKind?)] = []
        while true {
            errno = 0
            guard let entry = readdir(dir) else {
                if errno != 0 { throw IOError(code: errno) }
                return out
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) { field in
                // 256 bytes on Linux, 1024 on Darwin.
                field.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: field.pointee)) {
                    String(cString: $0)
                }
            }
            if name == "." || name == ".." { continue }
            out.append((name, FileKind(direntType: entry.pointee.d_type)))
        }
        #endif
    }

    /// A new directory in the system's temporary directory.
    static func temporaryDirectory(prefix: String) throws(IOError) -> String {
        #if os(Windows)
        var buf = [CChar](repeating: 0, count: 2048)
        try check(cv_fs_temp_dir(prefix, &buf, Int32(buf.count)))
        return String(cString: buf)
        #else
        var base = getenv("TMPDIR").map { String(cString: $0) } ?? "/tmp"
        while base.count > 1 && base.hasSuffix("/") { base.removeLast() }
        var template = Array("\(base)/\(prefix)XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw IOError(code: errno) }
        return String(cString: made)
        #endif
    }

    /// Copy a regular file over `destination`, with the source's permissions.
    static func copy(_ source: String, _ destination: String) throws(IOError) -> Int {
        #if os(Windows)
        guard try stat(source, follow: true).kind == .file else { throw IOError(code: EINVAL) }
        let n = cv_fs_copy(source, destination)
        if n < 0 { throw IOError(code: Int32(-n)) }
        return Int(n)
        #else
        let src = try open(source, .reading)
        defer { _ = close(src) }
        let st = try fstat(src)
        guard st.kind == .file else { throw IOError(code: EINVAL) }
        var request = OpenRequest.replacing
        request.permissions = st.permissions
        let dst = try open(destination, request)
        defer { _ = close(dst) }
        let n = cv_copy_fd(src, dst)
        if n < 0 { throw IOError(code: Int32(-n)) }
        // An existing destination keeps its mode through O_CREAT.
        try chmod(dst, st.permissions)
        return Int(n)
        #endif
    }
}

#if !os(Windows)
// The C functions under names Sys's own don't shadow.
private func Glibc_open(_ path: String, _ flags: Int32, _ mode: mode_t) -> Int32 { open(path, flags, mode) }
private func Glibc_close(_ fd: Int32) -> Int32 { close(fd) }
private func Glibc_read(_ fd: Int32, _ buf: UnsafeMutableRawPointer, _ n: Int) -> Int { read(fd, buf, n) }
private func Glibc_write(_ fd: Int32, _ buf: UnsafeRawPointer, _ n: Int) -> Int { write(fd, buf, n) }
private typealias Glibc_stat = stat
private func Glibc_fstat(_ fd: Int32, _ st: inout stat) -> Int32 { fstat(fd, &st) }
private func Glibc_statPath(_ path: String, _ st: inout stat) -> Int32 { stat(path, &st) }
private func Glibc_chmod(_ path: String, _ mode: mode_t) -> Int32 { chmod(path, mode) }
private func Glibc_mkdir(_ path: String, _ mode: mode_t) -> Int32 { mkdir(path, mode) }
private func Glibc_rmdir(_ path: String) -> Int32 { rmdir(path) }
private func Glibc_unlink(_ path: String) -> Int32 { unlink(path) }
private func Glibc_rename(_ from: String, _ to: String) -> Int32 { rename(from, to) }
private func Glibc_link(_ from: String, _ to: String) -> Int32 { link(from, to) }
private func Glibc_symlink(_ target: String, _ link: String) -> Int32 { symlink(target, link) }
private func Glibc_readlink(_ path: String, _ buf: UnsafeMutablePointer<CChar>, _ n: Int) -> Int { readlink(path, buf, n) }
private func Glibc_realpath(_ path: String, _ resolved: UnsafeMutablePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    realpath(path, resolved)
}
#endif
