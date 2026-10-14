import Vega
import VegaIO
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// An open file: Tokio's `tokio::fs::File`.
///
/// ```swift
/// let file = try await File.open("/etc/hosts")
/// var buf = IOBuffer(capacity: 4096)
/// while try await file.read(into: &buf) > 0 { ... }
/// ```
///
/// On the io_uring driver, reads, writes, syncs and opens go through the
/// running worker's ring. Elsewhere (the readiness drivers, or a task off
/// Vega's workers) each runs on the blocking pool, so a slow disk never
/// stalls a worker thread.
///
/// Cancelling a task abandons a ring operation where the kernel allows
/// (`IOError.cancelled`); one on the blocking pool always finishes first.
/// Either way the buffer is never written after the call returns.
///
/// The file is closed when the value is dropped, or with `close()`, which
/// reports errors a deferred write may surface there.
public struct File: ~Copyable, Sendable {
    /// How to open a file: Rust's `OpenOptions`. At least one of `read`,
    /// `write` and `append` must be set.
    public struct Options: Sendable, Hashable {
        public var read: Bool
        public var write: Bool
        /// Every write goes to the end of the file.
        public var append: Bool
        /// Empty the file on open. Needs `write`, and not `append`.
        public var truncate: Bool
        /// Create the file if it doesn't exist. Needs `write` or `append`.
        public var create: Bool
        /// Create the file, failing with EEXIST if it exists (`create` and
        /// `truncate` are then ignored).
        public var createNew: Bool
        /// The mode of a file this creates, before the umask.
        public var permissions: UInt32

        public init(read: Bool = false, write: Bool = false, append: Bool = false,
                    truncate: Bool = false, create: Bool = false, createNew: Bool = false,
                    permissions: UInt32 = 0o666) {
            self.read = read
            self.write = write
            self.append = append
            self.truncate = truncate
            self.create = create
            self.createNew = createNew
            self.permissions = permissions
        }

        /// Read only.
        public static let reading = Options(read: true)
        /// Write, creating or emptying the file.
        public static let creating = Options(write: true, truncate: true, create: true)
        /// Append, creating the file if needed.
        public static let appending = Options(append: true, create: true)

        /// What to open for, or EINVAL for a combination that makes no sense.
        var request: OpenRequest {
            get throws(IOError) {
                let writes = write || append
                guard read || writes else { throw IOError(code: EINVAL) }
                var r = OpenRequest(read: read, write: write, append: append, permissions: permissions)
                if createNew {
                    guard writes else { throw IOError(code: EINVAL) }
                    r.create = true
                    r.exclusive = true
                } else {
                    if truncate {
                        guard write, !append else { throw IOError(code: EINVAL) }
                        r.truncate = true
                    }
                    if create {
                        guard writes else { throw IOError(code: EINVAL) }
                        r.create = true
                    }
                }
                return r
            }
        }
    }

    /// Where `seek` moves the file position from.
    public enum SeekOrigin: Sendable, Hashable {
        case start(Int)
        case current(Int)
        case end(Int)
    }

    /// The file descriptor, owned by this value.
    public let descriptor: Int32

    /// Take ownership of an open descriptor.
    public init(adopting descriptor: Int32) {
        self.descriptor = descriptor
    }

    deinit { _ = Sys.close(descriptor) }

    /// Open `path` with `options` (read only by default).
    public static func open(_ path: String, options: Options = .reading) async throws(IOError) -> File {
        try checkPath(path)
        let request = try options.request
        #if !os(Windows)
        // The ring reads the path until the open completes, which the call
        // waits for even when cancelled.
        let cpath = strdup(path)!
        defer { free(cpath) }
        if let res = await FileIO.open(cpath, flags: request.posixFlags, mode: request.permissions) {
            return File(adopting: Int32(try ringResult(res)))
        }
        #endif
        return File(adopting: try await Runtime.blocking { () throws(IOError) -> Int32 in
            try Sys.open(path, request)
        })
    }

    /// Create `path` for writing, emptying it if it exists.
    public static func create(_ path: String, permissions: UInt32 = 0o666) async throws(IOError) -> File {
        var options = Options.creating
        options.permissions = permissions
        return try await open(path, options: options)
    }

    // MARK: - Beneath a directory

    /// Open the regular file `path` names beneath the directory `root`, for
    /// reading, refusing one that resolves outside it -- through `..`, or a
    /// symbolic link -- with ENOENT, as if it were not there: `path` came
    /// from a client, and must not reach the rest of the file system. A
    /// symbolic link that stays inside is followed. A directory is EISDIR,
    /// and anything else that is not a regular file ENOENT.
    ///
    /// On Linux the kernel decides containment as it resolves (openat2 with
    /// RESOLVE_BENEATH), so nothing can be swapped between the check and the
    /// open; elsewhere, and for an absolute symbolic link, both paths are
    /// resolved and compared first.
    ///
    /// Synchronous, on the calling thread: a server answering from a
    /// directory of assets makes the few system calls this takes against the
    /// kernel's caches, cheaper than handing them to another thread.
    public static func open(beneath root: String, _ path: String) throws(IOError) -> File {
        try checkPath(root)
        try checkPath(path)
        var fd = Int32(cv_open_beneath(root, path))
        if fd == -ENOSYS || fd == -EXDEV {
            fd = try openResolving(root, path)
        } else if fd < 0 {
            // Outside the root is as good as absent.
            throw IOError(code: -fd)
        }
        let file = File(adopting: fd)
        let kind = try Sys.fstat(fd).kind
        if kind != .file { throw IOError(code: kind == .directory ? EISDIR : ENOENT) }
        return file
    }

    /// `open(beneath:)` by resolving both paths and comparing them.
    static func openResolving(_ root: String, _ path: String) throws(IOError) -> Int32 {
        let base = try Sys.realpath(root)
        var relative = Substring(path)
        while relative.first == "/" || relative.first == "\\" { relative = relative.dropFirst() }
        let resolved = try Sys.realpath(base + "/" + relative)
        // The resolved path is the root, or under it at a separator: a root
        // of /var/www does not take in /var/www-old.
        guard resolved.hasPrefix(base) else { throw IOError(code: ENOENT) }
        let rest = resolved.utf8.dropFirst(base.utf8.count)
        if let next = rest.first, next != UInt8(ascii: "/") && next != UInt8(ascii: "\\"),
           base.utf8.last != UInt8(ascii: "/") && base.utf8.last != UInt8(ascii: "\\") {
            throw IOError(code: ENOENT)
        }
        return try Sys.open(resolved, .reading)
    }

    /// The file's metadata, read on the calling thread: fstat of an open
    /// file waits on no disk.
    public func metadataNow() throws(IOError) -> FileMetadata {
        try Sys.fstat(descriptor)
    }

    /// Reads into `buffer` from `offset` on the calling thread: for a small
    /// file likely in the page cache, where handing the read to the ring or
    /// another thread costs more than it does. Returns the bytes read, 0 at
    /// the end of the file.
    public func readNow(into buffer: UnsafeMutableRawBufferPointer, at offset: Int) throws(IOError) -> Int {
        guard let base = buffer.baseAddress, buffer.count > 0 else { return 0 }
        return try Sys.read(descriptor, base, buffer.count, Int64(offset))
    }

    // MARK: - Reading

    /// Read into `buffer`'s spare capacity at the file position, advancing
    /// it. Returns the bytes read: 0 at end of file (or with a full buffer).
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        try await read(into: &buffer, offset: -1)
    }

    /// Read into `buffer`'s spare capacity from `offset`, leaving the file
    /// position alone (pread).
    public func read(into buffer: inout IOBuffer, at offset: Int) async throws(IOError) -> Int {
        guard offset >= 0 else { throw IOError(code: EINVAL) }
        return try await read(into: &buffer, offset: Int64(offset))
    }

    /// Read from the file position to the end, growing `buffer` as needed.
    /// Returns the bytes read.
    @discardableResult
    public func readToEnd(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        var total = 0
        while true {
            if buffer.spareCapacity < 4096 {
                buffer.reserveCapacity(max(buffer.capacity * 2, buffer.count + 16 * 1024))
            }
            let n = try await read(into: &buffer)
            if n == 0 { return total }
            total += n
        }
    }

    private func read(into buffer: inout IOBuffer, offset: Int64) async throws(IOError) -> Int {
        let want = buffer.spareCapacity
        guard want > 0 else { return 0 }
        let fd = descriptor
        let n: Int
        if let res = await FileIO.read(fd, into: buffer.spareBytes, count: want, at: offset) {
            n = try ringResult(res)
        } else {
            nonisolated(unsafe) let dst = buffer.spareBytes
            n = try await Runtime.blocking { () throws(IOError) -> Int in
                try Sys.read(fd, dst, want, offset)
            }
        }
        buffer.count += n
        return n
    }

    // MARK: - Writing

    /// Write all of `bytes` at the file position (the end, when opened to
    /// append), advancing it.
    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        try await write(bytes, offset: -1)
    }

    /// Write all of `buffer`'s readable bytes at the file position.
    public func write(_ buffer: borrowing IOBuffer) async throws(IOError) {
        let bytes = buffer.withUnsafeBytes { $0 }
        try await write(bytes, offset: -1)
    }

    /// Write all of `bytes` at `offset`, leaving the file position alone
    /// (pwrite).
    public func write(_ bytes: UnsafeRawBufferPointer, at offset: Int) async throws(IOError) {
        guard offset >= 0 else { throw IOError(code: EINVAL) }
        try await write(bytes, offset: Int64(offset))
    }

    public func write(_ buffer: borrowing IOBuffer, at offset: Int) async throws(IOError) {
        let bytes = buffer.withUnsafeBytes { $0 }
        try await write(bytes, at: offset)
    }

    private func write(_ bytes: UnsafeRawBufferPointer, offset: Int64) async throws(IOError) {
        guard let base = bytes.baseAddress, bytes.count > 0 else { return }
        let fd = descriptor, count = bytes.count
        var done = 0
        while done < count {
            let at = offset < 0 ? -1 : offset + Int64(done)
            guard let res = await FileIO.write(fd, from: base + done, count: count - done, at: at) else {
                // Not on a ring: the rest in one trip to the blocking pool.
                nonisolated(unsafe) let rest = base + done
                let left = count - done
                try await Runtime.blocking { () throws(IOError) in
                    try Sys.writeAll(fd, rest, left, at)
                }
                return
            }
            let n = try ringResult(res)
            if n == 0 { throw IOError(code: EIO) }
            done += n
        }
    }

    // MARK: - The rest

    /// Move the file position; returns it, from the start.
    @discardableResult
    public func seek(_ origin: SeekOrigin) throws(IOError) -> Int {
        let (offset, whence): (Int, Int32) = switch origin {
        case .start(let n): (n, 0)
        case .current(let n): (n, 1)
        case .end(let n): (n, 2)
        }
        return try Sys.seek(descriptor, offset, whence)
    }

    /// Flush the file's data and metadata to the device (fsync).
    public func sync() async throws(IOError) {
        try await sync(dataOnly: false)
    }

    /// Flush the file's data, and only the metadata needed to read it back
    /// (fdatasync).
    public func syncData() async throws(IOError) {
        try await sync(dataOnly: true)
    }

    private func sync(dataOnly: Bool) async throws(IOError) {
        let fd = descriptor
        #if !canImport(Darwin)
        if let res = await FileIO.sync(fd, dataOnly: dataOnly) {
            _ = try ringResult(res)
            return
        }
        #endif
        try await Runtime.blocking { () throws(IOError) in try Sys.sync(fd, dataOnly: dataOnly) }
    }

    public func metadata() async throws(IOError) -> FileMetadata {
        let fd = descriptor
        return try await Runtime.blocking { () throws(IOError) -> FileMetadata in
            try Sys.fstat(fd)
        }
    }

    /// Truncate or extend (with zeros) the file to `length` bytes.
    public func setLength(_ length: Int) async throws(IOError) {
        let fd = descriptor
        try await Runtime.blocking { () throws(IOError) in
            try Sys.setLength(fd, length)
        }
    }

    /// Set the permission bits (`chmod`).
    public func setPermissions(_ permissions: UInt32) async throws(IOError) {
        let fd = descriptor
        try await Runtime.blocking { () throws(IOError) in
            try Sys.chmod(fd, permissions)
        }
    }

    /// A second descriptor for the same open file, sharing its position.
    public func duplicate() throws(IOError) -> File {
        let fd = descriptor
        return File(adopting: try Sys.duplicate(fd))
    }

    /// Close the file, reporting an error close(2) returns (some file
    /// systems report failed writes only there). The descriptor is released
    /// either way.
    public consuming func close() throws(IOError) {
        let fd = descriptor
        discard self
        let e = Sys.close(fd)
        if e != 0 { throw IOError(code: e) }
    }
}

extension File: AsyncReader, AsyncWriter {}
