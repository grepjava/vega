import Vega
import VegaIO
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
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

        /// The open(2) flags, or EINVAL for a combination that makes no sense.
        var flags: Int32 {
            get throws(IOError) {
                let writes = write || append
                var flags: Int32
                switch (read, writes) {
                case (true, false): flags = O_RDONLY
                case (false, true): flags = O_WRONLY
                case (true, true): flags = O_RDWR
                case (false, false): throw IOError(code: EINVAL)
                }
                if append { flags |= O_APPEND }
                if createNew {
                    guard writes else { throw IOError(code: EINVAL) }
                    flags |= O_CREAT | O_EXCL
                } else {
                    if truncate {
                        guard write, !append else { throw IOError(code: EINVAL) }
                        flags |= O_TRUNC
                    }
                    if create {
                        guard writes else { throw IOError(code: EINVAL) }
                        flags |= O_CREAT
                    }
                }
                return flags | O_CLOEXEC
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

    deinit { _ = posixClose(descriptor) }

    /// Open `path` with `options` (read only by default).
    public static func open(_ path: String, options: Options = .reading) async throws(IOError) -> File {
        try checkPath(path)
        let flags = try options.flags
        let mode = options.permissions
        // The ring reads the path until the open completes, which the call
        // waits for even when cancelled.
        let cpath = strdup(path)!
        defer { free(cpath) }
        if let res = await FileIO.open(cpath, flags: flags, mode: mode) {
            return File(adopting: Int32(try ringResult(res)))
        }
        return File(adopting: try await Runtime.blocking { () throws(IOError) -> Int32 in
            try posixOpen(path, flags, mode)
        })
    }

    /// Create `path` for writing, emptying it if it exists.
    public static func create(_ path: String, permissions: UInt32 = 0o666) async throws(IOError) -> File {
        var options = Options.creating
        options.permissions = permissions
        return try await open(path, options: options)
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
                try posixRead(fd, dst, want, offset)
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
                    try posixWriteAll(fd, rest, left, at)
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
        case .start(let n): (n, SEEK_SET)
        case .current(let n): (n, SEEK_CUR)
        case .end(let n): (n, SEEK_END)
        }
        let fd = descriptor
        return Int(try retrying { lseek(fd, off_t(offset), whence) })
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
        try await Runtime.blocking { () throws(IOError) in try posixSync(fd, dataOnly: dataOnly) }
    }

    public func metadata() async throws(IOError) -> FileMetadata {
        let fd = descriptor
        return try await Runtime.blocking { () throws(IOError) -> FileMetadata in
            FileMetadata(try posixFstat(fd))
        }
    }

    /// Truncate or extend (with zeros) the file to `length` bytes.
    public func setLength(_ length: Int) async throws(IOError) {
        let fd = descriptor
        try await Runtime.blocking { () throws(IOError) in
            _ = try retrying { ftruncate(fd, off_t(length)) }
        }
    }

    /// Set the permission bits (`chmod`).
    public func setPermissions(_ permissions: UInt32) async throws(IOError) {
        let fd = descriptor
        try await Runtime.blocking { () throws(IOError) in
            _ = try retrying { fchmod(fd, mode_t(permissions)) }
        }
    }

    /// A second descriptor for the same open file, sharing its position.
    public func duplicate() throws(IOError) -> File {
        let fd = descriptor
        return File(adopting: try retrying { fcntl(fd, F_DUPFD_CLOEXEC, 0) })
    }

    /// Close the file, reporting an error close(2) returns (some file
    /// systems report failed writes only there). The descriptor is released
    /// either way.
    public consuming func close() throws(IOError) {
        let fd = descriptor
        discard self
        if posixClose(fd) != 0 && errno != EINTR { throw IOError(code: errno) }
    }
}

extension File: AsyncReader, AsyncWriter {}
