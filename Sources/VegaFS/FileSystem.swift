// POSIX for now; Windows comes with the IOCP driver.
#if os(Linux) || canImport(Darwin)
import CVega
import Vega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// One name in a directory.
public struct DirectoryEntry: Sendable, Hashable {
    /// The name, without the directory.
    public var name: String
    /// The directory's path joined with `name`.
    public var path: String
    /// What the name is, itself (a symbolic link is `.symbolicLink`).
    public var kind: FileKind
}

/// Operations on paths: Tokio's `tokio::fs` functions. Each runs on the
/// blocking pool (path lookups have no non-blocking form on any driver),
/// and runs to completion even if the caller is cancelled.
public enum FileSystem {
    // MARK: - Whole files

    /// The file's contents.
    public static func read(_ path: String) async throws(IOError) -> [UInt8] {
        try checkPath(path)
        return try await Runtime.blocking { () throws(IOError) -> [UInt8] in
            let fd = try posixOpen(path, O_RDONLY | O_CLOEXEC, 0)
            defer { _ = posixClose(fd) }
            // The size is a hint: the file may grow or shrink meanwhile, and
            // /proc files say 0.
            let hint = (try? posixFstat(fd)).map { Int($0.st_size) } ?? 0
            var bytes = [UInt8](repeating: 0, count: max(hint, 0) + 1)
            var count = 0
            while true {
                if count == bytes.count { bytes.append(contentsOf: repeatElement(0, count: max(bytes.count, 16 * 1024))) }
                // (withUnsafeMutableBytes rethrows untyped: carry the error out.)
                let n = try bytes.withUnsafeMutableBytes { raw in
                    Result { () throws(IOError) -> Int in
                        try posixRead(fd, raw.baseAddress! + count, raw.count - count, -1)
                    }
                }.get()
                if n == 0 { break }
                count += n
            }
            bytes.removeSubrange(count...)
            return bytes
        }
    }

    /// The file's contents as UTF-8 (invalid sequences repaired).
    public static func readString(_ path: String) async throws(IOError) -> String {
        String(decoding: try await read(path), as: UTF8.self)
    }

    /// Replace the file's contents with `bytes`, creating it if needed.
    public static func write(_ path: String, contents bytes: [UInt8]) async throws(IOError) {
        try checkPath(path)
        try await Runtime.blocking { () throws(IOError) in
            let fd = try posixOpen(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0o666)
            defer { _ = posixClose(fd) }
            try bytes.withUnsafeBytes { raw in
                Result { () throws(IOError) in
                    if let base = raw.baseAddress { try posixWriteAll(fd, base, raw.count, -1) }
                }
            }.get()
        }
    }

    public static func write(_ path: String, contents string: String) async throws(IOError) {
        try await write(path, contents: Array(string.utf8))
    }

    /// Copy the file at `source` to `destination`, replacing it, with the
    /// source's permissions. Returns the bytes copied.
    @discardableResult
    public static func copyFile(_ source: String, to destination: String) async throws(IOError) -> Int {
        try checkPath(source)
        try checkPath(destination)
        return try await Runtime.blocking { () throws(IOError) -> Int in
            let src = try posixOpen(source, O_RDONLY | O_CLOEXEC, 0)
            defer { _ = posixClose(src) }
            let st = try posixFstat(src)
            guard FileKind(mode: UInt32(st.st_mode)) == .file else { throw IOError(code: EINVAL) }
            let mode = UInt32(st.st_mode) & 0o7777
            let dst = try posixOpen(destination, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode)
            defer { _ = posixClose(dst) }
            let n = cv_copy_fd(src, dst)
            if n < 0 { throw IOError(code: Int32(-n)) }
            // An existing destination keeps its mode through O_CREAT.
            _ = try retrying { fchmod(dst, mode_t(mode)) }
            return Int(n)
        }
    }

    // MARK: - Metadata

    /// What `stat` (or, with `followingSymbolicLinks` false, `lstat`) says.
    public static func metadata(_ path: String, followingSymbolicLinks: Bool = true) async throws(IOError) -> FileMetadata {
        try checkPath(path)
        return try await Runtime.blocking { () throws(IOError) -> FileMetadata in
            FileMetadata(try posixStat(path, follow: followingSymbolicLinks))
        }
    }

    /// Whether `path` names something (following symbolic links). Errors
    /// other than "no such file" are thrown, not taken for false.
    public static func exists(_ path: String) async throws(IOError) -> Bool {
        do {
            _ = try await metadata(path)
            return true
        } catch where error.code == ENOENT || error.code == ENOTDIR {
            return false
        }
    }

    /// Set the permission bits (`chmod`).
    public static func setPermissions(_ path: String, _ permissions: UInt32) async throws(IOError) {
        try checkPath(path)
        try await Runtime.blocking { () throws(IOError) in
            _ = try retrying { chmod(path, mode_t(permissions)) }
        }
    }

    // MARK: - Names

    /// Remove a file (or a symbolic link, not what it points to).
    public static func removeFile(_ path: String) async throws(IOError) {
        try checkPath(path)
        try await Runtime.blocking { () throws(IOError) in
            _ = try retrying { unlink(path) }
        }
    }

    /// Rename `source` to `destination`, replacing it (rename(2): on one
    /// file system).
    public static func rename(_ source: String, to destination: String) async throws(IOError) {
        try checkPath(source)
        try checkPath(destination)
        try await Runtime.blocking { () throws(IOError) in
            _ = try retrying { sysRename(source, destination) }
        }
    }

    /// Make `link` another name for the file at `original`.
    public static func createHardLink(at link: String, to original: String) async throws(IOError) {
        try checkPath(link)
        try checkPath(original)
        try await Runtime.blocking { () throws(IOError) in
            _ = try retrying { sysLink(original, link) }
        }
    }

    /// Make `link` a symbolic link whose target is `target` (stored as
    /// given: a relative target is relative to the link's directory).
    public static func createSymbolicLink(at link: String, to target: String) async throws(IOError) {
        try checkPath(link)
        try checkPath(target)
        try await Runtime.blocking { () throws(IOError) in
            _ = try retrying { symlink(target, link) }
        }
    }

    /// A symbolic link's target, as stored.
    public static func readSymbolicLink(_ path: String) async throws(IOError) -> String {
        try checkPath(path)
        return try await Runtime.blocking { () throws(IOError) -> String in
            var size = 256
            while true {
                var buf = [CChar](repeating: 0, count: size)
                let n = try retrying { readlink(path, &buf, size) }
                if n < size {
                    return String(decoding: buf[..<n].map { UInt8(bitPattern: $0) }, as: UTF8.self)
                }
                size *= 2 // it may have been cut short
            }
        }
    }

    /// The absolute path with every symbolic link, `.` and `..` resolved
    /// (realpath). The path must exist.
    public static func canonicalPath(_ path: String) async throws(IOError) -> String {
        try checkPath(path)
        return try await Runtime.blocking { () throws(IOError) -> String in
            guard let resolved = realpath(path, nil) else { throw IOError(code: errno) }
            defer { free(resolved) }
            return String(cString: resolved)
        }
    }

    // MARK: - Directories

    /// Create a directory; with `intermediates`, its missing parents too,
    /// and no error if it exists already (`mkdir -p`).
    public static func createDirectory(_ path: String, intermediates: Bool = false,
                                       permissions: UInt32 = 0o777) async throws(IOError) {
        try checkPath(path)
        try await Runtime.blocking { () throws(IOError) in
            try makeDirectory(path, intermediates: intermediates, mode: permissions)
        }
    }

    /// Remove an empty directory; with `recursive`, everything in it first
    /// (`rm -r`: symbolic links inside are removed, not followed).
    public static func removeDirectory(_ path: String, recursive: Bool = false) async throws(IOError) {
        try checkPath(path)
        try await Runtime.blocking { () throws(IOError) in
            if recursive {
                try removeTree(path)
            } else {
                _ = try retrying { rmdir(path) }
            }
        }
    }

    /// The names in a directory, without `.` and `..`, in the order the file
    /// system gives them.
    public static func contentsOfDirectory(_ path: String) async throws(IOError) -> [DirectoryEntry] {
        try checkPath(path)
        return try await Runtime.blocking { () throws(IOError) -> [DirectoryEntry] in
            try listDirectory(path)
        }
    }

    /// Create a new, empty directory in the system's temporary directory
    /// (`$TMPDIR`, else /tmp), readable by its owner only. Returns its path.
    public static func createTemporaryDirectory(prefix: String = "vega-") async throws(IOError) -> String {
        try checkPath(prefix)
        return try await Runtime.blocking { () throws(IOError) -> String in
            var base = getenv("TMPDIR").map { String(cString: $0) } ?? "/tmp"
            while base.count > 1 && base.hasSuffix("/") { base.removeLast() }
            var template = Array("\(base)/\(prefix)XXXXXX".utf8CString)
            guard let made = mkdtemp(&template) else { throw IOError(code: errno) }
            return String(cString: made)
        }
    }
}

// MARK: - On the blocking pool

// rename(2) and link(2), under names FileSystem's own methods don't shadow.
private func sysRename(_ from: String, _ to: String) -> Int32 { rename(from, to) }
private func sysLink(_ from: String, _ to: String) -> Int32 { link(from, to) }

/// Whether `path` is a directory, or a link to one.
private func isDirectory(_ path: String) -> Bool {
    (try? posixStat(path, follow: true)).map { FileKind(mode: UInt32($0.st_mode)) } == .directory
}

private func makeDirectory(_ path: String, intermediates: Bool, mode: UInt32) throws(IOError) {
    if mkdir(path, mode_t(mode)) == 0 { return }
    let err = errno
    guard intermediates else { throw IOError(code: err) }
    switch err {
    case EEXIST:
        // Fine if it's a directory (or a link to one).
        if isDirectory(path) { return }
        throw IOError(code: EEXIST)
    case ENOENT:
        let parent = parentPath(path)
        guard !parent.isEmpty, parent != path else { throw IOError(code: ENOENT) }
        try makeDirectory(parent, intermediates: true, mode: mode)
        if mkdir(path, mode_t(mode)) == 0 { return }
        // Another process may have made it meanwhile.
        let again = errno
        if again == EEXIST && isDirectory(path) { return }
        throw IOError(code: again)
    default:
        throw IOError(code: err)
    }
}

/// `path` without its last component ("" when there's none).
private func parentPath(_ path: String) -> String {
    var p = Substring(path)
    while p.count > 1 && p.hasSuffix("/") { p.removeLast() }
    guard let slash = p.lastIndex(of: "/") else { return "" }
    if slash == p.startIndex { return "/" }
    return String(p[..<slash])
}

private func joined(_ directory: String, _ name: String) -> String {
    directory.hasSuffix("/") ? directory + name : directory + "/" + name
}

private func listDirectory(_ path: String) throws(IOError) -> [DirectoryEntry] {
    guard let dir = opendir(path) else { throw IOError(code: errno) }
    defer { closedir(dir) }
    var entries: [DirectoryEntry] = []
    while true {
        errno = 0
        guard let entry = readdir(dir) else {
            if errno != 0 { throw IOError(code: errno) }
            return entries
        }
        let name = withUnsafePointer(to: &entry.pointee.d_name) { field in
            // 256 bytes on Linux, 1024 on Darwin.
            field.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: field.pointee)) {
                String(cString: $0)
            }
        }
        if name == "." || name == ".." { continue }
        let full = joined(path, name)
        let kind = FileKind(direntType: entry.pointee.d_type)
            ?? (try? posixStat(full, follow: false)).map { FileKind(mode: UInt32($0.st_mode)) }
            ?? .unknown
        entries.append(DirectoryEntry(name: name, path: full, kind: kind))
    }
}

private func removeTree(_ path: String) throws(IOError) {
    let st = try posixStat(path, follow: false)
    guard FileKind(mode: UInt32(st.st_mode)) == .directory else {
        _ = try retrying { unlink(path) }
        return
    }
    for entry in try listDirectory(path) {
        if entry.kind == .directory {
            try removeTree(entry.path)
        } else {
            do {
                _ = try retrying { unlink(entry.path) }
            } catch where error.code == ENOENT {
                // Gone already.
            }
        }
    }
    _ = try retrying { rmdir(path) }
}
#endif
