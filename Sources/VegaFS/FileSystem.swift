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
///
/// On Windows, permissions are the read-only attribute: a mode without
/// write bits makes a file read-only, and metadata reports 0o444 or 0o666
/// (0o555 or 0o777 for a directory). Creating a symbolic link needs
/// developer mode or the privilege to.
public enum FileSystem {
    // MARK: - Whole files

    /// The file's contents.
    public static func read(_ path: String) async throws(IOError) -> [UInt8] {
        try checkPath(path)
        return try await Runtime.blocking { () throws(IOError) -> [UInt8] in
            let fd = try Sys.open(path, .reading)
            defer { _ = Sys.close(fd) }
            // The size is a hint: the file may grow or shrink meanwhile, and
            // /proc files say 0.
            let hint = (try? Sys.fstat(fd)).map(\.size) ?? 0
            var bytes = [UInt8](repeating: 0, count: max(hint, 0) + 1)
            var count = 0
            while true {
                if count == bytes.count { bytes.append(contentsOf: repeatElement(0, count: max(bytes.count, 16 * 1024))) }
                // (withUnsafeMutableBytes rethrows untyped: carry the error out.)
                let n = try bytes.withUnsafeMutableBytes { raw in
                    Result { () throws(IOError) -> Int in
                        try Sys.read(fd, raw.baseAddress! + count, raw.count - count, -1)
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
            let fd = try Sys.open(path, .replacing)
            defer { _ = Sys.close(fd) }
            try bytes.withUnsafeBytes { raw in
                Result { () throws(IOError) in
                    if let base = raw.baseAddress { try Sys.writeAll(fd, base, raw.count, -1) }
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
            try Sys.copy(source, destination)
        }
    }

    // MARK: - Metadata

    /// What `stat` (or, with `followingSymbolicLinks` false, `lstat`) says.
    public static func metadata(_ path: String, followingSymbolicLinks: Bool = true) async throws(IOError) -> FileMetadata {
        try checkPath(path)
        return try await Runtime.blocking { () throws(IOError) -> FileMetadata in
            try Sys.stat(path, follow: followingSymbolicLinks)
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
            try Sys.chmod(path, permissions)
        }
    }

    // MARK: - Names

    /// Remove a file (or a symbolic link, not what it points to).
    public static func removeFile(_ path: String) async throws(IOError) {
        try checkPath(path)
        try await Runtime.blocking { () throws(IOError) in
            try Sys.unlink(path)
        }
    }

    /// Rename `source` to `destination`, replacing it (rename(2): on one
    /// file system).
    public static func rename(_ source: String, to destination: String) async throws(IOError) {
        try checkPath(source)
        try checkPath(destination)
        try await Runtime.blocking { () throws(IOError) in
            try Sys.rename(source, destination)
        }
    }

    /// Make `link` another name for the file at `original`.
    public static func createHardLink(at link: String, to original: String) async throws(IOError) {
        try checkPath(link)
        try checkPath(original)
        try await Runtime.blocking { () throws(IOError) in
            try Sys.link(original, link)
        }
    }

    /// Make `link` a symbolic link whose target is `target` (stored as
    /// given: a relative target is relative to the link's directory).
    public static func createSymbolicLink(at link: String, to target: String) async throws(IOError) {
        try checkPath(link)
        try checkPath(target)
        try await Runtime.blocking { () throws(IOError) in
            try Sys.symlink(target, link)
        }
    }

    /// A symbolic link's target, as stored.
    public static func readSymbolicLink(_ path: String) async throws(IOError) -> String {
        try checkPath(path)
        return try await Runtime.blocking { () throws(IOError) -> String in
            try Sys.readlink(path)
        }
    }

    /// The absolute path with every symbolic link, `.` and `..` resolved
    /// (realpath). The path must exist.
    public static func canonicalPath(_ path: String) async throws(IOError) -> String {
        try checkPath(path)
        return try await Runtime.blocking { () throws(IOError) -> String in
            try Sys.realpath(path)
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
                try Sys.rmdir(path)
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
    /// (`$TMPDIR`, else /tmp; on Windows, %TEMP%), readable by its owner
    /// only on POSIX. Returns its path.
    public static func createTemporaryDirectory(prefix: String = "vega-") async throws(IOError) -> String {
        try checkPath(prefix)
        return try await Runtime.blocking { () throws(IOError) -> String in
            try Sys.temporaryDirectory(prefix: prefix)
        }
    }
}

// MARK: - On the blocking pool

/// Whether `path` is a directory, or a link to one.
private func isDirectory(_ path: String) -> Bool {
    (try? Sys.stat(path, follow: true))?.kind == .directory
}

private func makeDirectory(_ path: String, intermediates: Bool, mode: UInt32) throws(IOError) {
    let err = Sys.mkdir(path, mode)
    if err == 0 { return }
    guard intermediates else { throw IOError(code: err) }
    switch err {
    case EEXIST:
        // Fine if it's a directory (or a link to one).
        if isDirectory(path) { return }
        throw IOError(code: EEXIST)
    case ENOENT:
        let parent = parentPath(path)
        guard !parent.isEmpty, parent != path else { throw IOError(code: ENOENT) }
        // A parent that is there but isn't a directory: ENOTDIR, as POSIX
        // says it (Windows reports a missing path).
        if let kind = (try? Sys.stat(parent, follow: true))?.kind, kind != .directory {
            throw IOError(code: ENOTDIR)
        }
        try makeDirectory(parent, intermediates: true, mode: mode)
        let again = Sys.mkdir(path, mode)
        if again == 0 { return }
        // Another process may have made it meanwhile.
        if again == EEXIST && isDirectory(path) { return }
        throw IOError(code: again)
    default:
        throw IOError(code: err)
    }
}

/// Whether `c` separates path components here.
private func isSeparator(_ c: Character) -> Bool {
    #if os(Windows)
    c == "/" || c == "\\"
    #else
    c == "/"
    #endif
}

/// `path` without its last component ("" when there's none).
private func parentPath(_ path: String) -> String {
    var p = Substring(path)
    while p.count > 1, let last = p.last, isSeparator(last) { p.removeLast() }
    guard let slash = p.lastIndex(where: isSeparator) else { return "" }
    if slash == p.startIndex { return String(p[slash]) }
    #if os(Windows)
    // "C:\x" → "C:\", not the drive-relative "C:".
    if p.distance(from: p.startIndex, to: slash) == 2, p.dropFirst().first == ":" { return String(p[...slash]) }
    #endif
    return String(p[..<slash])
}

private func joined(_ directory: String, _ name: String) -> String {
    if let last = directory.last, isSeparator(last) { return directory + name }
    return directory + "/" + name
}

private func listDirectory(_ path: String) throws(IOError) -> [DirectoryEntry] {
    try Sys.list(path).map { entry in
        let full = joined(path, entry.name)
        let kind = entry.kind ?? (try? Sys.stat(full, follow: false))?.kind ?? .unknown
        return DirectoryEntry(name: entry.name, path: full, kind: kind)
    }
}

private func removeTree(_ path: String) throws(IOError) {
    guard try Sys.stat(path, follow: false).kind == .directory else {
        try Sys.unlink(path)
        return
    }
    for entry in try listDirectory(path) {
        if entry.kind == .directory {
            try removeTree(entry.path)
        } else {
            do {
                try Sys.unlink(entry.path)
            } catch where error.code == ENOENT {
                // Gone already.
            }
        }
    }
    try Sys.rmdir(path)
}
