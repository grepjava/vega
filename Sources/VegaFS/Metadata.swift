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

/// What a path names.
public enum FileKind: Sendable, Hashable {
    case file
    case directory
    case symbolicLink
    case fifo
    case socket
    case characterDevice
    case blockDevice
    case unknown

    init(mode: UInt32) {
        switch mode & 0o170000 {
        case 0o100000: self = .file
        case 0o040000: self = .directory
        case 0o120000: self = .symbolicLink
        case 0o010000: self = .fifo
        case 0o140000: self = .socket
        case 0o020000: self = .characterDevice
        case 0o060000: self = .blockDevice
        default: self = .unknown
        }
    }

    /// From a directory entry's d_type; nil for DT_UNKNOWN.
    init?(direntType: UInt8) {
        switch direntType {
        case 8: self = .file
        case 4: self = .directory
        case 10: self = .symbolicLink
        case 1: self = .fifo
        case 12: self = .socket
        case 2: self = .characterDevice
        case 6: self = .blockDevice
        default: return nil
        }
    }
}

/// A point in time as the file system records it: since the Unix epoch.
public struct FileTime: Sendable, Hashable, Comparable {
    public var seconds: Int64
    public var nanoseconds: Int32

    public init(seconds: Int64, nanoseconds: Int32) {
        self.seconds = seconds
        self.nanoseconds = nanoseconds
    }

    init(_ ts: timespec) {
        self.init(seconds: Int64(ts.tv_sec), nanoseconds: Int32(ts.tv_nsec))
    }

    /// Time since the Unix epoch.
    public var sinceEpoch: Duration { .seconds(seconds) + .nanoseconds(nanoseconds) }

    public static func < (a: FileTime, b: FileTime) -> Bool {
        (a.seconds, a.nanoseconds) < (b.seconds, b.nanoseconds)
    }
}

/// What `stat` says about a file: Tokio's `Metadata`.
public struct FileMetadata: Sendable, Hashable {
    public var kind: FileKind
    /// In bytes.
    public var size: Int
    /// The permission bits (`mode & 0o7777`), setuid, setgid and sticky
    /// included.
    public var permissions: UInt32
    public var linkCount: Int
    public var userID: UInt32
    public var groupID: UInt32
    public var device: UInt64
    public var inode: UInt64
    public var accessed: FileTime
    public var modified: FileTime
    /// When the inode last changed (ctime): contents, owner, permissions.
    public var statusChanged: FileTime

    public var isFile: Bool { kind == .file }
    public var isDirectory: Bool { kind == .directory }
    public var isSymbolicLink: Bool { kind == .symbolicLink }

    init(_ st: stat) {
        let mode = UInt32(st.st_mode)
        kind = FileKind(mode: mode)
        size = Int(st.st_size)
        permissions = mode & 0o7777
        linkCount = Int(st.st_nlink)
        userID = st.st_uid
        groupID = st.st_gid
        device = UInt64(truncatingIfNeeded: st.st_dev)
        inode = UInt64(st.st_ino)
        #if canImport(Darwin)
        accessed = FileTime(st.st_atimespec)
        modified = FileTime(st.st_mtimespec)
        statusChanged = FileTime(st.st_ctimespec)
        #else
        accessed = FileTime(st.st_atim)
        modified = FileTime(st.st_mtim)
        statusChanged = FileTime(st.st_ctim)
        #endif
    }
}
#endif
