#if os(Linux) || canImport(Darwin) || os(Windows)
import Testing
@testable import Vega
import VegaFS
import VegaIO
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// The permissions a file set to `mode` reports: Windows keeps only
/// whether it's writable.
private func reported(_ mode: UInt32) -> UInt32 {
    #if os(Windows)
    mode & 0o222 != 0 ? 0o666 : 0o444
    #else
    mode
    #endif
}

private func bytes(_ s: String) -> IOBuffer {
    var b = IOBuffer(capacity: max(s.utf8.count, 1))
    b.append(s)
    return b
}

/// Run `body` on a fresh runtime with a scratch directory, removed after.
private func withScratch<T: Sendable>(
    _ body: @escaping @Sendable (String) async throws -> T
) throws -> T {
    let rt = Runtime(workers: 2)
    defer { rt.shutdown() }
    return try rt.block { () async throws -> T in
        let dir = try await FileSystem.createTemporaryDirectory(prefix: "vega-fs-")
        do {
            let result = try await body(dir)
            try await FileSystem.removeDirectory(dir, recursive: true)
            return result
        } catch {
            try? await FileSystem.removeDirectory(dir, recursive: true)
            throw error
        }
    }
}

@Suite struct FileTests {
    @Test func wholeFileRoundTrip() throws {
        let (text, raw) = try withScratch { dir in
            let path = dir + "/a.txt"
            try await FileSystem.write(path, contents: "hello, file\n")
            let text = try await FileSystem.readString(path)
            try await FileSystem.write(path, contents: [1, 2, 3])
            return (text, try await FileSystem.read(path))
        }
        #expect(text == "hello, file\n")
        #expect(raw == [1, 2, 3])
    }

    /// Bigger than any one read: the size hint and the growth both work.
    @Test func largeFile() throws {
        let (whole, streamed) = try withScratch { dir in
            let path = dir + "/big"
            let data = (0..<(3 * 1024 * 1024 + 17)).map { UInt8(truncatingIfNeeded: $0 &* 31) }
            try await FileSystem.write(path, contents: data)
            let whole = try await FileSystem.read(path) == data
            let file = try await File.open(path)
            var buf = IOBuffer(capacity: 1000)
            let n = try await file.readToEnd(into: &buf)
            let streamed = n == data.count && buf.withUnsafeBytes { Array($0) } == data
            return (whole, streamed)
        }
        #expect(whole)
        #expect(streamed)
    }

    @Test func cursorAndPositionalIO() throws {
        let (all, middle, position) = try withScratch { dir in
            let path = dir + "/f"
            let file = try await File.open(path, options: .init(read: true, write: true, create: true))
            try await file.write(bytes("hello world"))
            try await file.write(bytes("W"), at: 6)          // leaves the position at the end
            try await file.write(bytes("!"))
            var mid = IOBuffer(capacity: 5)
            _ = try await file.read(into: &mid, at: 6)
            let position = try file.seek(.current(0))
            try file.seek(.start(0))
            var all = IOBuffer(capacity: 64)
            try await file.readToEnd(into: &all)
            return (all.string, mid.string, position)
        }
        #expect(all == "hello World!")
        #expect(middle == "World")
        #expect(position == 12)
    }

    @Test func appendAndTruncate() throws {
        let (appended, truncated, length) = try withScratch { dir in
            let path = dir + "/log"
            for line in ["one\n", "two\n"] {
                let f = try await File.open(path, options: .appending)
                try await f.write(bytes(line))
            }
            let appended = try await FileSystem.readString(path)
            _ = try await File.create(path)               // empties it
            let truncated = try await FileSystem.readString(path)
            let f = try await File.open(path, options: .init(write: true))
            try await f.setLength(10)
            let length = try await f.metadata().size
            return (appended, truncated, length)
        }
        #expect(appended == "one\ntwo\n")
        #expect(truncated == "")
        #expect(length == 10)
    }

    @Test func openErrors() throws {
        let codes = try withScratch { dir -> [Int32] in
            func code(_ options: File.Options, _ path: String) async -> Int32 {
                do {
                    _ = try await File.open(path, options: options)
                    return 0
                } catch {
                    return error.code
                }
            }
            try await FileSystem.write(dir + "/there", contents: "x")
            return [
                await code(.reading, dir + "/missing"),
                await code(.init(createNew: true, permissions: 0o600).with(write: true), dir + "/there"),
                await code(.init(read: true, truncate: true), dir + "/there"),
                await code(.init(read: true, create: true), dir + "/there"),
                await code(.init(), dir + "/there"),
                await code(.reading, dir + "/bad\0name"),
            ]
        }
        #expect(codes == [ENOENT, EEXIST, EINVAL, EINVAL, EINVAL, EINVAL])
    }

    @Test func syncAndClose() throws {
        let text = try withScratch { dir in
            let path = dir + "/s"
            let f = try await File.create(path)
            try await f.write(bytes("durable"))
            try await f.syncData()
            try await f.sync()
            try f.close()
            return try await FileSystem.readString(path)
        }
        #expect(text == "durable")
    }

    @Test func duplicateSharesThePosition() throws {
        let text = try withScratch { dir in
            let path = dir + "/d"
            let f = try await File.create(path)
            let g = try f.duplicate()
            try await f.write(bytes("ab"))
            try await g.write(bytes("cd"))
            return try await FileSystem.readString(path)
        }
        #expect(text == "abcd")
    }

    #if os(Linux)
    /// On the uring driver, File's reads, writes, syncs and opens go through
    /// the ring: no blocking thread starts.
    @Test func ringOperationsSkipTheBlockingPool() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        guard rt.ioBackend == .ioUring else { return }
        let dir = "/tmp/vega-ring-\(getpid())"
        mkdir(dir, 0o700)
        defer { rmdir(dir) }
        let path = dir + "/r"
        let text = try rt.block { () async throws -> String in
            let f = try await File.open(path, options: .init(read: true, write: true, create: true))
            try await f.write(bytes("ring"))
            try await f.syncData()
            var buf = IOBuffer(capacity: 8)
            _ = try await f.read(into: &buf, at: 0)
            return buf.string
        }
        unlink(path)
        #expect(text == "ring")
        #expect(rt.scheduler.blocking.threadCount == 0)
    }
    #endif

    /// Files are byte streams: VegaIO's copy and codecs work on them.
    @Test func filesAreStreams() throws {
        let (copied, lines) = try withScratch { dir in
            try await FileSystem.write(dir + "/in", contents: "alpha\nbeta\ngamma\n")
            let src = try await File.open(dir + "/in")
            let dst = try await File.create(dir + "/out")
            let copied = try await copy(from: src, to: dst, bufferSize: 4)
            var framed = FramedRead(reading: try await File.open(dir + "/out"), decoder: LinesCodec())
            var lines: [String] = []
            while let line = try await framed.next() { lines.append(line) }
            return (copied, lines)
        }
        #expect(copied == 17)
        #expect(lines == ["alpha", "beta", "gamma"])
    }
}

@Suite struct FileSystemTests {
    @Test func metadataAndPermissions() throws {
        let (meta, mode, dirMeta) = try withScratch { dir in
            let path = dir + "/m"
            try await FileSystem.write(path, contents: "12345")
            try await FileSystem.setPermissions(path, 0o640)
            let meta = try await FileSystem.metadata(path)
            let f = try await File.open(path)
            try await f.setPermissions(0o600)
            let mode = try await f.metadata().permissions
            return (meta, mode, try await FileSystem.metadata(dir))
        }
        #expect(meta.isFile && meta.size == 5 && meta.permissions == reported(0o640))
        #expect(meta.linkCount == 1)
        #expect(meta.modified.seconds > 1_600_000_000)
        #expect(mode == reported(0o600))
        #expect(dirMeta.isDirectory)
    }

    @Test func directories() throws {
        let (names, kinds, gone, existsAfter) = try withScratch { dir in
            try await FileSystem.createDirectory(dir + "/a/b/c", intermediates: true)
            try await FileSystem.createDirectory(dir + "/a/b/c", intermediates: true)  // exists: fine
            try await FileSystem.write(dir + "/a/file", contents: "x")
            try await FileSystem.createSymbolicLink(at: dir + "/a/link", to: "b")
            let entries = try await FileSystem.contentsOfDirectory(dir + "/a")
            let names = entries.map(\.name).sorted()
            let kinds = Dictionary(uniqueKeysWithValues: entries.map { ($0.name, $0.kind) })
            var gone = false
            do throws(IOError) {
                try await FileSystem.removeDirectory(dir + "/a")      // not empty
            } catch {
                gone = error.code == ENOTEMPTY || error.code == EEXIST
            }
            try await FileSystem.removeDirectory(dir + "/a", recursive: true)
            return (names, kinds, gone, try await FileSystem.exists(dir + "/a"))
        }
        #expect(names == ["b", "file", "link"])
        #expect(kinds == ["b": FileKind.directory, "file": .file, "link": .symbolicLink])
        #expect(gone)
        #expect(!existsAfter)
    }

    @Test func createDirectoryErrors() throws {
        let codes = try withScratch { dir -> [Int32] in
            try await FileSystem.write(dir + "/plain", contents: "")
            var codes: [Int32] = []
            for (path, deep) in [(dir + "/x/y", false), (dir + "/plain", true), (dir + "/plain/z", true)] {
                do throws(IOError) {
                    try await FileSystem.createDirectory(path, intermediates: deep)
                    codes.append(0)
                } catch {
                    codes.append(error.code)
                }
            }
            return codes
        }
        #expect(codes == [ENOENT, EEXIST, ENOTDIR])
    }

    @Test func linksRenameAndCopy() throws {
        let r = try withScratch { dir in
            let a = dir + "/a"
            try await FileSystem.write(a, contents: "contents")
            try await FileSystem.setPermissions(a, 0o604)
            try await FileSystem.createSymbolicLink(at: dir + "/sym", to: "a")
            try await FileSystem.createHardLink(at: dir + "/hard", to: a)
            let target = try await FileSystem.readSymbolicLink(dir + "/sym")
            let followed = try await FileSystem.metadata(dir + "/sym")
            let link = try await FileSystem.metadata(dir + "/sym", followingSymbolicLinks: false)
            let canonical = try await FileSystem.canonicalPath(dir + "/./sym")
            let real = try await FileSystem.canonicalPath(a)
            let copied = try await FileSystem.copyFile(a, to: dir + "/copy")
            let copy = try await FileSystem.metadata(dir + "/copy")
            try await FileSystem.rename(dir + "/copy", to: dir + "/moved")
            let moved = try await FileSystem.readString(dir + "/moved")
            let copyGone = try await !FileSystem.exists(dir + "/copy")
            try await FileSystem.removeFile(dir + "/sym")
            let aStays = try await FileSystem.exists(a)
            let links = try await FileSystem.metadata(a).linkCount
            return (target, followed.isFile, link.isSymbolicLink, canonical == real, copied,
                    copy.permissions, moved, copyGone, aStays, links)
        }
        #expect(r.0 == "a")
        #expect(r.1)
        #expect(r.2)
        #expect(r.3)
        #expect(r.4 == 8)
        #expect(r.5 == reported(0o604))
        #expect(r.6 == "contents")
        #expect(r.7)
        #expect(r.8)
        #expect(r.9 == 2)
    }

    /// The blocking pool runs path operations for tasks on any executor,
    /// not just a Vega worker.
    @Test func worksOffTheRuntime() async throws {
        let dir = try await FileSystem.createTemporaryDirectory()
        try await FileSystem.write(dir + "/x", contents: "off")
        let f = try await File.open(dir + "/x")
        var buf = IOBuffer(capacity: 8)
        _ = try await f.read(into: &buf)
        try await FileSystem.removeDirectory(dir, recursive: true)
        #expect(buf.string == "off")
    }
}

private extension File.Options {
    func with(write: Bool) -> File.Options {
        var o = self
        o.write = write
        return o
    }
}
#endif
