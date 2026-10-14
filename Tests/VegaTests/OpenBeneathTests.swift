#if os(Linux) || canImport(Darwin)
import Testing
import Vega
@testable import VegaFS
import VegaIO
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// What `File.open(beneath:)` makes of `path` under `root` -- or, with
/// `resolving`, the check it falls back on without openat2: the file's
/// contents, or the errno it threw.
private func outcome(_ root: String, _ path: String, resolving: Bool = false) -> String {
    do {
        let file = resolving ? File(adopting: try File.openResolving(root, path)) : try File.open(beneath: root, path)
        if try file.metadataNow().isDirectory { return "EISDIR" }
        var buffer = [UInt8](repeating: 0, count: 64)
        let n = buffer.withUnsafeMutableBytes { read(file.descriptor, $0.baseAddress, $0.count) }
        return String(decoding: buffer[0..<max(0, n)], as: UTF8.self)
    } catch {
        switch error.code {
        case ENOENT: return "ENOENT"
        case EISDIR: return "EISDIR"
        default: return "errno \(error.code)"
        }
    }
}

@Suite struct OpenBeneathTests {
    /// The tree: root/{a.txt, sub/b.txt, inside -> sub/b.txt,
    /// absolute -> <root>/a.txt, out -> ../secret.txt, up -> ..},
    /// with secret.txt and root-old/c.txt beside the root.
    @Test func containsWhatAClientMayName() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let results = try rt.block { () async throws -> [[String]] in
            let base = try await FileSystem.createTemporaryDirectory(prefix: "vega-beneath-")
            let root = base + "/root"
            try await FileSystem.createDirectory(root + "/sub", intermediates: true)
            try await FileSystem.createDirectory(base + "/root-old")
            try await FileSystem.write(root + "/a.txt", contents: "a")
            try await FileSystem.write(root + "/sub/b.txt", contents: "b")
            try await FileSystem.write(base + "/secret.txt", contents: "secret")
            try await FileSystem.write(base + "/root-old/c.txt", contents: "old")
            try await FileSystem.createSymbolicLink(at: root + "/inside", to: "sub/b.txt")
            try await FileSystem.createSymbolicLink(at: root + "/absolute", to: root + "/a.txt")
            try await FileSystem.createSymbolicLink(at: root + "/out", to: "../secret.txt")
            try await FileSystem.createSymbolicLink(at: root + "/up", to: "..")
            var results: [[String]] = []
            for resolving in [false, true] {
                results.append([
                    outcome(root, "a.txt", resolving: resolving),
                    outcome(root, "/a.txt", resolving: resolving),
                    outcome(root, "sub/b.txt", resolving: resolving),
                    outcome(root, "sub/../a.txt", resolving: resolving),
                    outcome(root, "inside", resolving: resolving),
                    outcome(root, "absolute", resolving: resolving),
                    outcome(root, "../secret.txt", resolving: resolving),
                    outcome(root, "sub/../../secret.txt", resolving: resolving),
                    outcome(root, "out", resolving: resolving),
                    outcome(root, "up/secret.txt", resolving: resolving),
                    outcome(root, "../root-old/c.txt", resolving: resolving),
                    outcome(root, "sub", resolving: resolving),
                    outcome(root, "", resolving: resolving),
                    outcome(root, "missing.txt", resolving: resolving),
                ])
            }
            try await FileSystem.removeDirectory(base, recursive: true)
            return results
        }
        let expected = [
            "a", "a", "b", "a", "b", "a",
            "ENOENT", "ENOENT", "ENOENT", "ENOENT", "ENOENT",
            "EISDIR", "EISDIR", "ENOENT",
        ]
        #expect(results == [expected, expected])
    }

    @Test func aPathWithANulIsRefused() {
        #expect(throws: IOError.self) { _ = try File.open(beneath: "/tmp", "a\0b") }
    }

    @Test func metadataNowIsTheFiles() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let size = try rt.block { () async throws -> Int in
            let base = try await FileSystem.createTemporaryDirectory(prefix: "vega-beneath-")
            try await FileSystem.write(base + "/f", contents: "12345")
            let file = try File.open(beneath: base, "f")
            let size = try file.metadataNow().size
            var bytes = [UInt8](repeating: 0, count: 8)
            let n = try bytes.withUnsafeMutableBytes { try file.readNow(into: $0, at: 1) }
            try await FileSystem.removeDirectory(base, recursive: true)
            return n == 4 && bytes[0..<4] == [0x32, 0x33, 0x34, 0x35] ? size : -1
        }
        #expect(size == 5)
    }
}
#endif
