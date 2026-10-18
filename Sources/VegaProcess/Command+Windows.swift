#if os(Windows)
import CVega
import Vega
import ucrt
import WinSDK

extension Command {
    func spawnWindows(stdin: Stdio, stdout: Stdio, stderr: Stdio) throws(IOError) -> Child {
        for s in [executable, workingDirectory ?? ""] + arguments where s.utf8.contains(0) {
            throw IOError(code: EINVAL)
        }
        let path = try resolve()
        let ext = path.lowercased()
        if ext.hasSuffix(".bat") || ext.hasSuffix(".cmd") { throw IOError(code: EINVAL) }
        guard !executable.contains("\"") else { throw IOError(code: EINVAL) }
        // The program as given, always quoted, as Rust's std writes it.
        let line = (["\"" + executable + "\""] + arguments.map(Command.quote)).joined(separator: " ")
        let block = try environment.map { env throws(IOError) in try Command.environmentBlock(env) }

        // The child's handles, by stdio index; the parent's ends of pipes.
        var childHandles: [Int32] = []
        var parentHandles: [Int32?] = [nil, nil, nil]
        var toClose: [Int32] = [] // the child's pipe ends: ours to close after the spawn
        defer { for h in toClose { closeHandle(h) } }
        for (i, stdio) in [stdin, stdout, stderr].enumerated() {
            switch stdio.kind {
            case .inherit: childHandles.append(CV_STDIO_INHERIT)
            case .null: childHandles.append(CV_STDIO_NULL)
            case .descriptor: childHandles.append(stdio.descriptor!)
            case .pipe:
                var fds: (Int32, Int32) = (-1, -1)
                // stdin: the child reads (end 0); stdout, stderr: it writes (end 1).
                let e = withUnsafeMutablePointer(to: &fds) {
                    $0.withMemoryRebound(to: Int32.self, capacity: 2) { cv_pipe_win($0, i == 0 ? 0 : 1) }
                }
                if e != 0 {
                    for case let h? in parentHandles { closeHandle(h) }
                    throw IOError(code: e)
                }
                let (mine, theirs) = i == 0 ? (fds.1, fds.0) : (fds.0, fds.1)
                childHandles.append(theirs)
                toClose.append(theirs)
                parentHandles[i] = mine
            default: preconditionFailure("no such Stdio: \(stdio)")
            }
        }

        var process = 0
        var pid: Int32 = 0
        let rc = path.withCString(encodedAs: UTF16.self) { app in
            line.withCString(encodedAs: UTF16.self) { cmd in
                withOptionalWide(workingDirectory) { cwd in
                    withOptionalBlock(block) { env in
                        childHandles.withUnsafeBufferPointer { stdio in
                            cv_spawn_win(app, cmd, env, cwd, stdio.baseAddress, processGroup == 0 ? 1 : 0,
                                         &process, &pid)
                        }
                    }
                }
            }
        }
        if rc != 0 {
            for case let h? in parentHandles { closeHandle(h) }
            throw IOError(code: rc)
        }
        // From here the child runs: whatever fails, the Child owns it.
        var child = Child(pid: pid, process: process, killOnDrop: killOnDrop)
        if let h = parentHandles[0] { child.stdin = try PipeWriter(adopting: h) }
        if let h = parentHandles[1] { child.stdout = try PipeReader(adopting: h) }
        if let h = parentHandles[2] { child.stderr = try PipeReader(adopting: h) }
        child.watchExit()
        return child
    }

    /// The executable's path: as given (plus `.exe` without an extension)
    /// if it names a directory, else the first match in the child's PATH,
    /// then the system directories.
    private func resolve() throws(IOError) -> String {
        if executable.isEmpty { throw IOError(code: ENOENT) }
        let name = Command.withExtension(executable)
        if executable.contains(where: { $0 == "/" || $0 == "\\" || $0 == ":" }) {
            switch fileKind(name) {
            case .some(true): throw IOError(code: EACCES)
            case .some(false): return name
            case .none: throw IOError(code: ENOENT)
            }
        }
        let search = environment.map { env in env.first { $0.key.uppercased() == "PATH" }?.value }
            ?? Command.currentEnvironment.first { $0.key.uppercased() == "PATH" }?.value
        var dirs = (search ?? "").split(separator: ";").map { String($0.filter { $0 != "\"" }) }
        dirs += [systemDirectory(GetSystemDirectoryW), systemDirectory(GetWindowsDirectoryW)].compactMap { $0 }
        var denied = false
        for dir in dirs where !dir.isEmpty {
            let candidate = dir.hasSuffix("\\") || dir.hasSuffix("/") ? dir + name : dir + "\\" + name
            switch fileKind(candidate) {
            case .some(false): return candidate
            case .some(true): denied = true
            case .none: continue
            }
        }
        throw IOError(code: denied ? EACCES : ENOENT)
    }

    /// `name` with `.exe` unless its last component has an extension.
    static func withExtension(_ name: String) -> String {
        let last = name.split(whereSeparator: { $0 == "/" || $0 == "\\" }).last ?? ""
        return last.contains(".") ? name : name + ".exe"
    }

    /// One argument as the Microsoft C runtime reads it back: quoted if it
    /// is empty or has a space, tab or quote; backslashes doubled only
    /// before a quote.
    static func quote(_ arg: String) -> String {
        if !arg.isEmpty && !arg.contains(where: { $0 == " " || $0 == "\t" || $0 == "\n" || $0 == "\u{0B}" || $0 == "\"" }) {
            return arg
        }
        var out = "\""
        var backslashes = 0
        for c in arg {
            switch c {
            case "\\":
                backslashes += 1
            case "\"":
                out += String(repeating: "\\", count: backslashes * 2 + 1) + "\""
                backslashes = 0
            default:
                out += String(repeating: "\\", count: backslashes)
                backslashes = 0
                out.append(c)
            }
        }
        out += String(repeating: "\\", count: backslashes * 2) + "\""
        return out
    }

    /// A CREATE_UNICODE_ENVIRONMENT block: NAME=value strings sorted by
    /// name, case-insensitively, each ending in a NUL, then one more.
    static func environmentBlock(_ env: [String: String]) throws(IOError) -> [UInt16] {
        var block: [UInt16] = []
        for (name, value) in env.sorted(by: { $0.key.uppercased() < $1.key.uppercased() }) {
            guard !name.isEmpty, !name.dropFirst().contains("="), !(name + value).utf8.contains(0) else {
                throw IOError(code: EINVAL)
            }
            block += "\(name)=\(value)".utf16
            block.append(0)
        }
        if block.isEmpty { block.append(0) }
        block.append(0)
        return block
    }
}

private func closeHandle(_ h: Int32) {
    _ = CloseHandle(HANDLE(bitPattern: Int(h)))
}

/// Whether `path` is a directory, or nil if it isn't there.
private func fileKind(_ path: String) -> Bool? {
    let attrs = path.withCString(encodedAs: UTF16.self) { GetFileAttributesW($0) }
    if attrs == INVALID_FILE_ATTRIBUTES { return nil }
    return attrs & DWORD(FILE_ATTRIBUTE_DIRECTORY) != 0
}

private func systemDirectory(_ get: (UnsafeMutablePointer<WCHAR>?, UINT) -> UINT) -> String? {
    var buf = [WCHAR](repeating: 0, count: Int(MAX_PATH))
    let n = get(&buf, UINT(buf.count))
    guard n > 0 && Int(n) < buf.count else { return nil }
    return String(decoding: buf[..<Int(n)], as: UTF16.self)
}

private func withOptionalWide<R>(_ s: String?, _ body: (UnsafePointer<WCHAR>?) -> R) -> R {
    guard let s else { return body(nil) }
    return s.withCString(encodedAs: UTF16.self) { body($0) }
}

private func withOptionalBlock<R>(_ block: [UInt16]?, _ body: (UnsafePointer<WCHAR>?) -> R) -> R {
    guard let block else { return body(nil) }
    return block.withUnsafeBufferPointer { body($0.baseAddress) }
}
#endif
