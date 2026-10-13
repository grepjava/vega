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

/// A program to run: Tokio's `tokio::process::Command`.
///
/// ```swift
/// let out = try await Command("git", arguments: ["rev-parse", "HEAD"]).output()
/// print(out.status, out.stdoutString)
///
/// var cat = Command("cat")
/// cat.standardInput = .pipe
/// cat.standardOutput = .pipe
/// var child = try cat.spawn()
/// try await child.stdin!.write(bytes)
/// ```
///
/// `executable` without a slash is looked up in `PATH` (the child's, when
/// `environment` sets one). Spawning and waiting need a Vega runtime. On
/// iOS, tvOS, watchOS and visionOS, where apps can't start processes,
/// `spawn` throws `ENOTSUP`.
public struct Command: Sendable {
    /// Where one of the child's standard streams goes.
    public enum Stdio: Sendable, Hashable {
        /// The parent's own.
        case inherit
        /// /dev/null.
        case null
        /// A pipe to the parent: `Child.stdin`, `stdout` or `stderr`.
        case pipe
        /// A descriptor of the parent's (it stays open in the parent).
        case descriptor(Int32)
    }

    public var executable: String
    public var arguments: [String]
    /// The child's whole environment; nil inherits the parent's.
    public var environment: [String: String]?
    /// The child's working directory; nil keeps the parent's.
    public var workingDirectory: String?
    /// nil: `.inherit` for `spawn` and `status`, `.null` for `output`.
    public var standardInput: Stdio?
    /// nil: `.inherit` for `spawn` and `status`, `.pipe` for `output`.
    public var standardOutput: Stdio?
    /// nil: `.inherit` for `spawn` and `status`, `.pipe` for `output`.
    public var standardError: Stdio?
    /// Put the child in this process group; 0 makes a new group led by the
    /// child. nil keeps the parent's.
    public var processGroup: Int32?
    /// Send SIGKILL to the child if its `Child` is dropped before it was
    /// waited for.
    public var killOnDrop = false

    public init(_ executable: String, arguments: [String] = []) {
        self.executable = executable
        self.arguments = arguments
    }

    /// Set (or, with nil, remove) one variable, starting from the parent's
    /// environment if none was set yet.
    public mutating func setEnvironment(_ name: String, _ value: String?) {
        var env = environment ?? Command.currentEnvironment
        env[name] = value
        environment = env
    }

    /// The parent's environment.
    public static var currentEnvironment: [String: String] {
        var env: [String: String] = [:]
        guard var p = cv_environ() else { return env }
        while let entry = p.pointee {
            let s = String(cString: entry)
            if let eq = s.firstIndex(of: "=") {
                env[String(s[..<eq])] = String(s[s.index(after: eq)...])
            }
            p += 1
        }
        return env
    }

    // MARK: - Running

    /// Start the program. Call from a task on a Vega runtime.
    public func spawn() throws(IOError) -> Child {
        try spawn(stdin: standardInput ?? .inherit, stdout: standardOutput ?? .inherit,
                  stderr: standardError ?? .inherit)
    }

    /// Run the program to its end, with the parent's streams unless set
    /// otherwise.
    public func status() async throws(IOError) -> ExitStatus {
        var child = try spawn()
        return try await child.wait()
    }

    /// Run the program to its end, collecting its stdout and stderr (stdin
    /// is /dev/null unless set otherwise).
    public func output() async throws(IOError) -> Output {
        try await spawn(stdin: standardInput ?? .null, stdout: standardOutput ?? .pipe,
                        stderr: standardError ?? .pipe).output()
    }

    func spawn(stdin: Stdio, stdout: Stdio, stderr: Stdio) throws(IOError) -> Child {
        #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        throw IOError(code: ENOTSUP)
        #else
        Orphans.reap()
        for s in [executable, workingDirectory ?? ""] + arguments where s.utf8.contains(0) {
            throw IOError(code: EINVAL)
        }
        let path = try resolve()

        // The child's ends, by stdio index; the parent's ends of pipes.
        var childFDs: [Int32] = []
        var parentFDs: [Int32?] = [nil, nil, nil]
        var toClose: [Int32] = []  // fds that are ours to close after the spawn
        defer { for fd in toClose { _ = close(fd) } }
        for (i, stdio) in [stdin, stdout, stderr].enumerated() {
            switch stdio {
            case .inherit: childFDs.append(CV_STDIO_INHERIT)
            case .null: childFDs.append(CV_STDIO_NULL)
            case .descriptor(let fd): childFDs.append(fd)
            case .pipe:
                var fds: (Int32, Int32) = (-1, -1)
                let e = withUnsafeMutablePointer(to: &fds) {
                    $0.withMemoryRebound(to: Int32.self, capacity: 2) { cv_pipe($0) }
                }
                if e != 0 {
                    for case let fd? in parentFDs { _ = close(fd) }
                    throw IOError(code: e)
                }
                // stdin: the child reads; stdout, stderr: the child writes.
                let (mine, theirs) = i == 0 ? (fds.1, fds.0) : (fds.0, fds.1)
                childFDs.append(theirs)
                toClose.append(theirs)
                parentFDs[i] = mine
            }
        }

        var pid: Int32 = 0
        let rc = withCStrings([executable] + arguments) { argv in
            withOptionalCStrings(environment.map { $0.map { "\($0.key)=\($0.value)" } }) { envp in
                childFDs.withUnsafeBufferPointer { stdio in
                    cv_spawn(path, argv, envp ?? UnsafePointer(cv_environ()), workingDirectory, stdio.baseAddress,
                             processGroup ?? -1, &pid)
                }
            }
        }
        if rc != 0 {
            for case let fd? in parentFDs { _ = close(fd) }
            throw IOError(code: rc)
        }
        // From here the child runs: whatever fails, the Child owns it (and
        // reaps or kills it when dropped).
        var child = Child(pid: pid, killOnDrop: killOnDrop)
        if let fd = parentFDs[0] { child.stdin = try PipeWriter(adopting: fd) }
        if let fd = parentFDs[1] { child.stdout = try PipeReader(adopting: fd) }
        if let fd = parentFDs[2] { child.stderr = try PipeReader(adopting: fd) }
        try child.watchExit()
        return child
        #endif
    }

    /// The executable's path: as given if it has a slash, else the first
    /// match in PATH.
    private func resolve() throws(IOError) -> String {
        if executable.contains("/") { return executable }
        if executable.isEmpty { throw IOError(code: ENOENT) }
        let search = environment.map { $0["PATH"] } ?? getenv("PATH").map { String(cString: $0) }
        let dirs = (search ?? "/usr/local/bin:/usr/bin:/bin").split(separator: ":", omittingEmptySubsequences: false)
        var denied = false
        for dir in dirs {
            let candidate = (dir.isEmpty ? "." : String(dir)) + "/" + executable
            var st = stat()
            guard stat(candidate, &st) == 0, UInt32(st.st_mode) & 0o170000 == 0o100000 else { continue }
            if access(candidate, X_OK) == 0 { return candidate }
            denied = true
        }
        throw IOError(code: denied ? EACCES : ENOENT)
    }
}

/// How a child ended.
public struct ExitStatus: Sendable, Hashable, CustomStringConvertible {
    /// The status as waitpid(2) reports it.
    public let rawValue: Int32

    public init(rawValue: Int32) { self.rawValue = rawValue }

    /// The exit code, if it exited (rather than being killed by a signal).
    public var code: Int32? { rawValue & 0x7f == 0 ? (rawValue >> 8) & 0xff : nil }

    /// The signal that killed it, if one did.
    public var signal: Int32? {
        let sig = rawValue & 0x7f
        return sig != 0 && sig != 0x7f ? sig : nil
    }

    /// Exited with code 0.
    public var isSuccess: Bool { code == 0 }

    public var description: String {
        if let code { return "exit code \(code)" }
        if let signal { return "killed by signal \(signal)" }
        return "wait status \(rawValue)"
    }
}

/// What `Command.output()` collects.
public struct Output: Sendable, Hashable {
    public var status: ExitStatus
    public var stdout: [UInt8]
    public var stderr: [UInt8]

    /// stdout as UTF-8 (invalid sequences repaired).
    public var stdoutString: String { String(decoding: stdout, as: UTF8.self) }
    public var stderrString: String { String(decoding: stderr, as: UTF8.self) }
}

/// `strings` as a NULL-terminated C array for `body`; nil stays nil.
private func withOptionalCStrings<R>(_ strings: [String]?, _ body: (UnsafePointer<UnsafeMutablePointer<CChar>?>?) -> R) -> R {
    guard let strings else { return body(nil) }
    var pointers: [UnsafeMutablePointer<CChar>?] = strings.map { strdup($0) }
    pointers.append(nil)
    defer { for p in pointers { free(p) } }
    return pointers.withUnsafeBufferPointer { body($0.baseAddress) }
}

private func withCStrings<R>(_ strings: [String], _ body: (UnsafePointer<UnsafeMutablePointer<CChar>?>) -> R) -> R {
    withOptionalCStrings(strings) { body($0!) }
}
#endif
