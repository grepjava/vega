#if os(Linux) || canImport(Darwin) || os(Windows)
import Testing
import Vega
@testable import VegaProcess
import VegaIO
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
import WinSDK
#endif

private func bytes(_ s: String) -> IOBuffer {
    var b = IOBuffer(capacity: max(s.utf8.count, 1))
    b.append(s)
    return b
}

private func run<T: Sendable>(_ body: @escaping @Sendable () async throws -> T) throws -> T {
    let rt = Runtime(workers: 2)
    defer { rt.shutdown() }
    return try rt.block { () async throws -> T in try await body() }
}

private func sh(_ script: String) -> Command {
    Command("sh", arguments: ["-c", script])
}

// iOS, tvOS, watchOS and visionOS apps can't start processes.
#if os(Linux) || os(macOS)
@Suite struct ProcessTests {
    @Test func outputCollectsBothStreams() throws {
        let out = try run { try await sh("echo out; echo err >&2; exit 3").output() }
        #expect(out.status.code == 3)
        #expect(!out.status.isSuccess)
        #expect(out.stdoutString == "out\n")
        #expect(out.stderrString == "err\n")
    }

    @Test func statusReportsSignals() throws {
        let status = try run { try await sh("kill -TERM $$").status() }
        #expect(status.code == nil)
        #expect(status.signal == SIGTERM)
    }

    /// Megabytes on both streams at once: neither pipe may fill and stall
    /// the child.
    @Test func largeOutputOnBothStreams() throws {
        let out = try run {
            try await sh("head -c 3000000 /dev/zero; head -c 2000000 /dev/zero >&2").output()
        }
        #expect(out.status.isSuccess)
        #expect(out.stdout.count == 3_000_000)
        #expect(out.stderr.count == 2_000_000)
    }

    @Test func stdinAndStdoutPipes() throws {
        let (echoed, status) = try run { () async throws -> (String, VegaProcess.ExitStatus) in
            var cat = Command("cat")
            cat.standardInput = .pipe
            cat.standardOutput = .pipe
            var child = try cat.spawn()
            let stdin = child.stdin.take()!
            try await stdin.write(bytes("through cat\n"))
            _ = consume stdin                         // end of input
            let stdout = child.stdout.take()!
            var buf = IOBuffer(capacity: 64)
            while try await stdout.read(into: &buf) > 0 {}
            return (buf.string, try await child.wait())
        }
        #expect(echoed == "through cat\n")
        #expect(status.isSuccess)
    }

    /// `wait` closes stdin, so a child reading to the end finishes.
    @Test func waitClosesStdin() throws {
        let status = try run { () async throws -> VegaProcess.ExitStatus in
            var cat = Command("cat")
            cat.standardInput = .pipe
            cat.standardOutput = .null
            var child = try cat.spawn()
            return try await child.wait()
        }
        #expect(status.isSuccess)
    }

    @Test func killAndTryWait() throws {
        let (before, status, elapsed) = try run { () async throws -> (Bool, VegaProcess.ExitStatus, Duration) in
            var child = try Command("sleep", arguments: ["30"]).spawn()
            let before = try child.tryWait() == nil
            let start = ContinuousClock.now
            try child.kill()
            let status = try await child.wait()
            try child.kill()                         // reaped: a no-op
            return (before, status, ContinuousClock.now - start)
        }
        #expect(before)
        #expect(status.signal == SIGKILL)
        #expect(elapsed < .seconds(5))
    }

    /// The exit wakes the waiting task through the driver (a pidfd, or
    /// EVFILT_PROC), not a poll.
    @Test func exitIsWatchedOnTheDriver() throws {
        let (watched, late) = try run { () async throws -> (Bool, Duration) in
            var child = try Command("sleep", arguments: ["0.2"]).spawn()
            let start = ContinuousClock.now
            let watched = child.exitWatched
            let status = try await child.wait()
            #expect(status.isSuccess)
            return (watched, ContinuousClock.now - start - .milliseconds(200))
        }
        #expect(watched)
        #expect(late < .seconds(1), "late by \(late)")
    }

    /// A child that ended before anyone waited: its status is there at once.
    @Test func exitBeforeTheWait() throws {
        let (status, elapsed) = try run { () async throws -> (VegaProcess.ExitStatus, Duration) in
            var child = try sh("exit 7").spawn()
            try await Runtime.sleep(for: .milliseconds(100))
            let start = ContinuousClock.now
            let status = try await child.wait()
            return (status, ContinuousClock.now - start)
        }
        #expect(status.code == 7)
        #expect(elapsed < .milliseconds(500))
    }

    @Test func environmentAndWorkingDirectory() throws {
        let out = try run { () async throws -> Output in
            var cmd = sh("echo \"$GREETING\"; echo \"${HOME-unset}\"; pwd")
            cmd.environment = ["GREETING": "hi", "PATH": "/usr/bin:/bin"]
            cmd.workingDirectory = "/"
            return try await cmd.output()
        }
        #expect(out.stdoutString == "hi\nunset\n/\n")
    }

    @Test func setEnvironmentStartsFromTheParents() throws {
        let out = try run { () async throws -> Output in
            var cmd = sh("echo \"$VEGA_PROCESS_TEST\"; [ -n \"$PATH\" ] && echo path")
            cmd.setEnvironment("VEGA_PROCESS_TEST", "set")
            return try await cmd.output()
        }
        #expect(out.stdoutString == "set\npath\n")
    }

    @Test func spawnErrors() throws {
        let codes = try run { () async throws -> [Int32] in
            var codes: [Int32] = []
            for name in ["vega-no-such-program", "/nonexistent/x", "/etc/hosts", ""] {
                do throws(IOError) {
                    _ = try Command(name).spawn()
                    codes.append(0)
                } catch {
                    codes.append(error.code)
                }
            }
            return codes
        }
        #expect(codes == [ENOENT, ENOENT, EACCES, ENOENT])
    }

    /// A child dropped unwaited is reaped later (killed first, with
    /// killOnDrop), never left a zombie.
    @Test func droppedChildrenAreReaped() throws {
        let left = try run { () async throws -> Int in
            var sleeper = Command("sleep", arguments: ["30"])
            sleeper.killOnDrop = true
            _ = try sleeper.spawn()
            _ = try Command("true").spawn()
            let deadline = ContinuousClock.now + .seconds(5)
            while Orphans.count > 0 && ContinuousClock.now < deadline {
                try await Runtime.sleep(for: .milliseconds(10))
                Orphans.reap()
            }
            return Orphans.count
        }
        #expect(left == 0)
    }

    /// A descriptor handed to the child as its stdout.
    @Test func descriptorStdio() throws {
        let text = try run { () async throws -> String in
            let pipe = try makePipe()
            var cmd = Command("echo", arguments: ["via fd"])
            cmd.standardOutput = .descriptor(pipe.writer.descriptor)
            var child = try cmd.spawn()
            _ = try await child.wait()
            let reader = pipe.reader
            let writer = pipe.writer
            _ = consume writer                       // the last write end: EOF follows
            var buf = IOBuffer(capacity: 32)
            while try await reader.read(into: &buf) > 0 {}
            return buf.string
        }
        #expect(text == "via fd\n")
    }
}
#elseif os(Windows)
private func cmd(_ script: String) -> Command {
    Command("cmd", arguments: ["/d", "/c", script])
}

@Suite struct ProcessTests {
    @Test func outputCollectsBothStreams() throws {
        let out = try run { try await cmd("echo out& echo err>&2& exit /b 3").output() }
        #expect(out.status.code == 3)
        #expect(!out.status.isSuccess)
        #expect(out.stdoutString == "out\r\n")
        #expect(out.stderrString == "err\r\n")
    }

    /// Megabytes on both streams at once: neither pipe may fill and stall
    /// the child.
    @Test func largeOutputOnBothStreams() throws {
        let out = try run {
            try await Command("powershell", arguments: [
                "-NoProfile", "-NonInteractive", "-Command",
                "[Console]::Out.Write('x' * 3000000); [Console]::Out.Flush(); [Console]::Error.Write('y' * 2000000)",
            ]).output()
        }
        #expect(out.status.isSuccess)
        #expect(out.stdout.count == 3_000_000)
        #expect(out.stderr.count == 2_000_000)
    }

    @Test func stdinAndStdoutPipes() throws {
        let (echoed, status) = try run { () async throws -> (String, VegaProcess.ExitStatus) in
            var cat = Command("findstr", arguments: ["^"])
            cat.standardInput = .pipe
            cat.standardOutput = .pipe
            var child = try cat.spawn()
            let stdin = child.stdin.take()!
            try await stdin.write(bytes("through findstr\r\n"))
            _ = consume stdin                         // end of input
            let stdout = child.stdout.take()!
            var buf = IOBuffer(capacity: 64)
            while try await stdout.read(into: &buf) > 0 {}
            return (buf.string, try await child.wait())
        }
        #expect(echoed == "through findstr\r\n")
        #expect(status.isSuccess)
    }

    /// `wait` closes stdin, so a child reading to the end finishes.
    @Test func waitClosesStdin() throws {
        let status = try run { () async throws -> VegaProcess.ExitStatus in
            var sort = Command("sort")
            sort.standardInput = .pipe
            sort.standardOutput = .null
            var child = try sort.spawn()
            return try await child.wait()
        }
        #expect(status.isSuccess)
    }

    @Test func killAndTryWait() throws {
        let (before, status, elapsed) = try run { () async throws -> (Bool, VegaProcess.ExitStatus, Duration) in
            var ping = Command("ping", arguments: ["-n", "30", "127.0.0.1"])
            ping.standardOutput = .null
            var child = try ping.spawn()
            let before = try child.tryWait() == nil
            let start = ContinuousClock.now
            try child.kill()
            let status = try await child.wait()
            try child.kill()                         // waited for: a no-op
            return (before, status, ContinuousClock.now - start)
        }
        #expect(before)
        #expect(status.code == 1)
        #expect(status.signal == nil)
        #expect(elapsed < .seconds(5))
    }

    /// The exit wakes the waiting task through the driver (a wait on the
    /// process handle), not a poll.
    @Test func exitIsWatchedOnTheDriver() throws {
        let (watched, status) = try run { () async throws -> (Bool, VegaProcess.ExitStatus) in
            var ping = Command("ping", arguments: ["-n", "2", "127.0.0.1"])
            ping.standardOutput = .null
            var child = try ping.spawn()
            return (child.exitWatched, try await child.wait())
        }
        #expect(watched)
        #expect(status.isSuccess)
    }

    /// A child that ended before anyone waited: its status is there at once.
    @Test func exitBeforeTheWait() throws {
        let (status, elapsed) = try run { () async throws -> (VegaProcess.ExitStatus, Duration) in
            var child = try cmd("exit /b 7").spawn()
            try await Runtime.sleep(for: .milliseconds(300))
            let start = ContinuousClock.now
            let status = try await child.wait()
            return (status, ContinuousClock.now - start)
        }
        #expect(status.code == 7)
        #expect(elapsed < .milliseconds(500))
    }

    @Test func environmentAndWorkingDirectory() throws {
        let out = try run { () async throws -> Output in
            var c = cmd("echo %GREETING%& echo %VEGA_UNSET%& cd")
            // No PATH: cmd.exe is found in the system directory.
            c.environment = ["GREETING": "hi", "SystemRoot": Command.currentEnvironment["SystemRoot"] ?? "C:\\Windows"]
            c.workingDirectory = "C:\\"
            return try await c.output()
        }
        #expect(out.stdoutString == "hi\r\n%VEGA_UNSET%\r\nC:\\\r\n")
    }

    @Test func setEnvironmentStartsFromTheParents() throws {
        let out = try run { () async throws -> Output in
            var c = cmd("echo %VEGA_PROCESS_TEST%& if defined PATH echo path")
            c.setEnvironment("VEGA_PROCESS_TEST", "set")
            c.setEnvironment("vega_process_test", "again") // names are case-insensitive
            return try await c.output()
        }
        #expect(out.stdoutString == "again\r\npath\r\n")
    }

    /// Arguments reach the child as written, through the C runtime's
    /// quoting rules (a child of this test binary would show argv; findstr
    /// shows that the pattern with spaces and quotes arrived whole).
    @Test func argumentsAreQuoted() throws {
        #expect(Command.quote("plain") == "plain")
        #expect(Command.quote("") == "\"\"")
        #expect(Command.quote("two words") == "\"two words\"")
        #expect(Command.quote(#"say "hi""#) == #""say \"hi\"""#)
        #expect(Command.quote(#"C:\dir\"#) == #"C:\dir\"#)
        #expect(Command.quote(#"C:\my dir\"#) == #""C:\my dir\\""#)
        #expect(Command.quote(#"a\\"b"#) == #""a\\\\\"b""#)
        let out = try run { () async throws -> Output in
            var c = Command("findstr", arguments: ["/c:say \"hi\" there"])
            c.standardInput = .pipe
            var child = try c.spawn(stdin: .pipe, stdout: .pipe, stderr: .pipe)
            let stdin = child.stdin.take()!
            try await stdin.write(bytes("no\r\nthey say \"hi\" there\r\n"))
            _ = consume stdin
            return try await child.output()
        }
        #expect(out.stdoutString == "they say \"hi\" there\r\n")
    }

    @Test func spawnErrors() throws {
        let windows = Command.currentEnvironment["SystemRoot"] ?? "C:\\Windows"
        let codes = try run { () async throws -> [Int32] in
            var codes: [Int32] = []
            for name in ["vega-no-such-program", "C:\\nonexistent\\x", windows + "\\win.ini", "", "x.bat"] {
                do throws(IOError) {
                    _ = try Command(name).spawn()
                    codes.append(0)
                } catch {
                    codes.append(error.code)
                }
            }
            return codes
        }
        #expect(codes == [ENOENT, ENOENT, ENOEXEC, ENOENT, ENOENT])
    }

    @Test func batchFilesAreRefused() throws {
        let code = try run { () async throws -> Int32 in
            let dir = Command.currentEnvironment["TEMP"] ?? "C:\\Windows\\Temp"
            let path = dir + "\\vega-\(UInt32.random(in: 0 ... .max)).bat"
            let f = fopen(path, "w")
            fputs("@echo hi\r\n", f)
            fclose(f)
            defer { _ = remove(path) }
            do throws(IOError) {
                _ = try Command(path).spawn()
                return 0
            } catch {
                return error.code
            }
        }
        #expect(code == EINVAL)
    }

    /// A child dropped unwaited with killOnDrop is terminated.
    @Test func killOnDrop() throws {
        let gone = try run { () async throws -> Bool in
            var ping = Command("ping", arguments: ["-n", "30", "127.0.0.1"])
            ping.standardOutput = .null
            ping.killOnDrop = true
            let pid = try ping.spawn().pid
            guard let h = OpenProcess(DWORD(SYNCHRONIZE), false, DWORD(pid)) else { return true }
            defer { CloseHandle(h) }
            return WaitForSingleObject(h, 5000) == WAIT_OBJECT_0
        }
        #expect(gone)
    }

    /// A handle handed to the child as its stdout.
    @Test func descriptorStdio() throws {
        let text = try run { () async throws -> String in
            let pipe = try makePipe()
            var c = cmd("echo via handle")
            c.standardOutput = .descriptor(pipe.writer.descriptor)
            var child = try c.spawn()
            _ = try await child.wait()
            let reader = pipe.reader
            let writer = pipe.writer
            _ = consume writer                       // the last write end: EOF follows
            var buf = IOBuffer(capacity: 32)
            while try await reader.read(into: &buf) > 0 {}
            return buf.string
        }
        #expect(text == "via handle\r\n")
    }
}
#else
@Suite struct ProcessTests {
    @Test func spawningIsUnsupported() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let error = try rt.block { () async throws -> IOError? in
            do throws(IOError) {
                _ = try Command("true").spawn()
                return nil
            } catch {
                return error
            }
        }
        #expect(error == IOError(code: ENOTSUP))
    }
}
#endif

@Suite struct PipeTests {
    @Test func bytesFlowAndEndOfStream() throws {
        let got = try run { () async throws -> String in
            let pipe = try makePipe()
            let reader = pipe.reader
            let writer = pipe.writer
            // More than a pipe holds, so the writer waits for the reader.
            let big = String(repeating: "x", count: 200_000)
            async let wrote: Void = {
                try await writer.write(bytes(big))
            }()
            var buf = IOBuffer(capacity: 300_000)
            while buf.count < 200_000 {
                if try await reader.read(into: &buf) == 0 { break }
            }
            try await wrote
            return buf.string
        }
        #expect(got.count == 200_000)
    }

    /// Writing after the reader is gone throws EPIPE instead of raising
    /// SIGPIPE (which would kill the test process).
    @Test func writingToAClosedPipeIsAnError() throws {
        let code = try run { () async throws -> Int32 in
            let pipe = try makePipe()
            let writer = pipe.writer
            let reader = pipe.reader
            _ = consume reader
            do throws(IOError) {
                try await writer.write(bytes("nobody listens"))
                return 0
            } catch {
                return error.code
            }
        }
        #expect(code == EPIPE)
    }

    @Test func pipesAreStreams() throws {
        let copied = try run { () async throws -> Int in
            let a = try makePipe(), b = try makePipe()
            let src = a.reader, dst = b.writer
            let input = a.writer
            try await input.write(bytes("stream me"))
            _ = consume input
            let n = try await copy(from: src, to: dst)
            return n
        }
        #expect(copied == 9)
    }
}
#endif
