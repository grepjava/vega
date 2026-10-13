#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif
import Testing
@testable import Vega

/// Diagnostic, off by default: hold Swift's default (cooperative) pool threads
/// without touching Vega, to see whether a Vega timer depends on that pool.
/// Run with VEGA_BLOCKERS=1.
@Suite(.enabled(if: getenv("VEGA_BLOCKERS") != nil))
struct PoolStarvationTests {
    @Test(arguments: 0..<6) func holdCooperativeThread(_ i: Int) {
        usleep(400_000)
    }
}

#if os(Linux) // glibc diagnostics
@_silgen_name("pthread_getname_np") func pthread_getname_np(_ t: pthread_t, _ buf: UnsafeMutablePointer<CChar>, _ n: Int) -> Int32
@_silgen_name("backtrace") func c_backtrace(_ buf: UnsafeMutablePointer<UnsafeMutableRawPointer?>, _ n: Int32) -> Int32
@_silgen_name("backtrace_symbols_fd") func c_backtrace_symbols_fd(_ buf: UnsafePointer<UnsafeMutableRawPointer?>, _ n: Int32, _ fd: Int32)

func Thread_callStackSymbols() {
    var frames = [UnsafeMutableRawPointer?](repeating: nil, count: 40)
    let n = c_backtrace(&frames, 40)
    c_backtrace_symbols_fd(frames, n, 1)
}

/// Diagnostic: where does a sleeping task's wake-up come from?
@Suite(.enabled(if: getenv("VEGA_TRACE") != nil))
struct SleepTraceTests {
    @Test func traceSleepWake() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let s = rt.scheduler
        Scheduler.foreignEnqueueHook = {
            var name = [CChar](repeating: 0, count: 32)
            pthread_getname_np(pthread_self(), &name, 32)
            let me = String(decoding: name.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
            print("TRACE foreign enqueue from thread '\(me)'")
            if me != "test" { print("TRACE stack:"); Thread_callStackSymbols() }
        }
        defer { Scheduler.foreignEnqueueHook = nil }
        let before = (s.timedEnqueues.load(ordering: .relaxed), s.foreignEnqueues.load(ordering: .relaxed))
        rt.block {
            try? await Task.sleep(for: .milliseconds(10))
        }
        let after = (s.timedEnqueues.load(ordering: .relaxed), s.foreignEnqueues.load(ordering: .relaxed))
        print("TRACE timed +\(after.0 - before.0), foreign +\(after.1 - before.1) (1 foreign = block's own start)")
    }
}
#endif
