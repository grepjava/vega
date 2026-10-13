// POSIX calls the tests use, on Windows.
#if os(Windows)
import WinSDK

/// Sleep (at the scheduler tick's resolution, about 15 ms by default).
@discardableResult
func usleep(_ microseconds: UInt32) -> Int32 {
    Sleep(DWORD((microseconds + 999) / 1000))
    return 0
}

@discardableResult
func sched_yield() -> Int32 {
    _ = SwitchToThread()
    return 0
}

typealias pthread_t = DWORD
func pthread_self() -> pthread_t { GetCurrentThreadId() }
#endif
