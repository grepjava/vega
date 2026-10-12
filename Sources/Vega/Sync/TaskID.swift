/// Names the running task's waiter in a primitive's queue: a task waits on
/// one thing at a time, so its address is unique among waiters.
@inlinable @inline(__always)
func currentTaskID() -> UInt {
    withUnsafeCurrentTask { t in t.map { UInt(bitPattern: unsafeBitCast($0, to: Int.self)) } ?? 0 }
}
