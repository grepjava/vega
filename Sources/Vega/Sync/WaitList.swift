/// Tasks parked on a primitive, in arrival order, each resumed with a code
/// the primitive defines. Guarded by the owner's lock; the owner calls
/// `destroy()`.
struct WaitList {
    struct Waiter {
        let id: UInt
        let continuation: UnsafeContinuation<UInt8, Never>
    }

    private var ring = RawRing<Waiter>(capacity: 4)

    var isEmpty: Bool { ring.isEmpty }

    mutating func push(_ id: UInt, _ c: UnsafeContinuation<UInt8, Never>) {
        ring.pushBack(Waiter(id: id, continuation: c))
    }

    mutating func popFront() -> Waiter? { ring.popFront() }

    mutating func remove(_ id: UInt) -> Waiter? { ring.remove(where: { $0.id == id }) }

    /// Every waiter, leaving the list empty. Resume them after unlocking.
    mutating func takeAll() -> [Waiter] {
        var all: [Waiter] = []
        while let w = ring.popFront() { all.append(w) }
        return all
    }

    mutating func destroy() { ring.destroy() }
}

/// A primitive's lock and its wait list, for `park`.
struct WaitListRef: @unchecked Sendable {
    let lock: RawLock
    let list: UnsafeMutablePointer<WaitList>
}

/// Park the calling task on `ref`'s list until a waker resumes it with a
/// code. Under the lock, `now` first returns a code to go on with at once,
/// or nil to queue. With `cancelled`, a cancelled task is taken off the list
/// and resumed with that code; without, cancellation doesn't end the wait.
func park(_ ref: WaitListRef, cancelled: UInt8? = nil, _ now: () -> UInt8?) async -> UInt8 {
    guard let cancelled else {
        return await withUnsafeContinuation { (c: UnsafeContinuation<UInt8, Never>) in
            let code = ref.lock.withLock { () -> UInt8? in
                if let code = now() { return code }
                ref.list.pointee.push(0, c)
                return nil
            }
            if let code { c.resume(returning: code) }
        }
    }
    let id = currentTaskID()
    return await withTaskCancellationHandler {
        await withUnsafeContinuation { (c: UnsafeContinuation<UInt8, Never>) in
            let code = ref.lock.withLock { () -> UInt8? in
                // Checked under the lock: either the cancel handler runs after
                // this and finds the waiter, or the flag is visible here.
                if Task.isCancelled { return cancelled }
                if let code = now() { return code }
                ref.list.pointee.push(id, c)
                return nil
            }
            if let code { c.resume(returning: code) }
        }
    } onCancel: {
        let waiter = ref.lock.withLock { ref.list.pointee.remove(id) }
        waiter?.continuation.resume(returning: cancelled)
    }
}
