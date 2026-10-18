import CVega

/// File operations on the completion drivers, for VegaFS: io_uring, and
/// IOCP's overlapped reads and writes on Windows. Each returns the call's
/// result (>= 0) or -errno (-ECANCELED once the task is cancelled), or nil
/// when the caller isn't on such a driver (or, on Windows, the file can't
/// take an overlapped request there): it then does the work on the
/// blocking pool.
///
/// Every pointer stays valid until the operation completes: the caller
/// waits for that, even when cancelled.
package enum FileIO {
    package static func read(_ fd: Int32, into buffer: UnsafeMutableRawPointer, count: Int,
                             at offset: Int64) async -> Int64? {
        #if os(Windows)
        await overlapped(write: false, fd, buffer, count, offset)
        #else
        await URing.perform(.fileRead(fd, buffer, count, offset), owner: nil)
        #endif
    }

    package static func write(_ fd: Int32, from buffer: UnsafeRawPointer, count: Int,
                              at offset: Int64) async -> Int64? {
        #if os(Windows)
        await overlapped(write: true, fd, UnsafeMutableRawPointer(mutating: buffer), count, offset)
        #else
        await URing.perform(.fileWrite(fd, buffer, count, offset), owner: nil)
        #endif
    }

    package static func sync(_ fd: Int32, dataOnly: Bool) async -> Int64? {
        await URing.perform(.fsync(fd, dataOnly), owner: nil)
    }

    package static func open(_ path: UnsafePointer<CChar>, flags: Int32, mode: UInt32) async -> Int64? {
        await URing.perform(.open(path, flags, mode), owner: nil)
    }

    #if os(Windows)
    /// One overlapped ReadFile or WriteFile on the running runtime's port,
    /// through the file's overlapped twin handle (see cvega.c). A read from
    /// the cache usually finishes at once, with no trip through the port.
    private static func overlapped(write: Bool, _ fd: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int,
                                   _ offset: Int64) async -> Int64? {
        guard let s = Worker.currentScheduler, s.usesIOCP, let d = s.driver?.raw else { return nil }
        var op: UnsafeMutableRawPointer? = nil
        var here = true
        let res = await withIOInterrupt { arm in
            await withUnsafeContinuation { (c: UnsafeContinuation<Int64, Never>) in
                var res: Int64 = 0
                let waiter = unsafeBitCast(c, to: UInt.self)
                let started = write ? cv_ovl_file_write(d, fd, waiter, buffer, count, offset, &res, &op)
                                    : cv_ovl_file_read(d, fd, waiter, buffer, count, offset, &res, &op)
                if started == 1 {
                    let cancel = IOInterrupt.file(op.unsafelyUnwrapped)
                    if !arm(cancel) { cancel.fire() }
                    return
                }
                here = started == 0
                c.resume(returning: res)
            }
        }
        // The interrupt is disarmed: nothing touches the request any more.
        if let op { cv_ovl_file_finish(op, res) }
        return here ? res : nil
    }
    #endif
}
