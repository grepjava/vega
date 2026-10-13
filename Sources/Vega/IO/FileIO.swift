/// File operations on the io_uring driver, for VegaFS. Each returns the
/// syscall's result (>= 0) or -errno (-ECANCELED once the task is
/// cancelled), or nil when the caller isn't on a ring's worker: it then
/// does the work on the blocking pool.
///
/// Every pointer stays valid until the operation completes: the caller
/// waits for that, even when cancelled.
package enum FileIO {
    package static func read(_ fd: Int32, into buffer: UnsafeMutableRawPointer, count: Int,
                             at offset: Int64) async -> Int64? {
        await URing.perform(.fileRead(fd, buffer, count, offset), owner: nil)
    }

    package static func write(_ fd: Int32, from buffer: UnsafeRawPointer, count: Int,
                              at offset: Int64) async -> Int64? {
        await URing.perform(.fileWrite(fd, buffer, count, offset), owner: nil)
    }

    package static func sync(_ fd: Int32, dataOnly: Bool) async -> Int64? {
        await URing.perform(.fsync(fd, dataOnly), owner: nil)
    }

    package static func open(_ path: UnsafePointer<CChar>, flags: Int32, mode: UInt32) async -> Int64? {
        await URing.perform(.open(path, flags, mode), owner: nil)
    }
}
