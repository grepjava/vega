#if os(Linux) || canImport(Darwin) || os(Windows)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// When a read's bytes arrived, as the kernel stamped them on receipt: for
/// a server that reports how long a request waited before anything looked
/// at it -- behind a busy worker, in the accept queue -- which no clock
/// read after the read can see.
///
/// ```swift
/// try listener.setOption(.receiveTimestamps, to: true) // accepted streams inherit it
/// let arrival = UnsafeMutablePointer<ReadArrival>.allocate(capacity: 1)
/// arrival.initialize(to: ReadArrival())
/// let n = try await stream.read(into: &buffer, arrival: arrival)
/// let queued = arrival.pointee.microseconds.map { wallClockMicros() - $0 }
/// ```
///
/// The read is one `recvmsg` in place of a `recv`: no system call more.
/// What the kernel fills in has to stay where it is while the read waits,
/// so the record lives in memory that does not move -- allocated, or a
/// field of something allocated -- and the read is handed its pointer.
public struct ReadArrival: @unchecked Sendable {
    @usableFromInline var raw = cv_arrival()

    public init() {}

    /// Microseconds since the epoch at which the last read's bytes arrived,
    /// or nil when they were not stamped: the socket had no
    /// `receiveTimestamps`, or the stream cannot say (TLS, Unix sockets,
    /// Windows).
    public var microseconds: UInt64? { raw.micros == 0 ? nil : raw.micros }

    /// Forgets the last read's stamp.
    public mutating func clear() { raw.micros = 0 }
}

extension TCPStream {
    /// `read(into:)`, saying in `arrival` when the bytes read arrived.
    public func read(into buffer: inout IOBuffer,
                     arrival: UnsafeMutablePointer<ReadArrival>) async throws(IOError) -> Int {
        try await reg.readStamped(into: &buffer, arrival.pointer(to: \.raw)!)
    }
}

extension ReadHalf {
    /// `read(into:)`, saying in `arrival` when the bytes read arrived.
    public func read(into buffer: inout IOBuffer,
                     arrival: UnsafeMutablePointer<ReadArrival>) async throws(IOError) -> Int {
        try await reg.readStamped(into: &buffer, arrival.pointer(to: \.raw)!)
    }
}

extension IORegistration {
    /// `read(into:)` as a `recvmsg` through `arrival`, which then says when
    /// the bytes arrived.
    func readStamped(into buffer: inout IOBuffer,
                     _ arrival: UnsafeMutablePointer<cv_arrival>) async throws(IOError) -> Int {
        arrival.pointee.micros = 0
        guard buffer.spareCapacity > 0 else { return 0 }
        #if canImport(Network)
        if let nw { return try await nwRead(into: &buffer, nw) }
        #endif
        while let res = await URing.perform(.recvStamped(fd, buffer.base + buffer.count, buffer.spareCapacity,
                                                         arrival), owner: owner) {
            if res >= 0 {
                cv_arrival_settle(arrival)
                buffer.count += Int(res)
                await Runtime.consumeBudget()
                return Int(res)
            }
            try Self.retryable(res)
        }
        if io.pointee.read_drained != 0 {
            // As `read(into:)`: the last read came up short, so wait for the
            // next event rather than ask an empty socket.
            io.pointee.read_drained = 0
            if cv_io_read_closed(io) == 0, cv_io_take_ready(io, CV_IO_READ) == 0 {
                try await wait(CV_IO_READ)
            }
        }
        while true {
            let want = buffer.spareCapacity
            let n = cv_recv_stamped(fd, buffer.base + buffer.count, want, arrival)
            if n >= 0 {
                buffer.count += n
                if n > 0 && n < want { io.pointee.read_drained = 1 }
                await Runtime.consumeBudget()
                return n
            }
            let err = Int32(-n)
            switch err {
            case EAGAIN, EWOULDBLOCK: try await wait(CV_IO_READ)
            case EINTR: continue
            default: throw IOError(code: err)
            }
        }
    }
}
#endif
