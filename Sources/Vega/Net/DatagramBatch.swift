#if os(Linux) || canImport(Darwin) || os(Windows)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// A set of datagrams in one block of memory, for receiving or sending many
/// with one system call (`recvmmsg` / `sendmmsg`).
///
/// ```swift
/// var batch = DatagramBatch(capacity: 32, slotSize: 1500)
/// while true {
///     let n = try await socket.receive(&batch)
///     var replies = DatagramBatch(capacity: n)
///     for i in 0..<n { replies.append(batch[i], to: batch.address(at: i)) }
///     try await socket.send(replies)
/// }
/// ```
///
/// Each datagram has a slot of `slotSize` bytes; one that arrives longer is
/// cut short and flagged (`isTruncated(at:)`). Allocated once: receiving
/// into a batch and refilling it allocate nothing.
///
/// A server bound to a wildcard address must answer from the address the
/// client reached, or NAT and the client drop the answer: with
/// `UDPSocket.enablePathInfo()` on, `localAddress(at:)` says where each
/// datagram arrived, and `append(_:to:from:ecn:)` sends from there.
public struct DatagramBatch: ~Copyable, @unchecked Sendable {
    let storage: UnsafeMutableRawPointer
    let lengths: UnsafeMutablePointer<UInt32>
    let flags: UnsafeMutablePointer<UInt32>
    let addresses: UnsafeMutablePointer<cv_sockaddr>
    let paths: UnsafeMutablePointer<cv_dgram_path>
    /// Whether a datagram to send has a source address or ECN bits.
    var sendsPaths = false
    /// Most datagrams the batch holds.
    public let capacity: Int
    /// Bytes per datagram.
    public let slotSize: Int
    /// Datagrams in the batch now.
    public internal(set) var count = 0

    public init(capacity: Int = 32, slotSize: Int = 1500) {
        precondition(capacity > 0 && slotSize > 0, "a DatagramBatch needs room")
        self.capacity = capacity
        self.slotSize = slotSize
        storage = .allocate(byteCount: capacity * slotSize, alignment: 16)
        lengths = .allocate(capacity: capacity)
        lengths.initialize(repeating: 0, count: capacity)
        flags = .allocate(capacity: capacity)
        flags.initialize(repeating: 0, count: capacity)
        addresses = .allocate(capacity: capacity)
        addresses.initialize(repeating: cv_sockaddr(), count: capacity)
        paths = .allocate(capacity: capacity)
        paths.initialize(repeating: cv_dgram_path(), count: capacity)
    }

    deinit {
        storage.deallocate()
        lengths.deallocate()
        flags.deallocate()
        addresses.deallocate()
        paths.deallocate()
    }

    public var isEmpty: Bool { count == 0 }
    public var isFull: Bool { count == capacity }

    /// The bytes of datagram `i`, valid until the batch changes.
    public subscript(i: Int) -> UnsafeRawBufferPointer {
        precondition(i >= 0 && i < count, "DatagramBatch index out of range")
        return UnsafeRawBufferPointer(start: storage + i * slotSize, count: Int(lengths[i]))
    }

    /// The sender of received datagram `i`, or the destination given to
    /// `append` (nil: the connected peer).
    public func address(at i: Int) -> SocketAddress? {
        precondition(i >= 0 && i < count, "DatagramBatch index out of range")
        return addresses[i].len == 0 ? nil : SocketAddress(raw: addresses[i])
    }

    /// Whether received datagram `i` was longer than `slotSize` and cut short.
    public func isTruncated(at i: Int) -> Bool {
        precondition(i >= 0 && i < count, "DatagramBatch index out of range")
        return flags[i] & CV_DGRAM_TRUNCATED != 0
    }

    /// The local address received datagram `i` arrived on, once the socket
    /// has `enablePathInfo()` on; otherwise nil. Or the source given to
    /// `append`.
    public func localAddress(at i: Int) -> SocketAddress? {
        precondition(i >= 0 && i < count, "DatagramBatch index out of range")
        return paths[i].local.len == 0 ? nil : SocketAddress(raw: paths[i].local)
    }

    /// The ECN bits of received datagram `i` (0 Not-ECT, 1 ECT(1), 2 ECT(0),
    /// 3 CE), once the socket has `enablePathInfo()` on; otherwise 0.
    public func ecn(at i: Int) -> UInt8 {
        precondition(i >= 0 && i < count, "DatagramBatch index out of range")
        return UInt8(truncatingIfNeeded: paths[i].ecn)
    }

    public mutating func removeAll() {
        count = 0
        sendsPaths = false
    }

    /// Add a datagram to send to `address` (nil: the connected peer), from
    /// the local address `source` (nil: the kernel's choice) with ECN bits
    /// `ecn`. False, adding nothing, if the batch is full or `bytes` exceeds
    /// `slotSize`.
    @discardableResult
    public mutating func append(_ bytes: UnsafeRawBufferPointer, to address: SocketAddress? = nil,
                                from source: SocketAddress? = nil, ecn: UInt8 = 0) -> Bool {
        append(to: address, from: source, ecn: ecn) { slot in
            guard bytes.count <= slot.count else { return -1 }
            if bytes.count > 0 { slot.baseAddress!.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count) }
            return bytes.count
        }
    }

    /// Add a datagram written in place: `fill` gets the slot and returns the
    /// bytes it wrote, or a negative number to add nothing. False if the
    /// batch is full or `fill` declined.
    @discardableResult
    public mutating func append<E: Error>(
        to address: SocketAddress? = nil,
        from source: SocketAddress? = nil,
        ecn: UInt8 = 0,
        _ fill: (UnsafeMutableRawBufferPointer) throws(E) -> Int
    ) throws(E) -> Bool {
        guard count < capacity else { return false }
        let n = try fill(UnsafeMutableRawBufferPointer(start: storage + count * slotSize, count: slotSize))
        guard n >= 0 else { return false }
        precondition(n <= slotSize, "wrote past the end of a DatagramBatch slot")
        lengths[count] = UInt32(n)
        flags[count] = 0
        addresses[count] = address?.raw ?? cv_sockaddr()
        paths[count] = cv_dgram_path(local: source?.raw ?? cv_sockaddr(), ecn: UInt32(ecn & 3))
        if source != nil || ecn != 0 { sendsPaths = true }
        count += 1
        return true
    }
}

/// Most datagrams one cv_recv_batch / cv_send_batch call moves.
private let batchChunk = 64

extension UDPSocket {
    /// Receive as many queued datagrams as fit in `batch`, at least one,
    /// replacing what it held. Returns how many arrived. One system call
    /// takes up to 64.
    public func receive(_ batch: inout DatagramBatch) async throws(IOError) -> Int {
        let fd = reg.fd, stride = batch.slotSize, capacity = batch.capacity
        let storage = batch.storage, addresses = batch.addresses
        let lengths = batch.lengths, flags = batch.flags, paths = batch.paths
        batch.count = 0
        batch.sendsPaths = false
        var got = try await reg.perform(CV_IO_READ) {
            cv_recv_batch(fd, storage, stride, Int32(min(capacity, batchChunk)), addresses, lengths, flags, paths)
        }
        // A full chunk may mean more is queued: take it without waiting.
        var last = got
        while last == batchChunk && got < capacity {
            let n = cv_recv_batch(fd, storage + got * stride, stride, Int32(min(capacity - got, batchChunk)),
                                  addresses + got, lengths + got, flags + got, paths + got)
            if n <= 0 { break }
            got += n
            last = n
        }
        batch.count = got
        return got
    }

    /// Send every datagram in `batch`, each to its address (or the connected
    /// peer), up to 64 per system call.
    public func send(_ batch: borrowing DatagramBatch) async throws(IOError) {
        let fd = reg.fd, stride = batch.slotSize, total = batch.count
        let storage = batch.storage, addresses = batch.addresses, lengths = batch.lengths
        let paths: UnsafeMutablePointer<cv_dgram_path>? = batch.sendsPaths ? batch.paths : nil
        var sent = 0
        while sent < total {
            let from = sent
            sent += try await reg.perform(CV_IO_WRITE) {
                cv_send_batch(fd, storage + from * stride, stride, lengths + from, addresses + from,
                              Int32(min(total - from, batchChunk)), paths.map { $0 + from })
            }
        }
    }

    /// Have `receive(_:)` report the local address each datagram arrived on
    /// and its ECN bits (`DatagramBatch.localAddress(at:)`, `ecn(at:)`):
    /// what a server bound to a wildcard address needs to answer from the
    /// address the client reached. Not on Windows yet.
    public func enablePathInfo(_ on: Bool = true) throws(IOError) {
        let e = cv_udp_path_info(reg.fd, on ? 1 : 0)
        if e != 0 { throw IOError(code: e) }
    }

    /// Set the don't-fragment bit on every datagram sent: one too large for
    /// the path fails (or is dropped on the way) rather than being split
    /// into IP fragments. QUIC requires it.
    public func setDontFragment(_ on: Bool = true) throws(IOError) {
        let e = cv_udp_dont_fragment(reg.fd, on ? 1 : 0)
        if e != 0 { throw IOError(code: e) }
    }

    /// Whether the kernel splits a segmented send itself (UDP GSO; Linux
    /// 4.18 and later). Without it, `send(segments:segmentSize:to:)` still
    /// works, one datagram per segment.
    public var supportsSegmentation: Bool { cv_udp_gso_supported(reg.fd) != 0 }

    /// Send `bytes` as datagrams of `segmentSize` bytes each (the last may
    /// be shorter). With UDP GSO it is one system call: the kernel splits
    /// them below the socket, so a burst costs one syscall and one route
    /// lookup. Where the kernel or the route can't, the segments go out as a
    /// batch instead. To `address`, or the connected peer if nil; from the
    /// local address `source` (nil: the kernel's choice) with ECN bits
    /// `ecn`. At most 64 segments, and 64 KB in all. Returns the bytes sent.
    @discardableResult
    public func send(segments bytes: UnsafeRawBufferPointer, segmentSize: Int,
                     to address: SocketAddress? = nil, from source: SocketAddress? = nil,
                     ecn: UInt8 = 0) async throws(IOError) -> Int {
        precondition(segmentSize > 0 && segmentSize <= Int(UInt16.max), "bad UDP segment size")
        precondition((bytes.count + segmentSize - 1) / segmentSize <= 64, "more than 64 UDP segments")
        let fd = reg.fd, base = bytes.baseAddress, total = bytes.count
        var to = address?.raw ?? cv_sockaddr()
        var path = cv_dgram_path(local: source?.raw ?? cv_sockaddr(), ecn: UInt32(ecn & 3))
        let hasPath = source != nil || ecn != 0
        // A batch that fills the socket stops after whole segments: go on
        // from there.
        var sent = 0
        repeat {
            let from = sent
            sent += try await reg.perform(CV_IO_WRITE) {
                hasPath
                    ? cv_send_segments(fd, base.map { $0 + from }, total - from, Int32(segmentSize), &to, &path)
                    : cv_send_segments(fd, base.map { $0 + from }, total - from, Int32(segmentSize), &to, nil)
            }
        } while sent < total
        return sent
    }

    /// Receive into `buffer`'s spare capacity with UDP GRO: once
    /// `SocketOption.udpGRO` is set, several datagrams from one sender can
    /// arrive together, each `segmentSize` bytes (the last may be shorter).
    /// `segmentSize` is 0 when one datagram came alone. The kernel coalesces
    /// up to 64 KB, so leave that much room: `truncated` says the arrival
    /// was longer than the spare capacity and its tail was lost.
    public func receiveSegments(into buffer: inout IOBuffer) async throws(IOError)
        -> (count: Int, segmentSize: Int, from: SocketAddress, truncated: Bool)
    {
        precondition(buffer.spareCapacity > 0, "receive into a full IOBuffer")
        let fd = reg.fd
        let at = buffer.base + buffer.count, room = buffer.spareCapacity
        var from = cv_sockaddr()
        var segment: Int32 = 0
        var flags: UInt32 = 0
        let n = try await reg.perform(CV_IO_READ) { cv_recv_segments(fd, at, room, &from, &segment, &flags) }
        buffer.readable += n
        return (n, Int(segment), SocketAddress(raw: from), flags & CV_DGRAM_TRUNCATED != 0)
    }

    /// Join the multicast group `group` (IPv4 or IPv6) on the interface with
    /// index `interface` (0: the kernel's choice).
    public func joinMulticastGroup(_ group: SocketAddress, interface: UInt32 = 0) throws(IOError) {
        let e = withUnsafePointer(to: group.raw) { cv_multicast(reg.fd, $0, interface, 1) }
        if e != 0 { throw IOError(code: e) }
    }

    public func leaveMulticastGroup(_ group: SocketAddress, interface: UInt32 = 0) throws(IOError) {
        let e = withUnsafePointer(to: group.raw) { cv_multicast(reg.fd, $0, interface, 0) }
        if e != 0 { throw IOError(code: e) }
    }
}
#endif
