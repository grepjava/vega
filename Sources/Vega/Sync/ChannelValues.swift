extension Channel.Receiver where Element: Copyable {
    /// The values as an `AsyncSequence`, for `for await` and the sequence
    /// algorithms. It ends once every sender is gone and the buffer is
    /// drained, or when the task iterating is cancelled.
    ///
    /// With a bounded channel this is a producer with backpressure, as
    /// NIO's `NIOAsyncSequenceProducer`: a sender's `send` waits while the
    /// buffer is full, so a producer runs at most `capacity` values ahead
    /// of the consumer.
    ///
    /// ```swift
    /// var channel = Channel<Event>(capacity: 64)
    /// rt.spawn(with: channel.sender) { tx in for e in source { try? await tx.send(e) } }
    /// for await event in channel.receiver.values() { ... }
    /// ```
    public consuming func values() -> ChannelValues<Element> {
        ChannelValues(self)
    }
}

/// A channel receiver's values as an `AsyncSequence`
/// (`Channel.Receiver.values()`). Every iterator takes from the one
/// receiver: two at the same time trap.
public struct ChannelValues<Element: Sendable>: AsyncSequence {
    public typealias Failure = Never

    final class Box {
        var receiver: Channel<Element>.Receiver
        init(_ receiver: consuming Channel<Element>.Receiver) { self.receiver = receiver }
    }

    let box: Box

    init(_ receiver: consuming Channel<Element>.Receiver) {
        box = Box(receiver)
    }

    public func makeAsyncIterator() -> Iterator { Iterator(box: box) }

    /// Stop further sends; what is queued is still iterated.
    public func close() { box.receiver.close() }

    public struct Iterator: AsyncIteratorProtocol {
        let box: Box

        public mutating func next() async -> Element? {
            try? await box.receiver.receive()
        }

        public mutating func next(isolation actor: isolated (any Actor)?) async -> Element? {
            try? await box.receiver.receive()
        }
    }
}
