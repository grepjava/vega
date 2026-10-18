import Testing
import Vega

@Suite struct IOBufferTests {
    @Test func consumeAndRemoveLastTrimEachEnd() {
        var buffer = IOBuffer(capacity: 16)
        buffer.append("head-body-tail")
        buffer.consume(5)
        #expect(buffer.string == "body-tail")
        buffer.removeLast(5)
        #expect(buffer.string == "body")
        buffer.removeLast(4)
        #expect(buffer.count == 0)
    }
}
