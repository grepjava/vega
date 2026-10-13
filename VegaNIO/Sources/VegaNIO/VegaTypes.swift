import Vega

// Vega and NIOCore both name a Channel, a SocketAddress and an IOError, so
// the files that use NIO import only the Vega types they need, and these
// names stand for the rest.
typealias VegaAddress = Vega.SocketAddress
typealias VegaIOError = Vega.IOError
