// swift-tools-version: 6.2
// SwiftNIO echo server for the echo benchmark. Its own package, so Vega's
// benchmarks stay free of dependencies.
import PackageDescription

let package = Package(
    name: "nio-echo",
    dependencies: [.package(url: "https://github.com/apple/swift-nio.git", from: "2.86.0")],
    targets: [
        .executableTarget(
            name: "nio-echo",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
            ],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
