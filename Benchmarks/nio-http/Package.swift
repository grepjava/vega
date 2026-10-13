// swift-tools-version: 6.2
// the-benchmarker's HTTP contract on SwiftNIO alone, against vega-http. Its
// own package, so Vega's benchmarks stay free of dependencies.
import PackageDescription

let package = Package(
    name: "nio-http",
    dependencies: [.package(url: "https://github.com/apple/swift-nio.git", from: "2.86.0")],
    targets: [
        .executableTarget(
            name: "nio-http",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
            ],
            swiftSettings: [.swiftLanguageMode(.v5), .unsafeFlags(["-enforce-exclusivity=unchecked"])]
        ),
    ]
)
