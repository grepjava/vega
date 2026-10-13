// swift-tools-version: 6.2
// VegaNIO: SwiftNIO's EventLoopGroup, Channel and bootstraps over Vega. Its
// own package, so Vega itself keeps no dependencies.
import PackageDescription

let package = Package(
    name: "VegaNIO",
    platforms: [.macOS("26.4"), .iOS("26.4")],
    products: [
        .library(name: "VegaNIO", targets: ["VegaNIO"]),
    ],
    dependencies: [
        .package(path: ".."),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.86.0"),
    ],
    targets: [
        .target(
            name: "VegaNIO",
            dependencies: [
                .product(name: "Vega", package: "vega"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "VegaNIOTests",
            dependencies: [
                "VegaNIO",
                .product(name: "Vega", package: "vega"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
