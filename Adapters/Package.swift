// swift-tools-version: 6.2
// Vega's runtime metrics and slow polls, reported through swift-metrics and
// swift-log. Its own package, so Vega itself keeps no dependencies.
import Foundation
import PackageDescription

// Inside Vega's repository, the Vega beside it; in a repository of its own,
// the release.
let vega: Package.Dependency =
    FileManager.default.fileExists(atPath: Context.packageDirectory + "/../Sources/Vega")
    ? .package(path: "..")
    : .package(url: "https://github.com/grepjava/vega.git", from: "1.0.0")

let package = Package(
    name: "VegaAdapters",
    platforms: [.macOS("26.4"), .iOS("26.4")],
    products: [
        .library(name: "VegaSwiftMetrics", targets: ["VegaSwiftMetrics"]),
        .library(name: "VegaLogging", targets: ["VegaLogging"]),
    ],
    dependencies: [
        vega,
        .package(url: "https://github.com/apple/swift-metrics.git", from: "2.5.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.6.0"),
    ],
    targets: [
        .target(name: "VegaSwiftMetrics",
                dependencies: [.product(name: "Vega", package: "vega"),
                               .product(name: "VegaMetrics", package: "vega"),
                               .product(name: "Metrics", package: "swift-metrics")],
                swiftSettings: [.swiftLanguageMode(.v6)]),
        .target(name: "VegaLogging",
                dependencies: [.product(name: "Vega", package: "vega"),
                               .product(name: "Logging", package: "swift-log")],
                swiftSettings: [.swiftLanguageMode(.v6)]),
        .testTarget(name: "VegaAdaptersTests",
                    dependencies: ["VegaSwiftMetrics", "VegaLogging",
                                   .product(name: "Vega", package: "vega"),
                                   .product(name: "MetricsTestKit", package: "swift-metrics"),
                                   .product(name: "Logging", package: "swift-log")],
                    swiftSettings: [.swiftLanguageMode(.v6)]),
    ]
)
