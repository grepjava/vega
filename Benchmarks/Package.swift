// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "VegaBenchmarks",
    platforms: [.macOS("26.4")],
    dependencies: [.package(path: "..")],
    targets: [
        .executableTarget(
            name: "vega-bench",
            dependencies: [.product(name: "Vega", package: "vega")],
            swiftSettings: [.swiftLanguageMode(.v6), .unsafeFlags(["-enforce-exclusivity=unchecked"])]
        ),
        // TCP echo server, driven by tokio-bench's echo-load.
        .executableTarget(
            name: "vega-echo",
            dependencies: [.product(name: "Vega", package: "vega")],
            swiftSettings: [.swiftLanguageMode(.v6), .unsafeFlags(["-enforce-exclusivity=unchecked"])]
        ),
        // the-benchmarker's HTTP contract on VegaHTTP1, against Hummingbird
        // and Vapor (VegaNIO/Examples).
        .executableTarget(
            name: "vega-http",
            dependencies: [.product(name: "Vega", package: "vega"),
                           .product(name: "VegaHTTP1", package: "vega")],
            swiftSettings: [.swiftLanguageMode(.v6), .unsafeFlags(["-enforce-exclusivity=unchecked"])]
        ),
        // UDP echo server, driven by tokio-bench's udp-load.
        .executableTarget(
            name: "vega-udp",
            dependencies: [.product(name: "Vega", package: "vega")],
            swiftSettings: [.swiftLanguageMode(.v6), .unsafeFlags(["-enforce-exclusivity=unchecked"])]
        ),
        // Checks Vega as the process-wide executor; tests can't install it
        // because the test runner has created tasks by then.
        .executableTarget(
            name: "vega-global-check",
            dependencies: [.product(name: "Vega", package: "vega")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // Runtime.sharded end to end: shards, crash restart, reload, stop.
        .executableTarget(
            name: "vega-shard-check",
            dependencies: [.product(name: "Vega", package: "vega"),
                           .product(name: "VegaProcess", package: "vega")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
