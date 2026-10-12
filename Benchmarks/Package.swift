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
        // Checks Vega as the process-wide executor; tests can't install it
        // because the test runner has created tasks by then.
        .executableTarget(
            name: "vega-global-check",
            dependencies: [.product(name: "Vega", package: "vega")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
