// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "VegaBenchmarks",
    platforms: [.macOS("26.4")],
    // Passed through to Vega: `swift build --traits BoringSSL` builds
    // vega-https on BoringSSL instead of the system's OpenSSL.
    traits: [
        .trait(name: "OpenSSL"),
        .trait(name: "BoringSSL"),
        .default(enabledTraits: ["OpenSSL"]),
    ],
    dependencies: [.package(path: "..", traits: [
        .trait(name: "OpenSSL", condition: .when(traits: ["OpenSSL"])),
        .trait(name: "BoringSSL", condition: .when(traits: ["BoringSSL"])),
    ])],
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
        // and Vapor (vega-nio's Examples).
        .executableTarget(
            name: "vega-http",
            dependencies: [.product(name: "Vega", package: "vega"),
                           .product(name: "VegaHTTP1", package: "vega")],
            swiftSettings: [.swiftLanguageMode(.v6), .unsafeFlags(["-enforce-exclusivity=unchecked"])]
        ),
        // vega-http over VegaTLS, for comparing TLS libraries.
        .executableTarget(
            name: "vega-https",
            dependencies: [.product(name: "Vega", package: "vega"),
                           .product(name: "VegaHTTP1", package: "vega"),
                           .product(name: "VegaTLS", package: "vega")],
            swiftSettings: [.swiftLanguageMode(.v6), .unsafeFlags(["-enforce-exclusivity=unchecked"])]
        ),
        // VegaTLS's per-record cost: request/response rounds over loopback,
        // client and server in one process.
        .executableTarget(
            name: "vega-tls-bench",
            dependencies: [.product(name: "Vega", package: "vega"),
                           .product(name: "VegaIO", package: "vega"),
                           .product(name: "VegaTLS", package: "vega")],
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
