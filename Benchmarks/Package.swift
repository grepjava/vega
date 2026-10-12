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
    ]
)
