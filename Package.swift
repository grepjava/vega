// swift-tools-version: 6.2
import PackageDescription

let swiftSettings: [SwiftSetting] = [.swiftLanguageMode(.v6)]

let package = Package(
    name: "Vega",
    // Replacing the global executor needs the custom-executor runtime (macOS/iOS 26.4).
    platforms: [.macOS("26.4"), .iOS("26.4")],
    products: [
        .library(name: "Vega", targets: ["Vega"]),
        .library(name: "VegaTest", targets: ["VegaTest"]),
    ],
    targets: [
        .target(name: "CVega", cSettings: [.define("_GNU_SOURCE")],
                linkerSettings: [.linkedLibrary("dl", .when(platforms: [.linux]))]),
        .target(name: "Vega", dependencies: ["CVega"], swiftSettings: swiftSettings),
        .target(name: "VegaTest", dependencies: ["Vega"], swiftSettings: swiftSettings),
        .testTarget(name: "VegaTests", dependencies: ["Vega", "VegaTest", "CVega"], swiftSettings: swiftSettings),
    ],
    cLanguageStandard: .gnu11
)
