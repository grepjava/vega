// swift-tools-version: 6.2
import PackageDescription

let swiftSettings: [SwiftSetting] = [.swiftLanguageMode(.v6)]

let package = Package(
    name: "Vega",
    // Replacing the global executor needs the custom-executor runtime (macOS/iOS 26.4).
    platforms: [.macOS("26.4"), .iOS("26.4")],
    products: [
        .library(name: "Vega", targets: ["Vega"]),
        .library(name: "VegaIO", targets: ["VegaIO"]),
        .library(name: "VegaFS", targets: ["VegaFS"]),
        .library(name: "VegaProcess", targets: ["VegaProcess"]),
        .library(name: "VegaMetrics", targets: ["VegaMetrics"]),
        .library(name: "VegaTest", targets: ["VegaTest"]),
    ],
    targets: [
        .target(name: "CVega", cSettings: [.define("_GNU_SOURCE")],
                linkerSettings: [.linkedLibrary("dl", .when(platforms: [.linux])),
                                 .linkedLibrary("Synchronization", .when(platforms: [.windows])),
                                 .linkedLibrary("bcrypt", .when(platforms: [.windows])),
                                 .linkedLibrary("ws2_32", .when(platforms: [.windows])),
                                 .linkedLibrary("winmm", .when(platforms: [.windows]))]),
        .target(name: "Vega", dependencies: ["CVega"], swiftSettings: swiftSettings),
        .target(name: "VegaIO", dependencies: ["Vega"], swiftSettings: swiftSettings),
        .target(name: "VegaFS", dependencies: ["Vega", "VegaIO", "CVega"], swiftSettings: swiftSettings),
        .target(name: "VegaProcess", dependencies: ["Vega", "VegaIO", "CVega"], swiftSettings: swiftSettings),
        .target(name: "VegaMetrics", dependencies: ["Vega"], swiftSettings: swiftSettings),
        .target(name: "VegaTest", dependencies: ["Vega", "VegaIO", "CVega"], swiftSettings: swiftSettings),
        .testTarget(name: "VegaTests", dependencies: ["Vega", "VegaIO", "VegaFS", "VegaProcess", "VegaMetrics", "VegaTest", "CVega"], swiftSettings: swiftSettings),
    ],
    cLanguageStandard: .gnu11
)
