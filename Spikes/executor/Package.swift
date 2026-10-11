// swift-tools-version: 6.2
import PackageDescription

let settings: [SwiftSetting] = [.swiftLanguageMode(.v6), .unsafeFlags(["-Ounchecked"])]

let package = Package(
    name: "VegaSpike",
    targets: [
        .target(name: "SpikeCore", swiftSettings: settings),
        .executableTarget(name: "spike", dependencies: ["SpikeCore"], swiftSettings: settings),
        .executableTarget(name: "spikefactory", dependencies: ["SpikeCore"], swiftSettings: settings),
    ]
)
