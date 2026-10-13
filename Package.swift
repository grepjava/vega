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
        .library(name: "VegaTLS", targets: ["VegaTLS"]),
        .library(name: "VegaHTTP1", targets: ["VegaHTTP1"]),
        .library(name: "VegaHTTP2", targets: ["VegaHTTP2"]),
        .library(name: "VegaTest", targets: ["VegaTest"]),
    ],
    targets: [
        .target(name: "CVega", cSettings: [.define("_GNU_SOURCE")],
                linkerSettings: [.linkedLibrary("dl", .when(platforms: [.linux])),
                                 .linkedLibrary("Synchronization", .when(platforms: [.windows])),
                                 .linkedLibrary("bcrypt", .when(platforms: [.windows])),
                                 .linkedLibrary("ws2_32", .when(platforms: [.windows])),
                                 .linkedLibrary("winmm", .when(platforms: [.windows])),
                                 .linkedLibrary("iphlpapi", .when(platforms: [.windows]))]),
        .target(name: "Vega", dependencies: ["CVega"], swiftSettings: swiftSettings),
        .target(name: "VegaIO", dependencies: ["Vega"], swiftSettings: swiftSettings),
        .target(name: "VegaFS", dependencies: ["Vega", "VegaIO", "CVega"], swiftSettings: swiftSettings),
        .target(name: "VegaProcess", dependencies: ["Vega", "VegaIO", "CVega"], swiftSettings: swiftSettings),
        .target(name: "VegaMetrics", dependencies: ["Vega"], swiftSettings: swiftSettings),
        .target(name: "VegaTest", dependencies: ["Vega", "VegaIO", "CVega"], swiftSettings: swiftSettings),
        // TLS on the system's OpenSSL (3.0+): libssl-dev on Linux, Homebrew's
        // openssl@3 on macOS; on Windows, an OpenSSL whose include and lib
        // directories are on INCLUDE and LIB. Only the C target sees its headers.
        .systemLibrary(name: "COpenSSL", pkgConfig: "openssl",
                       providers: [.apt(["libssl-dev"]), .brew(["openssl@3"]), .yum(["openssl-devel"])]),
        .target(name: "CVegaTLS", dependencies: [.target(name: "COpenSSL", condition: .when(platforms: [.linux, .macOS, .windows]))],
                linkerSettings: [.linkedLibrary("ssl", .when(platforms: [.linux, .macOS])),
                                 .linkedLibrary("crypto", .when(platforms: [.linux, .macOS])),
                                 .linkedLibrary("libssl", .when(platforms: [.windows])),
                                 .linkedLibrary("libcrypto", .when(platforms: [.windows])),
                                 .linkedLibrary("crypt32", .when(platforms: [.windows]))]),
        .target(name: "VegaTLS", dependencies: ["Vega", "VegaIO", "CVegaTLS"], swiftSettings: swiftSettings),
        .target(name: "VegaHTTP1", dependencies: ["Vega", "VegaIO"], swiftSettings: swiftSettings),
        .target(name: "VegaHTTP2", dependencies: ["Vega", "VegaIO", "VegaHTTP1"], swiftSettings: swiftSettings),
        .testTarget(name: "VegaTests", dependencies: ["Vega", "VegaIO", "VegaFS", "VegaProcess", "VegaMetrics", "VegaTest", "VegaTLS", "VegaHTTP1", "VegaHTTP2", "CVega"], swiftSettings: swiftSettings),
    ],
    cLanguageStandard: .gnu11
)
