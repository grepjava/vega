// swift-tools-version: 6.2
import PackageDescription

// Nonsending by default: an async function runs on its caller's executor,
// so returning from one is no hop. Each hop asks the runtime for the task's
// preferred executor under the task's status lock, and Vega's tasks all
// prefer one.
let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
]

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
        .library(name: "VegaCrypto", targets: ["VegaCrypto"]),
        .library(name: "VegaHTTP1", targets: ["VegaHTTP1"]),
        .library(name: "VegaHTTP2", targets: ["VegaHTTP2"]),
        .library(name: "VegaWebSocket", targets: ["VegaWebSocket"]),
        .library(name: "VegaExtras", targets: ["VegaExtras"]),
        .library(name: "VegaTest", targets: ["VegaTest"]),
    ],
    // The TLS library under VegaTLS. A dependent picks BoringSSL with
    //   .package(url: "https://github.com/grepjava/vega.git", from: ..., traits: ["BoringSSL"])
    // and a build of this package with `swift build --traits BoringSSL`.
    traits: [
        .trait(name: "OpenSSL", description: "VegaTLS on the system's OpenSSL 3 (the default)."),
        .trait(name: "BoringSSL",
               description: "VegaTLS on the vendored BoringSSL in Sources/CVegaBoringSSL: cheaper handshakes, no system OpenSSL needed. Wins if OpenSSL is enabled too."),
        .default(enabledTraits: ["OpenSSL"]),
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
        // TLS on the system's OpenSSL (3.0+) with the OpenSSL trait:
        // libssl-dev on Linux, Homebrew's openssl@3 on macOS; on Windows, an
        // OpenSSL whose include and lib directories are on INCLUDE and LIB.
        // Only the C target sees its headers.
        .systemLibrary(name: "COpenSSL", pkgConfig: "openssl",
                       providers: [.apt(["libssl-dev"]), .brew(["openssl@3"]), .yum(["openssl-devel"])]),
        // BoringSSL, vendored and prefixed CVegaBoringSSL, with the BoringSSL
        // trait. Its VENDORING.md says where it came from and how to update it.
        .target(name: "CVegaBoringSSL",
                cSettings: [.define("_GNU_SOURCE"),
                            .define("_POSIX_C_SOURCE", to: "200112L"),
                            .define("_DARWIN_C_SOURCE"),
                            // Recent Windows SDKs pull in headers whose symbols
                            // collide with BoringSSL's.
                            .define("_WINSOCKAPI_", .when(platforms: [.windows])),
                            .define("NOMINMAX", .when(platforms: [.windows])),
                            .define("NOCRYPT", .when(platforms: [.windows]))],
                cxxSettings: [.define("_WINSOCKAPI_", .when(platforms: [.windows])),
                              .define("NOMINMAX", .when(platforms: [.windows])),
                              .define("NOCRYPT", .when(platforms: [.windows]))]),
        .target(name: "CVegaTLS",
                dependencies: [.target(name: "COpenSSL", condition: .when(platforms: [.linux, .macOS, .windows], traits: ["OpenSSL"])),
                               .target(name: "CVegaBoringSSL", condition: .when(traits: ["BoringSSL"]))],
                cSettings: [.define("VEGA_TLS_OPENSSL", .when(traits: ["OpenSSL"])),
                            .define("VEGA_TLS_BORINGSSL", .when(traits: ["BoringSSL"]))],
                linkerSettings: [.linkedLibrary("ssl", .when(platforms: [.linux, .macOS], traits: ["OpenSSL"])),
                                 .linkedLibrary("crypto", .when(platforms: [.linux, .macOS], traits: ["OpenSSL"])),
                                 .linkedLibrary("libssl", .when(platforms: [.windows], traits: ["OpenSSL"])),
                                 .linkedLibrary("libcrypto", .when(platforms: [.windows], traits: ["OpenSSL"])),
                                 .linkedLibrary("crypt32", .when(platforms: [.windows]))]),
        .target(name: "VegaTLS", dependencies: ["Vega", "VegaIO", "CVegaTLS"], swiftSettings: swiftSettings),
        // Hashes, HMAC, HKDF, AEADs, key exchange and signatures, over the
        // same library as VegaTLS (and empty without one).
        .target(name: "VegaCrypto", dependencies: ["CVegaTLS"], swiftSettings: swiftSettings),
        // gzip and deflate on the system's zlib; brotli and zstd loaded with
        // dlopen when there. None yet on Windows (no zlib in its SDK).
        .target(name: "CVegaCompress",
                linkerSettings: [.linkedLibrary("z", .when(platforms: [.linux, .macOS, .iOS])),
                                 .linkedLibrary("dl", .when(platforms: [.linux]))]),
        .target(name: "VegaHTTP1", dependencies: ["Vega", "VegaIO"], swiftSettings: swiftSettings),
        .target(name: "VegaHTTP2", dependencies: ["Vega", "VegaIO", "VegaHTTP1"], swiftSettings: swiftSettings),
        .target(name: "VegaWebSocket", dependencies: ["Vega", "VegaIO", "VegaHTTP1", "CVegaCompress"], swiftSettings: swiftSettings),
        .target(name: "VegaExtras", dependencies: ["Vega", "VegaIO", "VegaHTTP1", "CVegaCompress"], swiftSettings: swiftSettings),
        .testTarget(name: "VegaTests", dependencies: ["Vega", "VegaIO", "VegaFS", "VegaProcess", "VegaMetrics", "VegaTest", "VegaTLS", "VegaCrypto", "VegaHTTP1", "VegaHTTP2", "VegaWebSocket", "VegaExtras", "CVega"], swiftSettings: swiftSettings),
    ],
    cLanguageStandard: .gnu11,
    cxxLanguageStandard: .gnucxx17
)
