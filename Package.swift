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
        .library(name: "VegaCompression", targets: ["VegaCompression"]),
        .library(name: "VegaProxy", targets: ["VegaProxy"]),
        // A protocol's networked module has its plain name; its logic, sans
        // I/O, is in its Core module, for servers that bring their own I/O.
        .library(name: "VegaHTTP", targets: ["VegaHTTP"]),
        .library(name: "VegaHTTP1", targets: ["VegaHTTP1"]),
        .library(name: "VegaHTTP2", targets: ["VegaHTTP2"]),
        .library(name: "VegaHTTP3", targets: ["VegaHTTP3"]),
        .library(name: "VegaWebSocket", targets: ["VegaWebSocket"]),
        .library(name: "VegaQUIC", targets: ["VegaQUIC"]),
        .library(name: "VegaWire", targets: ["VegaWire"]),
        .library(name: "VegaHTTP1Core", targets: ["VegaHTTP1Core"]),
        .library(name: "VegaHTTP2Core", targets: ["VegaHTTP2Core"]),
        .library(name: "VegaHTTP3Core", targets: ["VegaHTTP3Core"]),
        .library(name: "VegaWebSocketCore", targets: ["VegaWebSocketCore"]),
        .library(name: "VegaQUICCore", targets: ["VegaQUICCore"]),
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
                            .define("NOCRYPT", .when(platforms: [.windows])),
                            // Its assembly is ELF and Mach-O only (Windows'
                            // is NASM, which SwiftPM cannot build): the C
                            // implementations instead.
                            .define("OPENSSL_NO_ASM", .when(platforms: [.windows]))],
                cxxSettings: [.define("_WINSOCKAPI_", .when(platforms: [.windows])),
                              .define("NOMINMAX", .when(platforms: [.windows])),
                              .define("NOCRYPT", .when(platforms: [.windows])),
                              .define("OPENSSL_NO_ASM", .when(platforms: [.windows]))]),
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
        .target(name: "VegaTLS", dependencies: ["Vega", "VegaIO", "CVegaTLS", "CVega"], swiftSettings: swiftSettings),
        // Hashes, HMAC, HKDF, AEADs, key exchange and signatures, over the
        // same library as VegaTLS (and empty without one).
        .target(name: "VegaCrypto", dependencies: ["CVegaTLS"], swiftSettings: swiftSettings),
        // gzip and deflate on the system's zlib; brotli and zstd loaded with
        // dlopen when there. On Windows (no zlib in its SDK) gzip and
        // deflate are on CVegaZlib, and there is no brotli or zstd yet.
        .target(name: "CVegaCompress",
                dependencies: [.target(name: "CVegaZlib", condition: .when(platforms: [.windows]))],
                linkerSettings: [.linkedLibrary("z", .when(platforms: [.linux, .macOS, .iOS])),
                                 .linkedLibrary("dl", .when(platforms: [.linux]))]),
        // zlib 1.3.1, vendored for Windows: deflate and inflate only, its
        // names z_-prefixed so that it can't collide with another zlib in
        // the process. Its VENDORING.md says where it came from.
        .target(name: "CVegaZlib", exclude: ["VENDORING.md", "LICENSE", "README"],
                cSettings: [.define("Z_PREFIX"),
                            .define("_CRT_SECURE_NO_WARNINGS", .when(platforms: [.windows])),
                            .define("_CRT_NONSTDC_NO_DEPRECATE", .when(platforms: [.windows]))]),
        // Sans I/O, pure Swift. VegaWire is the bytes they share: ByteBuffer,
        // ByteSpan and the parsing helpers. Vendored from aviancore through
        // Garuda; see its VENDORED.md.
        .target(name: "VegaWire", exclude: ["VENDORED.md"], swiftSettings: swiftSettings),
        // HTTP/1.1 (RFC 9112) head and body parsing.
        .target(name: "VegaHTTP1Core", dependencies: ["VegaHTTP", "VegaWire"], swiftSettings: swiftSettings),
        // HPACK (RFC 7541) and HTTP/2 frame headers (RFC 9113).
        .target(name: "VegaHTTP2Core", dependencies: ["VegaWire"], swiftSettings: swiftSettings),
        // HTTP/3 (RFC 9114) framing, QPACK (RFC 9204, on HPACK's Huffman
        // code), capsules (RFC 9297), and the WebSocket (RFC 9220) and
        // WebTransport identifiers.
        .target(name: "VegaHTTP3Core", dependencies: ["VegaWire", "VegaHTTP2Core"], swiftSettings: swiftSettings),
        // WebSocket frames (RFC 6455) and permessage-deflate negotiation (RFC 7692).
        .target(name: "VegaWebSocketCore", dependencies: ["VegaWire"], swiftSettings: swiftSettings),
        // QUIC (RFC 9000, 9001, 9002): a connection is handed datagrams and
        // asked for them. TLS 1.3 is its own, over VegaCrypto.
        .target(name: "VegaQUICCore", dependencies: ["VegaWire", "VegaCrypto"], swiftSettings: swiftSettings),
        // The types every HTTP version shares: methods, heads, fields, whole
        // requests and responses. VegaHTTP1, VegaHTTP2 and VegaHTTP3 re-export it.
        .target(name: "VegaHTTP", dependencies: ["VegaWire"], swiftSettings: swiftSettings),
        .target(name: "VegaHTTP1", dependencies: ["Vega", "VegaIO", "VegaHTTP", "VegaHTTP1Core", "VegaWire"],
                swiftSettings: swiftSettings),
        .target(name: "VegaHTTP2", dependencies: ["Vega", "VegaIO", "VegaHTTP", "VegaWire", "VegaHTTP2Core"],
                swiftSettings: swiftSettings),
        .target(name: "VegaWebSocket", dependencies: ["Vega", "VegaIO", "VegaHTTP", "VegaHTTP1", "VegaWire", "VegaWebSocketCore",
                                                     "CVegaCompress"],
                swiftSettings: swiftSettings),
        // VegaQUICCore's connections on Vega's UDP sockets: an endpoint task
        // per socket, and connections and streams for the application's tasks.
        .target(name: "VegaQUIC", dependencies: ["Vega", "VegaIO", "VegaQUICCore", "VegaWire", "VegaCrypto", "CVega"],
                swiftSettings: swiftSettings),
        // HTTP/3 over VegaQUIC: a server and a client with whole bodies, as VegaHTTP2's.
        .target(name: "VegaHTTP3", dependencies: ["Vega", "VegaIO", "VegaHTTP", "VegaHTTP3Core", "VegaHTTP2Core",
                                                 "VegaQUICCore", "VegaQUIC", "VegaWire", "VegaCrypto"],
                swiftSettings: swiftSettings),
        // Content codings: gzip, deflate, brotli, zstd.
        .target(name: "VegaCompression", dependencies: ["VegaHTTP", "CVegaCompress"], swiftSettings: swiftSettings),
        // Connecting through SOCKS5 and HTTP CONNECT proxies.
        .target(name: "VegaProxy", dependencies: ["Vega", "VegaIO", "VegaHTTP", "VegaHTTP1"], swiftSettings: swiftSettings),
        // The servers h2spec, Autobahn and aioquic test (ci/conformance.sh).
        .executableTarget(name: "vega-conformance", dependencies: ["Vega", "VegaHTTP", "VegaHTTP1", "VegaHTTP2", "VegaWebSocket", "VegaTLS",
                                                                "VegaCrypto", "VegaQUICCore", "VegaQUIC", "VegaHTTP3"],
                          swiftSettings: swiftSettings),
        .testTarget(name: "VegaTests", dependencies: ["Vega", "VegaIO", "VegaFS", "VegaProcess", "VegaMetrics", "VegaTest", "VegaTLS", "VegaCrypto", "VegaHTTP", "VegaHTTP1", "VegaHTTP2", "VegaHTTP2Core", "VegaWebSocket", "VegaWebSocketCore", "VegaCompression", "VegaProxy", "VegaWire", "CVega"], swiftSettings: swiftSettings),
        .testTarget(name: "VegaWireTests", dependencies: ["VegaWire", "VegaHTTP2Core", "VegaHTTP3Core", "VegaWebSocketCore"], swiftSettings: swiftSettings),
        // A QUIC client for the tests: a handshake and streams against a VegaQUICCore server.
        .target(name: "QUICTestPeer", dependencies: ["VegaQUICCore", "VegaWire", "VegaCrypto", "VegaTLS"],
                path: "Tests/QUICTestPeer", swiftSettings: swiftSettings),
        .testTarget(name: "VegaQUICTests", dependencies: ["VegaQUICCore", "VegaWire", "QUICTestPeer", "VegaCrypto", "VegaTLS",
                                                         "VegaQUIC", "VegaHTTP3", "VegaHTTP3Core", "VegaHTTP", "VegaHTTP1",
                                                         "Vega", "VegaIO"],
                    swiftSettings: swiftSettings),
    ],
    cLanguageStandard: .gnu11,
    cxxLanguageStandard: .gnucxx17
)
