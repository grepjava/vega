// swift-tools-version: 6.2
// Vapor 4 serving on VegaNIO. Run ./setup.sh first: it fetches Vapor and
// applies ../vapor-make-bootstrap.patch.
import PackageDescription

let package = Package(
    name: "VaporHello",
    platforms: [.macOS("26.4")],
    dependencies: [
        .package(path: "../.."),
        .package(path: ".deps/vapor"),
        .package(url: "https://github.com/swift-server/async-http-client.git", from: "1.24.0"),
    ],
    targets: [
        .target(
            name: "VaporVega",
            dependencies: [
                .product(name: "VegaNIO", package: "veganio"),
                .product(name: "Vapor", package: "vapor"),
            ]
        ),
        .executableTarget(
            name: "VaporHello",
            dependencies: [
                "VaporVega",
                .product(name: "VegaNIO", package: "veganio"),
                .product(name: "Vapor", package: "vapor"),
            ]
        ),
        .testTarget(
            name: "VaporHelloTests",
            dependencies: [
                "VaporVega",
                .product(name: "VegaNIO", package: "veganio"),
                .product(name: "Vapor", package: "vapor"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
            ]
        ),
    ]
)
