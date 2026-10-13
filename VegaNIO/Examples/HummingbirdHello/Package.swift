// swift-tools-version: 6.2
// Hummingbird 2 serving on VegaNIO. Run ./setup.sh first: it fetches
// Hummingbird and applies ../hummingbird-make-bootstrap.patch.
import PackageDescription

let package = Package(
    name: "HummingbirdHello",
    platforms: [.macOS("26.4")],
    dependencies: [
        .package(path: "../.."),
        .package(path: ".deps/hummingbird"),
    ],
    targets: [
        .target(
            name: "HummingbirdVega",
            dependencies: [
                .product(name: "VegaNIO", package: "veganio"),
                .product(name: "Hummingbird", package: "hummingbird"),
            ],
            path: "Sources/HummingbirdVega"
        ),
        .executableTarget(
            name: "HummingbirdHello",
            dependencies: [
                "HummingbirdVega",
                .product(name: "VegaNIO", package: "veganio"),
                .product(name: "Hummingbird", package: "hummingbird"),
            ]
        ),
        .testTarget(
            name: "HummingbirdHelloTests",
            dependencies: [
                "HummingbirdVega",
                .product(name: "VegaNIO", package: "veganio"),
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "HummingbirdTesting", package: "hummingbird"),
            ]
        ),
    ]
)
