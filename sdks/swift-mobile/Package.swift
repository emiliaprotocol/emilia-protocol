// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "EmiliaMobile",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "EmiliaMobile", targets: ["EmiliaMobile"]),
    ],
    targets: [
        .target(name: "EmiliaMobile"),
        .testTarget(name: "EmiliaMobileTests", dependencies: ["EmiliaMobile"]),
    ]
)
