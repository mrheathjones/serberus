// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AuthURIBrowser",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "AuthURIBrowser",
            path: "Sources/AuthURIBrowser",
            swiftSettings: [.swiftLanguageMode(.v6)]
        )
    ]
)
