# Extras

Tools that sit next to Serberus but aren't part of what it installs on a Mac.
Nothing here is needed to build, test or deploy Serberus.

| Directory | What it is |
|---|---|
| [`AuthURIBrowser/`](AuthURIBrowser/) | A standalone, read-only app that lists every authorization right on a Mac, useful when writing authURI rules. Its own SwiftPM package; `PKG/build-authuribrowser-pkg.sh` packages it. |
| [`SerberusAuthProbe/`](SerberusAuthProbe/) | The research spike used to learn how authorization plugins behave before SerberusAuth was built. Kept for reference; the `SerberusAuthProbe` scheme still builds it. See [docs/authuri-prompt-plugin-design.md](../docs/authuri-prompt-plugin-design.md). |
| [`build-apps.sh`](build-apps.sh) | Builds Serberus Commander and the Serberus Sentinel window app for UI work. For anything else, use Xcode or the scripts in `PKG/`. |
| [`design/`](design/) | Icon sources, the scripts that generate the app icons from them, and an early UI mockup (`design-reference.pdf`). |
| [`icon-tools/`](icon-tools/) | `icongen.swift`, which draws the app icons in code, and `iconpreview/`, which previews them. Run from the repository root. |
