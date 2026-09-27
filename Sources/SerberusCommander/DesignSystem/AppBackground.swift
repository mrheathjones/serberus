import SwiftUI

/// The app's ambient backdrop: Sentinel's near-black canvas (`--bg`) plus a
/// barely-there top-to-bottom lift and one faint accent bloom in the
/// top-leading corner. Deliberately low-contrast so content cards read clearly
/// and the accent stays a hint, never a fill. (Sentinel's window ground is the
/// flat `--bg` alone; the lift + bloom are a console-canvas allowance.)
struct AppBackground: View {
    var body: some View {
        ZStack {
            Theme.background

            LinearGradient(
                colors: [Theme.backgroundDeep, Theme.background],
                startPoint: .top,
                endPoint: .bottom
            )
            .opacity(0.9)

            // A single soft accent bloom in the top-leading corner.
            RadialGradient(
                colors: [Theme.emerald.opacity(0.07), .clear],
                center: .init(x: 0.04, y: -0.02),
                startRadius: 0,
                endRadius: 560
            )
        }
        .ignoresSafeArea()
    }
}
