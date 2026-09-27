import SwiftUI

/// The Serberus shell: branded sidebar on the lifted ground, content and
/// detail over the ambient near-black backdrop, dark scheme, emerald tint —
/// the same frame Commander's `RootView` uses.
struct ContentView: View {
    @Bindable var catalog: Catalog
    @State private var splashDone = false

    var body: some View {
        ZStack {
            NavigationSplitView {
                SidebarView(catalog: catalog)
            } content: {
                ZStack {
                    AppBackground()
                    EntryListView(catalog: catalog)
                }
                .navigationSplitViewColumnWidth(min: 380, ideal: 460, max: 620)
            } detail: {
                ZStack {
                    AppBackground()
                    if let entry = catalog.selectedEntry {
                        EntryDetailView(entry: entry, catalog: catalog)
                            .id(entry.id)
                    } else {
                        emptyDetail
                    }
                }
            }
            .toolbar(removing: splashDone ? nil : .sidebarToggle)

            if !splashDone {
                LaunchSplashView(catalog: catalog) {
                    withAnimation(.easeOut(duration: 0.4)) { splashDone = true }
                }
                .transition(.opacity)
                .zIndex(1)
            }
        }
        .preferredColorScheme(.dark)
        .tint(Theme.emerald)
        .toolbarBackground(.hidden, for: .windowToolbar)
    }

    private var emptyDetail: some View {
        VStack(spacing: Spacing.md) {
            ZStack {
                Circle().fill(Theme.accentDim).frame(width: 64, height: 64)
                Image(systemName: "key.viewfinder")
                    .font(.system(size: 26, weight: .medium))
                    .foregroundStyle(Theme.emerald)
            }
            Text("Select a right")
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(Theme.textPrimary)
            Text("Pick an authorization right to see its description, who can satisfy it, and its live definition.")
                .font(.system(size: 12))
                .foregroundStyle(Theme.textSecondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 320)
        }
        .padding(Spacing.xl)
    }
}

/// Branded launch page: the icon chip + wordmark over the backdrop while the
/// template and live database are read. Fades once the catalog is loaded and
/// a short minimum has passed, so a fast load never flashes.
struct LaunchSplashView: View {
    let catalog: Catalog
    let onFinish: () -> Void
    @State private var minimumElapsed = false
    @State private var fired = false

    var body: some View {
        ZStack {
            AppBackground()
            VStack(spacing: Spacing.xl) {
                BrandChip(size: 88)
                    .shadow(color: Theme.accentGlow, radius: 28, y: 8)
                VStack(spacing: 6) {
                    Text("SERBERUS")
                        .font(.system(size: 22, weight: .bold)).tracking(4)
                        .foregroundStyle(Theme.textPrimary)
                    Text("Auth URI Browser")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Theme.emerald.opacity(0.9))
                }
                HStack(spacing: Spacing.sm) {
                    ProgressView().controlSize(.small).tint(Theme.emerald)
                    Text(catalog.loadError ?? "Reading the authorization database…")
                        .font(.system(size: 12))
                        .foregroundStyle(catalog.loadError == nil ? Theme.textSecondary : Theme.critical)
                }
                .padding(.top, Spacing.sm)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .task {
            try? await Task.sleep(for: .milliseconds(600))
            minimumElapsed = true
            advance()
        }
        .onChange(of: catalog.isLoading) { _, _ in advance() }
        .onChange(of: catalog.entries.count) { _, _ in advance() }
    }

    private func advance() {
        guard minimumElapsed, !fired, !catalog.isLoading, !catalog.entries.isEmpty || catalog.loadError != nil else { return }
        fired = true
        onFinish()
    }
}
