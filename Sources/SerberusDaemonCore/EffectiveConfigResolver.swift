import Foundation
import PrivMgrCore

/// Where the config the daemon is actually serving came from.
public enum EffectiveConfigSource: String, Sendable, Equatable {
    /// A present, safely-enforceable managed config, `daemonEnabled == true` (the
    /// normal case): a non-empty `pamBypass` at least one of whose entries
    /// resolves on this Mac. This is the ONLY source that is snapshotted as
    /// last-known-good.
    case managed
    /// A delivered kill switch (`daemonEnabled == false`). Adopted so an admin can
    /// turn Serberus off — but NEVER snapshotted (a non-enforcing snapshot would let
    /// a later profile removal leave the Mac disabled). The caller's daemonEnabled
    /// guard drives the restore/remove teardown.
    case killSwitch
    /// The last-known-good snapshot: the managed config is absent, unscoped, or
    /// present-but-unsafe on a Mac that HAS been configured, and the snapshot LOADS.
    /// Still enforcing (the snapshot is enforceable by construction), degraded.
    case lastKnownGood
    /// A last-known-good FILE exists but does NOT load (corrupt / hollowed / written
    /// by an older build). pam selects LAST_KNOWN_GOOD here and its readers fail
    /// CLOSED, so the daemon must match: enforce with no break-glass, never
    /// pass-through. The accepted fail-closed lockout of a tampered configured Mac.
    case failClosed
    /// Nothing usable anywhere AND no snapshot FILE — this Mac has never been
    /// configured (bootstrap / the Jamf pkg beat the profile). The daemon does not
    /// enforce; pam PAM_IGNOREs in bootstrap and never consults it.
    case awaitingConfig
}

/// The configuration the daemon serves this cycle, plus what it is allowed to do
/// with it.
public struct EffectiveConfig: Sendable, Equatable {
    /// The config to enforce, publish, and hand to ``PAMEvaluator``. In the
    /// ``EffectiveConfigSource/awaitingConfig`` case it is a canonical EMPTY config
    /// (monitor, no break-glass, no enrollment); in the
    /// ``EffectiveConfigSource/failClosed`` case a canonical fail-closed config
    /// (enforce, no break-glass, no enrollment).
    public let config: SerberusConfig
    public let source: EffectiveConfigSource
    /// Diagnostics for the integrity log (never user-facing).
    public let notes: [String]
    /// Enforcement with zero working break-glass: the DELIVERED config (which
    /// was then refused, like an empty `pamBypass`) or the config being served
    /// names `pamBypass` entries none of which resolves. Reported as
    /// `degraded(bypass_unresolvable)`.
    public let bypassUnresolvable: Bool
    /// Each `pamBypass` entry of the delivered and served configs that does not
    /// resolve (`user x` / `group y`), for logging — including partial typos
    /// where other entries do resolve.
    public let unresolvedBypassEntries: [String]

    /// Bootstrap: no config has EVER been usable on this Mac and no snapshot FILE
    /// exists. The daemon must not enforce; and — critically — it must mutate TOWARD
    /// the native state (restore the authdb, remove any sudoers drop-in), NOT skip
    /// mutations, so a Mac that adopted a config, mutated the system, then lost the
    /// config before the snapshot marker was planted is cleaned up rather than
    /// stranded. See ``DaemonState/awaitingConfig``.
    public var isAwaitingConfig: Bool { source == .awaitingConfig }

    /// A delivered kill switch. The caller's `daemonEnabled == false` guard owns the
    /// teardown (restore authdb, remove drop-in, state killSwitch); this flag exists
    /// only to name the case and keep the resolver total.
    public var isKillSwitch: Bool { source == .killSwitch }

    /// The delivered policy is not what the admin's console says it is — the daemon
    /// is enforcing a snapshot (``EffectiveConfigSource/lastKnownGood``) or failing
    /// closed against a corrupt one (``EffectiveConfigSource/failClosed``). Reported
    /// as `degraded(config_missing)`. It is still ENFORCING, so profile removal or
    /// tamper cannot disable Serberus.
    public var reportsConfigMissing: Bool {
        source == .lastKnownGood || source == .failClosed
    }

    public init(config: SerberusConfig, source: EffectiveConfigSource, notes: [String] = [],
                bypassUnresolvable: Bool = false, unresolvedBypassEntries: [String] = []) {
        self.config = config
        self.source = source
        self.notes = notes
        self.bypassUnresolvable = bypassUnresolvable
        self.unresolvedBypassEntries = unresolvedBypassEntries
    }
}

/// Resolves the configuration the daemon actually runs on.
///
/// This is the single arbiter of the enrollment-race / tamper contract, called
/// from BOTH ``StartupCoordinator/run()`` and
/// ``DaemonController/reloadPolicyIfChanged()`` so the two can never diverge —
/// and it must AGREE with `pam_serberus.c`'s `serberus_config_resolve_source`,
/// which keys the bootstrap-vs-configured decision on the EXISTENCE of the
/// last-known-good FILE (`access(F_OK)`), not on whether it loads. The cases:
///
/// - **Configured**: managed config present, safely enforceable, and
///   `daemonEnabled`: adopt it and PERSIST it as the last-known-good snapshot. This
///   is the ONLY site that snapshots, so neither a kill switch nor an unsafe/partial
///   profile can ever become the last-known-good. "Safely enforceable" is
///   ``SerberusConfig/isEnforceable`` (a non-empty `pamBypass` in enforce) AND at
///   least one `pamBypass` entry resolving on this Mac: a bypass whose entries
///   ALL fail to resolve is as unenforceable as an empty one.
/// - **Kill switch**: managed config present with `daemonEnabled == false`:
///   adopt it (the caller restores the authdb, removes the drop-in, reports
///   `kill_switch`) but do NOT snapshot it.
/// - **No usable delivered config** (absent, unscoped, or present-but-unsafe):
///   the bootstrap-vs-configured decision is made by the EXISTENCE of the snapshot
///   FILE, mirroring pam:
///   - snapshot file exists AND loads → run on it (still enforcing, break-glass
///     intact), reported `degraded(config_missing)`;
///   - snapshot file exists but does NOT load (corrupt, or failing its owner /
///     mode checks) → fail CLOSED (enforce, no break-glass), reported
///     `degraded(config_missing)`. Never pass-through on a Mac that has a
///     snapshot file — pam fails closed here too;
///   - no snapshot file → `awaiting_config`. Adopt a canonical EMPTY config and
///     let the caller mutate TOWARD the native state. The daemon does not enforce
///     (pam does not consult it in bootstrap).
///
/// The ONLY fail-open (pass-through) path is the last one — a Mac with NO
/// snapshot file. Once a Mac has adopted a usable config even once, the file
/// exists, and an absent / unsafe / corrupt config keeps it enforcing. An
/// attacker therefore cannot disarm Serberus by removing or corrupting its
/// profile.
public enum EffectiveConfigResolver {

    /// Canonical EMPTY effective config for the bootstrap (no snapshot file) case: `monitor` so
    /// nothing is denied, no break-glass, no enrollment. Provisioning it REMOVES any
    /// stale sudoers drop-in, and reconciling `[]` restores any stranded authdb
    /// rights — the "mutate toward native" cleanup. Deliberately strips any
    /// enrollment a partial profile may have carried, so bootstrap never provisions.
    static let emptyBootstrapConfig = SerberusConfig(
        jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
        daemonEnabled: true, enforcementMode: .monitor, sudoCacheSeconds: 0,
        promptTimeoutSeconds: 60, pamBypass: PAMBypass(),
        sudoEnrollment: SerberusConfig.SudoEnrollment()
    )

    /// Canonical fail-closed effective config for the unusable-snapshot case:
    /// `enforce` with NO break-glass and NO enrollment. Every non-bypass `sudo` is
    /// denied (there is no bypass), matching pam's fail-closed read of an unloadable
    /// snapshot. The accepted lockout of a tampered, previously-configured Mac.
    static let failClosedConfig = SerberusConfig(
        jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
        daemonEnabled: true, enforcementMode: .enforce, sudoCacheSeconds: 0,
        promptTimeoutSeconds: 60, pamBypass: PAMBypass(),
        sudoEnrollment: SerberusConfig.SudoEnrollment()
    )

    /// - Parameters:
    ///   - managedConfig: the parsed config domain (fail-safe-defaulted; only
    ///     meaningful together with `configPresent`).
    ///   - configPresent: whether the config domain delivered ANY key
    ///     (``ManagedPreferencesReader/configIsPresent()``).
    ///   - lastKnownGood: the snapshot store. `save` is best-effort — a write
    ///     failure is noted, never fatal, and never blocks adoption (the daemon
    ///     re-attempts the snapshot on later polls; see the LKG-save retry).
    ///   - bypassResolver: resolves `pamBypass` entries against this Mac's
    ///     accounts. The default treats every entry as resolvable (unit tests);
    ///     production passes ``LocalBypassResolver``.
    public static func resolve(
        managedConfig: SerberusConfig,
        configPresent: Bool,
        lastKnownGood: any LastKnownGoodConfigStoring,
        bypassResolver: BypassResolving = AssumeResolvableBypass()
    ) -> EffectiveConfig {
        var notes: [String] = []
        // Break-glass resolvability of the DELIVERED config (only an enforcing
        // one can fail it). Each unresolved entry is reported even when others
        // resolve.
        var unresolved: [String] = []
        var deliveredUnresolvable = false
        if configPresent {
            unresolved = BypassResolution.unresolvedEntries(managedConfig, resolver: bypassResolver)
            deliveredUnresolvable = BypassResolution.isUnresolvable(managedConfig, resolver: bypassResolver)
        }
        // Stamps the break-glass findings for the config actually served.
        func finish(_ config: SerberusConfig, _ source: EffectiveConfigSource) -> EffectiveConfig {
            var entries = unresolved
            if source != .managed {
                for entry in BypassResolution.unresolvedEntries(config, resolver: bypassResolver)
                where !entries.contains(entry) {
                    entries.append(entry)
                }
            }
            let unresolvable = deliveredUnresolvable
                || BypassResolution.isUnresolvable(config, resolver: bypassResolver)
            return EffectiveConfig(config: config, source: source, notes: notes,
                                   bypassUnresolvable: unresolvable, unresolvedBypassEntries: entries)
        }

        if configPresent {
            // Kill switch. Adopt as delivered so an admin can turn Serberus
            // off without also shipping a pamBypass, but NEVER snapshot it: a
            // non-enforcing last-known-good would let a later profile removal leave
            // the Mac unprotected (violating "removing the profile can never disable
            // Serberus"). The caller's `!daemonEnabled` guard restores the authdb,
            // removes the drop-in, and reports kill_switch.
            if !managedConfig.daemonEnabled {
                notes.append("kill switch delivered; adopted, not snapshotted as last-known-good")
                return EffectiveConfig(config: managedConfig, source: .killSwitch, notes: notes)
            }

            // A usable delivered config. Snapshot ONLY here: the guard is
            // (present && daemonEnabled && isEnforceable && some bypass entry
            // resolves), so a kill switch (above) and an unsafe/partial profile
            // (below) can never overwrite the good last-known-good.
            if managedConfig.isEnforceable && !deliveredUnresolvable {
                do {
                    try lastKnownGood.save(managedConfig)
                } catch {
                    // Non-fatal: still adopt. The snapshot is re-attempted on later
                    // polls so the FILE — the configured-Mac marker pam keys on —
                    // is eventually planted; a Mac can never be left enforcing
                    // without one for long.
                    notes.append("last-known-good config save failed: \(error.localizedDescription)")
                }
                return finish(managedConfig, .managed)
            }

            if deliveredUnresolvable {
                notes.append(
                    "managed config present but not safely enforceable (enforce mode, and NO pamBypass "
                    + "entry resolves on this Mac — zero working break-glass); consulting last-known-good"
                )
            } else {
                notes.append(
                    "managed config present but not safely enforceable (enforce mode with an empty "
                    + "pamBypass — an unscoped or partial profile); consulting last-known-good"
                )
            }
        } else {
            notes.append("no managed config delivered")
        }

        // No usable delivered config. The bootstrap-vs-configured decision
        // is made by the EXISTENCE of the snapshot FILE, IDENTICALLY to pam
        // (serberus_config_resolve_source: access(F_OK)). Keying it on load success
        // instead would let pam (which fails closed on a present-but-corrupt file)
        // and the daemon (which would pass through) disagree — a total lockout with
        // divergence.
        if lastKnownGood.exists() {
            if let snapshot = lastKnownGood.load() {
                // The snapshot loads and is enforceable by construction.
                notes.append("running on the last-known-good config (still enforcing; break-glass intact)")
                return finish(snapshot, .lastKnownGood)
            }
            // The file exists but will not load. pam selects LAST_KNOWN_GOOD and
            // its readers fail CLOSED (enforce, no bypass, daemon consulted); the
            // daemon MUST NOT drop into awaitingConfig/pass-through. Enforce a
            // fail-closed config so both sides deny. Accepted lockout of a tampered,
            // previously-configured Mac.
            let why = lastKnownGood.unusableReason() ?? "corrupt/hollowed"
            notes.append(
                "last-known-good file present but unusable (\(why)); failing closed "
                + "(enforcing, no break-glass) to match pam — never passing through on a configured Mac"
            )
            return finish(failClosedConfig, .failClosed)
        }

        // No delivered config AND no snapshot file: this Mac has NEVER been
        // configured. Adopt a canonical EMPTY config; the caller mutates TOWARD the
        // native state (reconcile([]) + provisionSudoers(empty)), never applying
        // policy and never denying. pam does not consult the daemon in bootstrap, so
        // the daemon never needs to "pass through" itself.
        notes.append(
            "no usable configuration and no last-known-good; awaiting config "
            + "(enforcing nothing, mutating toward the native state)"
        )
        return finish(emptyBootstrapConfig, .awaitingConfig)
    }
}
