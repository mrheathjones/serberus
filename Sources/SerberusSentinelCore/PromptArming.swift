import CoreGraphics
import Foundation
import Security

/// The arming rule for a prompt's Approve action.
///
/// Any app in the user's session can raise the install and uninstall prompts
/// (the "Install/Uninstall with Serberus" Services entries carry no caller
/// identity), so the prompt itself must make sure the user has seen it before
/// an approval counts. Approve — the button and ⌘↩ — arms only after the prompt
/// has been key, visible and uncovered, all three at once, continuously for
/// ``delay``. An observation with any of them false disarms it at once, and
/// arming again takes another full ``delay``. A click or keystroke timed with
/// the prompt's appearance, or one landing on it through another app's window,
/// therefore can't approve. The rule applies to every prompt. While Approve is
/// disarmed, a click on the prompt or a ⌘↩ (held or repeated included) restarts
/// the delay (``noteInput(at:)``), so rapid or held input can't ride it out;
/// the window controller judges each such input on the prompt's state at that
/// moment, not on the last poll.
///
/// The latest observation is taken to hold until the next one, so the window
/// controller reports every change AppKit announces and polls for the overlap,
/// which it doesn't. A value over explicit instants, so the rule is unit-tested;
/// ``PromptViewModel`` gates approval on it.
public struct PromptArming: Sendable, Equatable {
    /// How long the prompt must stay key, visible and uncovered before Approve arms.
    public static let delay: Duration = .seconds(1)

    /// Start of the current unbroken run of clear observations; `nil` while the
    /// latest observation found the prompt unfocused, hidden or covered.
    public private(set) var clearSince: ContinuousClock.Instant?

    public init() {}

    /// Records the prompt window's state at `time`. Any false input disarms at
    /// once; a clear observation starts the delay unless it's already running.
    public mutating func observe(isKey: Bool, isVisible: Bool, isUncovered: Bool,
                                 at time: ContinuousClock.Instant) {
        guard isKey, isVisible, isUncovered else {
            clearSince = nil
            return
        }
        if clearSince == nil { clearSince = time }
    }

    /// Whether Approve is armed at `time`: the latest observation was clear and
    /// its run began at least ``delay`` earlier.
    public func isArmed(at time: ContinuousClock.Instant) -> Bool {
        guard let clearSince else { return false }
        return clearSince.duration(to: time) >= Self.delay
    }

    /// Records a click on the prompt or a ⌘↩ at `time`. While the prompt is
    /// clear but not yet armed, the delay starts again from `time`. Once armed,
    /// input changes nothing (only the three conditions disarm), and a blocked
    /// prompt stays blocked until a clear observation.
    public mutating func noteInput(at time: ContinuousClock.Instant) {
        guard clearSince != nil, !isArmed(at: time) else { return }
        clearSince = time
    }

    /// Whether a key-down is the approve shortcut for ``noteInput(at:)``: Return
    /// or keypad Enter with Command held (key repeats are key-downs too).
    /// Typing, Escape, bare Return and Tab don't count.
    public static func isApproveKey(keyCode: UInt16, commandHeld: Bool) -> Bool {
        commandHeld && (keyCode == returnKeyCode || keyCode == keypadEnterKeyCode)
    }

    static let returnKeyCode: UInt16 = 36       // kVK_Return
    static let keypadEnterKeyCode: UInt16 = 76  // kVK_ANSI_KeypadEnter
}

/// The overlap half of arming: does another app's window cover the prompt?
///
/// Answered from the window server's list (`CGWindowListCopyWindowInfo`). Owner
/// PID, bounds, alpha and the on-screen flag need no Screen Recording
/// permission; window names would, and are never read. The prompt's own
/// occlusion state isn't enough: it stays visible under a partial or
/// translucent overlay, such as a click-through panel showing fake content.
public enum PromptOverlap {
    /// One entry of the window server's list, reduced to what the check reads.
    public struct ListedWindow: Equatable, Sendable {
        public var number: CGWindowID
        public var ownerPID: pid_t
        /// In the window server's global space (origin at the top-left of the
        /// main display, y down), which every entry of a list shares.
        public var bounds: CGRect
        public var alpha: Double
        public var isOnScreen: Bool

        public init(number: CGWindowID = 0, ownerPID: pid_t, bounds: CGRect,
                    alpha: Double = 1, isOnScreen: Bool = true) {
            self.number = number
            self.ownerPID = ownerPID
            self.bounds = bounds
            self.alpha = alpha
            self.isOnScreen = isOnScreen
        }

        /// Parses one `CGWindowListCopyWindowInfo` entry. `nil` when the number,
        /// owner, bounds or alpha is missing or not finite, so callers fail closed.
        public init?(windowInfo info: [String: Any]) {
            guard let number = info[kCGWindowNumber as String] as? NSNumber,
                  let pid = info[kCGWindowOwnerPID as String] as? NSNumber,
                  let alpha = (info[kCGWindowAlpha as String] as? NSNumber)?.doubleValue,
                  let boundsInfo = info[kCGWindowBounds as String] as? NSDictionary,
                  let bounds = CGRect(dictionaryRepresentation: boundsInfo as CFDictionary),
                  [alpha, bounds.minX, bounds.minY, bounds.width, bounds.height].allSatisfy(\.isFinite)
            else { return nil }
            self.init(number: number.uint32Value, ownerPID: pid.int32Value, bounds: bounds, alpha: alpha,
                      // An absent flag means off screen (CGWindow.h).
                      isOnScreen: info[kCGWindowIsOnscreen as String] as? Bool ?? false)
        }
    }

    /// Whether any window the window server lists above the prompt overlaps it.
    ///
    /// Ignored: our own process's windows, fully transparent ones (alpha 0),
    /// windows that only touch or miss the prompt (zero-area ones included),
    /// and windows whose owner `isExemptOwner` names (see
    /// ``isExemptSystemUI(pid:)``). Everything else counts, at any window level:
    /// an app can put its window at any level. An empty prompt frame counts as
    /// covered, since nothing shows it uncovered.
    public static func isCovered(
        prompt: CGRect,
        byWindowsAbove windows: [ListedWindow],
        ownPID: pid_t,
        isExemptOwner: (pid_t) -> Bool
    ) -> Bool {
        guard !prompt.isEmpty else { return true }
        return windows.contains { window in
            guard window.ownerPID != ownPID, window.alpha != 0 else { return false }
            let overlap = prompt.intersection(window.bounds)
            guard !overlap.isNull, overlap.width > 0, overlap.height > 0 else { return false }
            return !isExemptOwner(window.ownerPID)
        }
    }

    /// Whether the prompt window `windowNumber` is uncovered, read through
    /// `windowList` (in production, `CGWindowListCopyWindowInfo`).
    ///
    /// The prompt's own frame comes from the same list
    /// (`.optionIncludingWindow`) as the windows above it
    /// (`.optionOnScreenAboveWindow`), so both are in one coordinate space.
    /// Fails closed — reports covered — when the window number is invalid,
    /// either list can't be read, the prompt's own entry is missing or off
    /// screen, or any entry above it is malformed.
    public static func isUncovered(
        windowNumber: Int,
        ownPID: pid_t,
        windowList: (CGWindowListOption, CGWindowID) -> [[String: Any]]?,
        isExemptOwner: (pid_t) -> Bool
    ) -> Bool {
        guard windowNumber > 0, let id = CGWindowID(exactly: windowNumber),
              let ownList = windowList(.optionIncludingWindow, id),
              let own = ownList.compactMap(ListedWindow.init(windowInfo:)).first(where: { $0.number == id }),
              own.isOnScreen,
              let aboveList = windowList(.optionOnScreenAboveWindow, id)
        else { return false }
        var above: [ListedWindow] = []
        for info in aboveList {
            guard let window = ListedWindow(windowInfo: info) else { return false }
            above.append(window)
        }
        return !isCovered(prompt: own.bounds, byWindowsAbove: above, ownPID: ownPID, isExemptOwner: isExemptOwner)
    }

    /// Whether `pid` is one of the Apple system-UI processes whose windows sit
    /// above every app's as a matter of course. Counting them would keep every
    /// prompt disarmed:
    /// - the Dock keeps a transparent window over the whole display, at the
    ///   Dock level, on screen at all times;
    /// - screencaptureui leaves one on screen, above the Dock, after a screenshot;
    /// - VoiceOver draws its cursor in a window over whichever control it's on,
    ///   Approve included.
    ///
    /// None of them draws another app's content. Identity is Apple's code
    /// signature (`anchor apple` plus the identifier), never a name or bundle ID
    /// an app could claim; a pid that can't be resolved or checked isn't exempt.
    public static func isExemptSystemUI(pid: pid_t) -> Bool {
        guard pid > 0, let requirement = systemUIRequirement else { return false }
        var code: SecCode?
        let attributes = [kSecGuestAttributePid as String: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    static let systemUIRequirementText =
        #"anchor apple and (identifier "com.apple.dock" or identifier "com.apple.screencaptureui" or identifier "com.apple.VoiceOver")"#

    // A compiled requirement is immutable and safe to share across threads.
    nonisolated(unsafe) private static let systemUIRequirement: SecRequirement? = {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(systemUIRequirementText as CFString, [], &requirement) == errSecSuccess
        else { return nil }
        return requirement
    }()
}
