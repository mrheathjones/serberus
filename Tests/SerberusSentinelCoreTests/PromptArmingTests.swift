import AppKit
import CoreGraphics
import Foundation
import Security
import Testing
@testable import SerberusSentinelCore

@Suite("PromptArming")
struct PromptArmingTests {
    private let start = ContinuousClock.now

    private func at(_ milliseconds: Int) -> ContinuousClock.Instant {
        start.advanced(by: .milliseconds(milliseconds))
    }

    @Test("never armed before a clear observation")
    func unobserved() {
        let arming = PromptArming()
        #expect(!arming.isArmed(at: at(0)))
        #expect(!arming.isArmed(at: at(60_000)))
    }

    @Test("armed once key, visible and uncovered have held for the whole delay")
    func armsAfterDelay() {
        var arming = PromptArming()
        arming.observe(isKey: true, isVisible: true, isUncovered: true, at: at(0))
        #expect(!arming.isArmed(at: at(0)))
        #expect(!arming.isArmed(at: at(999)))
        #expect(arming.isArmed(at: at(1000)))
    }

    @Test("repeated clear observations don't restart the delay")
    func continuousRun() {
        var arming = PromptArming()
        for ms in stride(from: 0, through: 1000, by: 200) {
            arming.observe(isKey: true, isVisible: true, isUncovered: true, at: at(ms))
        }
        #expect(arming.clearSince == at(0))
        #expect(arming.isArmed(at: at(1000)))
    }

    @Test("any false input disarms at once, and arming again takes a full delay")
    func disarmAndRearm() {
        let blocked: [(isKey: Bool, isVisible: Bool, isUncovered: Bool)] = [
            (false, true, true), (true, false, true), (true, true, false), (false, false, false),
        ]
        for state in blocked {
            var arming = PromptArming()
            arming.observe(isKey: true, isVisible: true, isUncovered: true, at: at(0))
            #expect(arming.isArmed(at: at(2000)))
            arming.observe(isKey: state.isKey, isVisible: state.isVisible, isUncovered: state.isUncovered, at: at(2000))
            #expect(!arming.isArmed(at: at(2000)))
            #expect(!arming.isArmed(at: at(9000)))
            arming.observe(isKey: true, isVisible: true, isUncovered: true, at: at(3000))
            #expect(!arming.isArmed(at: at(3999)))
            #expect(arming.isArmed(at: at(4000)))
        }
    }

    @Test("input while clear but unarmed restarts the delay from that instant")
    func inputRestarts() {
        var arming = PromptArming()
        arming.observe(isKey: true, isVisible: true, isUncovered: true, at: at(0))
        arming.noteInput(at: at(950))
        #expect(arming.clearSince == at(950))
        #expect(!arming.isArmed(at: at(1050)))
        #expect(!arming.isArmed(at: at(1949)))
        #expect(arming.isArmed(at: at(1950)))
    }

    @Test("input once armed changes nothing; input while blocked stays blocked")
    func inputArmedOrBlocked() {
        var armed = PromptArming()
        armed.observe(isKey: true, isVisible: true, isUncovered: true, at: at(0))
        armed.noteInput(at: at(1500))
        #expect(armed.clearSince == at(0))
        #expect(armed.isArmed(at: at(1500)))

        var blocked = PromptArming()
        blocked.observe(isKey: true, isVisible: true, isUncovered: false, at: at(0))
        blocked.noteInput(at: at(500))
        #expect(blocked.clearSince == nil)
        #expect(!blocked.isArmed(at: at(5000)))
    }

    @Test("only ⌘↩ and ⌘ keypad Enter are approve keys; typing, Escape, bare Return and Tab aren't")
    func approveKeys() {
        #expect(PromptArming.isApproveKey(keyCode: 36, commandHeld: true))   // ⌘↩ (repeats too)
        #expect(PromptArming.isApproveKey(keyCode: 76, commandHeld: true))   // ⌘ keypad Enter
        #expect(!PromptArming.isApproveKey(keyCode: 36, commandHeld: false))  // bare Return: deny
        #expect(!PromptArming.isApproveKey(keyCode: 76, commandHeld: false))
        #expect(!PromptArming.isApproveKey(keyCode: 53, commandHeld: false))  // Escape
        #expect(!PromptArming.isApproveKey(keyCode: 53, commandHeld: true))
        #expect(!PromptArming.isApproveKey(keyCode: 48, commandHeld: false))  // Tab
        #expect(!PromptArming.isApproveKey(keyCode: 49, commandHeld: false))  // Space
        #expect(!PromptArming.isApproveKey(keyCode: 0, commandHeld: false))   // "a"
        #expect(!PromptArming.isApproveKey(keyCode: 0, commandHeld: true))    // ⌘A
    }
}

@Suite("PromptOverlap")
struct PromptOverlapTests {
    private let ownPID: pid_t = 4242
    private let otherPID: pid_t = 777
    private let ownNumber = 31
    /// The prompt, in window-server coordinates.
    private let prompt = CGRect(x: 500, y: 300, width: 470, height: 420)
    private let noneExempt: (pid_t) -> Bool = { _ in false }

    private func window(_ bounds: CGRect, pid: pid_t? = nil, alpha: Double = 1) -> PromptOverlap.ListedWindow {
        PromptOverlap.ListedWindow(ownerPID: pid ?? otherPID, bounds: bounds, alpha: alpha)
    }

    private func covered(_ windows: [PromptOverlap.ListedWindow],
                         exempt: (pid_t) -> Bool = { _ in false }) -> Bool {
        PromptOverlap.isCovered(prompt: prompt, byWindowsAbove: windows, ownPID: ownPID, isExemptOwner: exempt)
    }

    /// A `CGWindowListCopyWindowInfo`-shaped entry.
    private func info(number: Int, pid: pid_t, bounds: CGRect, alpha: Double = 1,
                      layer: Int = 0, onScreen: Bool? = true) -> [String: Any] {
        var info: [String: Any] = [
            kCGWindowNumber as String: number,
            kCGWindowOwnerPID as String: Int(pid),
            kCGWindowBounds as String: bounds.dictionaryRepresentation,
            kCGWindowAlpha as String: alpha,
            kCGWindowLayer as String: layer,
        ]
        if let onScreen { info[kCGWindowIsOnscreen as String] = onScreen }
        return info
    }

    private var ownInfo: [String: Any] { info(number: ownNumber, pid: ownPID, bounds: prompt, layer: 3) }

    /// Reads the prompt's own entry and the list above it from fixed lists.
    private func uncovered(own: [[String: Any]]?, above: [[String: Any]]?, windowNumber: Int? = nil,
                           exempt: (pid_t) -> Bool = { _ in false }) -> Bool {
        PromptOverlap.isUncovered(
            windowNumber: windowNumber ?? ownNumber, ownPID: ownPID,
            windowList: { option, _ in
                if option == .optionIncludingWindow { return own }
                if option == .optionOnScreenAboveWindow { return above }
                return nil
            },
            isExemptOwner: exempt
        )
    }

    // MARK: The pure overlap test

    @Test("another app's window over any part of the prompt covers it")
    func otherAppCovers() {
        #expect(covered([window(CGRect(x: 600, y: 400, width: 50, height: 50))]))
        // A one-point sliver over the corner is enough.
        #expect(covered([window(CGRect(x: 0, y: 0, width: 501, height: 301))]))
        // A window bigger than the prompt, and a nearly transparent one.
        #expect(covered([window(CGRect(x: 0, y: 0, width: 3000, height: 2000))]))
        #expect(covered([window(CGRect(x: 600, y: 400, width: 50, height: 50), alpha: 0.01)]))
    }

    @Test("our own process's windows are ignored")
    func ownWindowsIgnored() {
        #expect(!covered([window(prompt, pid: ownPID), window(CGRect(x: 0, y: 0, width: 3000, height: 2000), pid: ownPID)]))
    }

    @Test("fully transparent windows are ignored")
    func transparentIgnored() {
        #expect(!covered([window(prompt, alpha: 0)]))
    }

    @Test("zero-area windows are ignored")
    func zeroAreaIgnored() {
        #expect(!covered([window(CGRect(x: 600, y: 400, width: 0, height: 100)),
                          window(CGRect(x: 600, y: 400, width: 100, height: 0))]))
    }

    @Test("adjacent and distant windows don't cover it")
    func adjacentIgnored() {
        #expect(!covered([
            window(CGRect(x: 500, y: 0, width: 470, height: 300)),     // touches the top edge
            window(CGRect(x: 970, y: 300, width: 200, height: 420)),   // touches the right edge
            window(CGRect(x: 0, y: 720, width: 3000, height: 100)),    // touches the bottom edge
            window(CGRect(x: 0, y: 0, width: 100, height: 100)),       // elsewhere
        ]))
    }

    @Test("windows of exempt system-UI owners are ignored; everyone else's still count")
    func exemptOwners() {
        let dockPID: pid_t = 55
        let isDock: (pid_t) -> Bool = { $0 == dockPID }
        let fullScreen = CGRect(x: 0, y: 0, width: 3000, height: 2000)
        #expect(!covered([window(fullScreen, pid: dockPID)], exempt: isDock))
        #expect(covered([window(fullScreen, pid: dockPID), window(CGRect(x: 600, y: 400, width: 5, height: 5))],
                        exempt: isDock))
        #expect(covered([window(fullScreen, pid: dockPID)], exempt: noneExempt))
    }

    @Test("an empty prompt frame counts as covered")
    func emptyPromptCovered() {
        #expect(PromptOverlap.isCovered(prompt: .zero, byWindowsAbove: [], ownPID: ownPID, isExemptOwner: noneExempt))
        #expect(PromptOverlap.isCovered(prompt: .null, byWindowsAbove: [], ownPID: ownPID, isExemptOwner: noneExempt))
    }

    // MARK: Reading the window server's lists

    @Test("parses a window-server entry; an absent on-screen flag means off screen")
    func parsesEntry() {
        let parsed = PromptOverlap.ListedWindow(windowInfo: info(number: 9, pid: 123, bounds: prompt, alpha: 0.5))
        #expect(parsed == PromptOverlap.ListedWindow(number: 9, ownerPID: 123, bounds: prompt, alpha: 0.5))
        let offScreen = PromptOverlap.ListedWindow(windowInfo: info(number: 9, pid: 123, bounds: prompt, onScreen: nil))
        #expect(offScreen?.isOnScreen == false)
    }

    @Test("an entry missing its number, owner, bounds or alpha can't be read")
    func malformedEntries() {
        for key in [kCGWindowNumber, kCGWindowOwnerPID, kCGWindowBounds, kCGWindowAlpha] {
            var entry = info(number: 9, pid: 123, bounds: prompt)
            entry[key as String] = nil
            #expect(PromptOverlap.ListedWindow(windowInfo: entry) == nil)
        }
        var garbled = info(number: 9, pid: 123, bounds: prompt)
        garbled[kCGWindowBounds as String] = "not a rect"
        #expect(PromptOverlap.ListedWindow(windowInfo: garbled) == nil)
        garbled = info(number: 9, pid: 123, bounds: prompt, alpha: .nan)
        #expect(PromptOverlap.ListedWindow(windowInfo: garbled) == nil)
    }

    @Test("an overlapping window counts at any window level")
    func anyLevelCounts() {
        let sliver = CGRect(x: 960, y: 700, width: 40, height: 40)
        for layer in [-20, 0, 3, 8, 25, 101, 1000, 1500, 2_147_483_630] {
            #expect(!uncovered(own: [ownInfo], above: [info(number: 99, pid: otherPID, bounds: sliver, layer: layer)]))
            // Our own windows (the toasts, the dropdown) at the same level don't.
            #expect(uncovered(own: [ownInfo], above: [info(number: 99, pid: ownPID, bounds: sliver, layer: layer)]))
        }
    }

    @Test("uncovered when only ignorable windows are above it")
    func uncoveredWithIgnorableWindows() {
        #expect(uncovered(own: [ownInfo], above: []))
        let above = [
            info(number: 40, pid: ownPID, bounds: prompt, layer: 25),
            info(number: 41, pid: otherPID, bounds: prompt, alpha: 0, layer: 1000),
            info(number: 42, pid: otherPID, bounds: CGRect(x: 600, y: 400, width: 0, height: 50), layer: 1000),
            info(number: 43, pid: otherPID, bounds: CGRect(x: 0, y: 0, width: 1470, height: 33), layer: 24),
            info(number: 44, pid: 55, bounds: CGRect(x: 0, y: 0, width: 1470, height: 956), layer: 20),
        ]
        #expect(uncovered(own: [ownInfo], above: above, exempt: { $0 == 55 }))
        #expect(!uncovered(own: [ownInfo], above: above))
    }

    @Test("reads its own frame and the windows above it for its own window number")
    func queriesOwnWindow() {
        var queries: [String] = []
        _ = PromptOverlap.isUncovered(
            windowNumber: ownNumber, ownPID: ownPID,
            windowList: { option, id in
                queries.append("\(option.rawValue):\(id)")
                return option == .optionIncludingWindow ? [self.ownInfo] : []
            },
            isExemptOwner: noneExempt
        )
        #expect(queries == ["\(CGWindowListOption.optionIncludingWindow.rawValue):\(ownNumber)",
                            "\(CGWindowListOption.optionOnScreenAboveWindow.rawValue):\(ownNumber)"])
    }

    @Test("fails closed: reports covered whenever the window server can't answer")
    func failsClosed() {
        let clear: [[String: Any]] = []
        #expect(!uncovered(own: [ownInfo], above: clear, windowNumber: 0))
        #expect(!uncovered(own: [ownInfo], above: clear, windowNumber: -1))
        #expect(!uncovered(own: nil, above: clear))
        #expect(!uncovered(own: [], above: clear))
        #expect(!uncovered(own: [info(number: ownNumber + 1, pid: ownPID, bounds: prompt)], above: clear))
        #expect(!uncovered(own: [info(number: ownNumber, pid: ownPID, bounds: prompt, onScreen: false)], above: clear))
        #expect(!uncovered(own: [info(number: ownNumber, pid: ownPID, bounds: prompt, onScreen: nil)], above: clear))
        #expect(!uncovered(own: [info(number: ownNumber, pid: ownPID, bounds: .zero)], above: clear))
        #expect(!uncovered(own: [ownInfo], above: nil))
        var unreadable = info(number: 50, pid: otherPID, bounds: CGRect(x: 0, y: 0, width: 10, height: 10))
        unreadable[kCGWindowBounds as String] = nil
        #expect(!uncovered(own: [ownInfo], above: [unreadable]))
    }

    // MARK: System-UI exemption

    @Test("the system-UI requirement compiles")
    func requirementCompiles() {
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(PromptOverlap.systemUIRequirementText as CFString, [], &requirement)
        #expect(status == errSecSuccess)
        #expect(requirement != nil)
    }

    @Test("our own process and invalid pids aren't exempt")
    func notExempt() {
        #expect(!PromptOverlap.isExemptSystemUI(pid: getpid()))
        #expect(!PromptOverlap.isExemptSystemUI(pid: 0))
        #expect(!PromptOverlap.isExemptSystemUI(pid: -1))
    }

    static let dockPID: pid_t? =
        NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.dock").first?.processIdentifier

    @Test("the running Dock is exempt", .enabled(if: dockPID != nil, "no Dock in this session"))
    func dockExempt() throws {
        let pid = try #require(Self.dockPID)
        #expect(PromptOverlap.isExemptSystemUI(pid: pid))
    }
}
