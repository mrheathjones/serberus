import Foundation

/// Races an **async** `work` closure against a wall-clock deadline, ABANDONING
/// whichever loses. Returns `nil` if the deadline elapsed first.
///
/// This is the async sibling of ``withDetachedTimeout`` (`JamfConnectStateSource.swift`),
/// which bounds a *synchronous* blocking read. Both share the same one-shot
/// arbiter, ``DetachedTimeoutBox``.
///
/// ## Why not `withTimeout` (`DaemonHealthProbe.swift`)?
///
/// That helper is built on `withTaskGroup`, which is *structured*: the group
/// implicitly awaits every child at scope exit. A child that ignores
/// cancellation — precisely the case a watchdog exists to survive — would
/// therefore hang the timeout itself, and the "timeout" would never return.
/// This function uses UNSTRUCTURED tasks plus the arbiter box, so a wedged
/// `work` is abandoned and the caller proceeds.
///
/// ## The loser is abandoned, not cancelled
///
/// Unlike ``withDetachedTimeout``, the worker is deliberately **not** cancelled
/// on expiry. Two reasons:
///
/// 1. It would not help. A task parked on a continuation that never resumes
///    stays parked; `Task.cancel()` only sets a flag.
/// 2. It could hurt. A pass that is merely *slow* (not wedged) still holds a
///    live continuation, and callers depend on it running to completion — e.g.
///    the reload watchdog's late-completion path clears its leak-guard flag
///    from inside `work`. Cancelling could make a partially-completed pass skip
///    that tail.
///
/// So an over-deadline `work` keeps running to its natural end on its own task;
/// its return value is simply dropped. The caller must therefore treat `work`
/// as still potentially in-flight after `nil` comes back, and bound how many
/// such tasks it can leak (the reload watchdog allows at most one).
///
/// The timer *is* cancelled once `work` wins, so the fast path does not leave a
/// sleeping task behind for the rest of the budget.
///
/// - Parameters:
///   - seconds: the wall-clock budget. Values `<= 0` collapse to an immediate
///     timeout.
///   - work: the async work to bound. Callers pass a NON-optional-producing
///     closure, so `nil` unambiguously means timeout.
/// - Returns: the closure's value, or `nil` if the deadline elapsed first.
func withAbandoningTimeout<T: Sendable>(
    seconds: TimeInterval,
    _ work: @escaping @Sendable () async -> T
) async -> T? {
    let box = DetachedTimeoutBox<T>()
    // Detached: `work` must not inherit the caller's cancellation, priority, or
    // actor context — the whole point is that it can outlive this call.
    Task.detached(priority: .utility) { box.settle(.value(await work())) }
    let timer = Task.detached(priority: .utility) {
        let nanos = seconds > 0 ? UInt64(seconds * 1_000_000_000) : 0
        try? await Task.sleep(nanoseconds: nanos)
        box.settle(.timedOut)
    }
    // Only the timer is cancelled: see "The loser is abandoned" above. A settle
    // from a cancelled timer is a harmless no-op re-settle.
    defer { timer.cancel() }
    return await withCheckedContinuation { (continuation: CheckedContinuation<T?, Never>) in
        box.attach(continuation)
    }
}
