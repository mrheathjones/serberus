/// The tiny wire contract between the sandboxed Finder Sync extension
/// (`SerberusFinderExtension`) and the agent's `FinderBridgeListener`.
///
/// Kept in PrivMgrCore so both targets — which cannot import each other — share
/// a single source of truth for the dictionary keys and action values. The
/// payload is deliberately minimal: an action discriminator and one absolute
/// path string. No file bytes cross the boundary; the daemon re-validates the
/// path and gates every action, so this contract carries no authority on its own.
public enum FinderBridgeWire {
    /// Dictionary key: the requested verb (``install`` / ``uninstall``).
    public static let actionKey = "action"
    /// Dictionary key: absolute path of the selected `.pkg`/`.app`.
    public static let pathKey = "path"
    /// Reply key: `true` once the agent has accepted the request.
    public static let acceptedKey = "accepted"

    /// Action value — install a notarized `.pkg`/`.app`.
    public static let install = "install"
    /// Action value — move a `/Applications` `.app` to the Trash.
    public static let uninstall = "uninstall"
}
