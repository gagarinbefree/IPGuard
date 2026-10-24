namespace IPGuard.Application.Network;

/// <summary>Exposes an atomic cached network generation without performing network requests.</summary>
public interface INetworkSnapshotProvider
{
    /// <summary>Returns a consistent snapshot, or null when network state cannot be established.</summary>
    /// <remarks>
    /// Known snapshots require a cancellable signal stable for their version. Every relevant change must
    /// invalidate the old token permanently and use a new version, including reconnects.
    /// </remarks>
    NetworkSnapshot? Capture();
}
