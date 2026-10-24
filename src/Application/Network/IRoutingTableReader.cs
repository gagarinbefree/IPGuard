namespace IPGuard.Application.Network;

/// <summary>Reads local routing diagnostics; implementations must disclose coverage limits and never grant access.</summary>
public interface IRoutingTableReader
{
    /// <summary>Returns all observed routes or throws, without silently dropping failed rows or interfaces.</summary>
    /// <remarks>Local OS calls are synchronous; callers must run collection off the UI thread.</remarks>
    IReadOnlyList<NetworkRoute> Read(CancellationToken cancellationToken);
}
