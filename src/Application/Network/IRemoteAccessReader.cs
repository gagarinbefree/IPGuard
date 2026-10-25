namespace IPGuard.Application.Network;

/// <summary>Reads provider-visible remote-access connections without claiming coverage of every VPN implementation.</summary>
public interface IRemoteAccessReader
{
    /// <summary>Returns a private list or throws; an empty list cannot establish that VPNs are absent.</summary>
    /// <remarks>Observations are synchronous and not a stable network-generation snapshot.</remarks>
    IReadOnlyList<RemoteAccessConnection> Read(CancellationToken cancellationToken);
}
