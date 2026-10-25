namespace IPGuard.Application.Network;

/// <summary>Reads limited local proxy settings without resolving proxies or establishing a public exit.</summary>
public interface IProxySettingsReader
{
    /// <summary>Returns a complete settings observation or throws; run synchronous OS calls off the UI thread.</summary>
    ProxySettings Read(CancellationToken cancellationToken);
}
