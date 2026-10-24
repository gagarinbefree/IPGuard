namespace IPGuard.Application.PublicIp;

/// <summary>Obtains every configured public address attempt without exposing an HTTP client to application scenarios.</summary>
public interface IPublicIpProbe
{
    /// <summary>Preserves source order and failed attempts; caller cancellation must stop collection.</summary>
    Task<IReadOnlyList<PublicIpReadResult>> ReadAllAsync(IEnumerable<PublicIpSource> sources, CancellationToken cancellationToken);
}
