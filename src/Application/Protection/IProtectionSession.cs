namespace IPGuard.Application.Protection;

/// <summary>Owns one authenticated block-only connection independently of its transport and operating system.</summary>
public interface IProtectionSession : IAsyncDisposable
{
    /// <summary>Exchanges one bounded command; interruption must retire ambiguous transport state.</summary>
    Task<ProtectionControlReport> SendAsync(ProtectionCommand command, CancellationToken cancellationToken);
}
