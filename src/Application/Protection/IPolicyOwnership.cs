namespace IPGuard.Application.Protection;

/// <summary>Owns exclusive cooperating access to machine-wide policy until asynchronously released.</summary>
public interface IPolicyOwnership : IAsyncDisposable
{
    /// <summary>Gets a permanent cancellable latch retired before ownership is released or when it is lost.</summary>
    CancellationToken Lost { get; }
}
