namespace IPGuard.Application.Protection;

/// <summary>Retains exclusive ownership across policy calls and drains them before releasing the owner.</summary>
public sealed class OwnedBlockPolicy : IBlockPolicy, IAsyncDisposable
{
    private readonly IBlockPolicy policy;
    private readonly IPolicyOwnership ownership;
    private readonly CancellationToken lost;
    private readonly SemaphoreSlim operations = new(1, 1);
    private readonly object lifetime = new();
    private Task? disposal;
    private bool stopping;

    /// <summary>Takes ownership of the lease; callers must not release it separately.</summary>
    public OwnedBlockPolicy(IBlockPolicy policy, IPolicyOwnership ownership)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(ownership);
        lost = ownership.Lost;
        if (!lost.CanBeCanceled || lost.IsCancellationRequested)
            throw new ArgumentException("A live ownership latch is required.", nameof(ownership));
        this.policy = policy;
        this.ownership = ownership;
    }

    /// <summary>Ensures persistent blocks only while exclusive ownership remains live.</summary>
    public async Task EnsureAsync(CancellationToken cancellationToken)
    {
        await RunAsync(async token =>
        {
            await policy.EnsureAsync(token).ConfigureAwait(false);
            return true;
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads policy only while exclusive ownership remains live, discarding results after loss.</summary>
    public Task<BlockPolicyInspection> InspectAsync(CancellationToken cancellationToken)
        => RunAsync(policy.InspectAsync, cancellationToken);

    /// <summary>Rejects new operations, drains existing native calls, then releases ownership exactly once.</summary>
    public ValueTask DisposeAsync()
    {
        lock (lifetime)
        {
            stopping = true;
            // Run outside the caller's stack: releasing ownership may invoke arbitrary callbacks.
            disposal ??= Task.Run(DrainAsync);
            return new(disposal);
        }
    }

    /// <summary>Serializes backend calls and rejects results whose ownership or lifetime has expired.</summary>
    private async Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken)
    {
        ThrowIfStopping();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lost);
        await operations.WaitAsync(linked.Token).ConfigureAwait(false);
        try
        {
            ThrowIfStopping();
            linked.Token.ThrowIfCancellationRequested();
            var result = await operation(linked.Token).ConfigureAwait(false);
            ThrowIfStopping();
            linked.Token.ThrowIfCancellationRequested();
            return result;
        }
        finally { operations.Release(); }
    }

    /// <summary>Prevents queued and new operations from entering a retiring backend.</summary>
    private void ThrowIfStopping()
    {
        lock (lifetime) ObjectDisposedException.ThrowIf(stopping, this);
    }

    /// <summary>Retains ownership until every admitted backend operation has returned.</summary>
    private async Task DrainAsync()
    {
        await operations.WaitAsync().ConfigureAwait(false);
        try { await ownership.DisposeAsync().ConfigureAwait(false); }
        finally { operations.Release(); }
    }
}
