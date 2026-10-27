namespace IPGuard.Infrastructure.Control;

/// <summary>Defines the common bounded time budget for one complete command exchange.</summary>
internal static class ControlCommandDeadline
{
    /// <summary>Rejects unsupported timer values before taking ownership or performing I/O.</summary>
    internal static void Validate(TimeSpan timeout)
    {
        if (timeout < TimeSpan.FromMilliseconds(1) || timeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(timeout), "A command timeout must be between 1 ms and 1 minute.");
    }

    /// <summary>Combines caller cancellation with one independent header/body/operation/reply deadline.</summary>
    internal static CancellationTokenSource Start(TimeSpan timeout, CancellationToken cancellationToken)
    {
        var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        source.CancelAfter(timeout);
        return source;
    }
}
