namespace IPGuard.Windows.Filtering;

/// <summary>Exposes the thread-affine mutex operations needed by one dedicated owner thread.</summary>
internal interface IPolicyMutex : IDisposable
{
    /// <summary>Attempts immediate acquisition, returning null when another thread owns the mutex.</summary>
    /// <returns>False for normal acquisition, true for abandonment, or null for contention.</returns>
    bool? TryAcquire();

    /// <summary>Releases the mutex on its acquiring thread.</summary>
    void Release();
}
