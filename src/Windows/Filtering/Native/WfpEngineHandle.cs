using System.Runtime.ExceptionServices;

namespace IPGuard.Windows.Filtering.Native;

/// <summary>Owns a WFP handle while preserving unconfirmed close failures.</summary>
internal sealed class WfpEngineHandle : IDisposable
{
    private readonly Func<nint, uint> _close;
    private readonly nint _value;
    private bool _closeAttempted;
    private Exception? _closeFailure;

    /// <summary>Takes ownership of a non-null handle and its matching close operation.</summary>
    internal WfpEngineHandle(nint value, Func<nint, uint> close)
    {
        if (value == 0)
        {
            throw new ArgumentException("A non-null WFP engine handle is required.", nameof(value));
        }

        ArgumentNullException.ThrowIfNull(close);
        _close = close;
        _value = value;
    }

    /// <summary>Makes a best-effort close only when explicit disposal was never attempted.</summary>
    ~WfpEngineHandle()
    {
        try
        {
            if (_value != 0 && !_closeAttempted)
            {
                _close(_value);
            }
        }
        catch
        {
            // Finalizer cleanup cannot confirm revocation or throw on the finalizer thread.
        }
    }

    /// <summary>Runs a synchronous operation while keeping the handle alive.</summary>
    internal uint Use(Func<nint, uint> operation)
    {
        ObjectDisposedException.ThrowIf(_closeAttempted, this);
        try
        {
            return operation(_value);
        }
        finally
        {
            GC.KeepAlive(this);
        }
    }

    /// <summary>Attempts native closure once and preserves any failure for subsequent disposal calls.</summary>
    public void Dispose()
    {
        if (_closeFailure is not null)
        {
            ExceptionDispatchInfo.Throw(_closeFailure);
        }

        if (_closeAttempted)
        {
            return;
        }

        _closeAttempted = true;
        try
        {
            WfpNativeError.Check(_close(_value), "FwpmEngineClose0");
        }
        catch (Exception error)
        {
            _closeFailure = error;
            throw;
        }
        finally
        {
            GC.SuppressFinalize(this);
        }
    }
}
