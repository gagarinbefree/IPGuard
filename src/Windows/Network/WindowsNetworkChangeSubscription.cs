using IPGuard.Windows.Network.Native;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace IPGuard.Windows.Network;

/// <summary>Owns route, interface, and address notifications and roots their shared delegate until cancellation succeeds.</summary>
internal sealed class WindowsNetworkChangeSubscription : IDisposable
{
    [ThreadStatic]
    private static WindowsNetworkChangeSubscription? activeCallback;
    private readonly object cleanupGate = new();
    private readonly Action<Exception?> changed;
    private readonly INetworkChangeApi api;
    private readonly List<nint> handles = [];
    private GCHandle callbackRoot;
    private bool stopping;

    /// <summary>Registers read-only native notifications on Windows.</summary>
    internal WindowsNetworkChangeSubscription(Action<Exception?> changed) : this(changed, new NativeNetworkChangeApi()) { }

    /// <summary>Composes registration and cleanup for deterministic native lifetime tests.</summary>
    internal WindowsNetworkChangeSubscription(Action<Exception?> changed, INetworkChangeApi api)
    {
        ArgumentNullException.ThrowIfNull(changed);
        ArgumentNullException.ThrowIfNull(api);
        this.changed = changed;
        this.api = api;
        NativeNetworkChanged callback = OnNativeChanged;
        callbackRoot = GCHandle.Alloc(callback);
        try
        {
            foreach (var kind in new[] { NetworkChangeKind.Route, NetworkChangeKind.Interface, NetworkChangeKind.Address })
            {
                uint result = api.Register(kind, callback, out nint handle);
                if (handle != 0) { handles.Add(handle); }
                if (result != 0) { throw new Win32Exception(unchecked((int)result), $"Cannot register {kind} notifications."); }
                if (handle == 0) { throw new InvalidOperationException($"Windows returned no {kind} notification handle."); }
            }
        }
        catch (Exception registrationError)
        {
            try { Dispose(); }
            catch (Exception cleanupError) { throw new AggregateException(registrationError, cleanupError); }
            throw;
        }
    }

    /// <summary>Retries failed cleanup while preserving roots for any remaining live native callbacks.</summary>
    public void Dispose()
    {
        if (ReferenceEquals(activeCallback, this))
        {
            throw new InvalidOperationException("Native notifications cannot be cancelled from their callback thread.");
        }

        lock (cleanupGate)
        {
            Volatile.Write(ref stopping, true);
            var failures = new List<Exception>();
            for (int index = handles.Count - 1; index >= 0; index--)
            {
                try
                {
                    uint result = api.Cancel(handles[index]);
                    if (result != 0) { throw new Win32Exception(unchecked((int)result), "Cannot cancel a Windows network notification."); }
                    handles.RemoveAt(index);
                }
                catch (Exception error) { failures.Add(error); }
            }
            // A failed cancellation may leave native code holding the delegate. Retain its GC root for a retry.
            if (handles.Count == 0 && callbackRoot.IsAllocated) { callbackRoot.Free(); }
            if (failures.Count > 0) { throw new AggregateException(failures); }
        }
    }

    /// <summary>Delivers change signals without retaining borrowed rows or letting exceptions cross native code.</summary>
    private void OnNativeChanged(nint context, nint row, uint notificationType)
    {
        if (notificationType == 3 || Volatile.Read(ref stopping)) { return; }
        var previous = activeCallback;
        activeCallback = this;
        try
        {
            try { changed(null); }
            catch (Exception error)
            {
                try { changed(error); }
                catch (Exception) { /* A broken fault consumer must not unwind through unmanaged code. */ }
            }
        }
        finally { activeCallback = previous; }
    }
}
