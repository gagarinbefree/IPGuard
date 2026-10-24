using System.ComponentModel;
using IPGuard.Windows.Network;
using IPGuard.Windows.Network.Native;
using Xunit;

namespace UnitTests;

/// <summary>Checks native registration ownership without registering with Windows or changing routes.</summary>
public sealed class WindowsNetworkChangeSubscriptionTests
{
    /// <summary>Subscribes to each distinct change category and releases each handle exactly once.</summary>
    [Fact]
    public void RegistersAndCancelsAllThreeCategories()
    {
        var api = new ChangeApi();
        using var subscription = new WindowsNetworkChangeSubscription(_ => { }, api);
        Assert.Equal([NetworkChangeKind.Route, NetworkChangeKind.Interface, NetworkChangeKind.Address], api.Registered);
        subscription.Dispose();
        subscription.Dispose();
        Assert.Equal(3, api.Cancelled.Count);
        Assert.Equal(3, api.Cancelled.Distinct().Count());
    }

    /// <summary>Every real notification invalidates, including unknown future kinds, without reading borrowed rows.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(99)]
    public void ChangeCallsMonitorWithoutDereferencingRow(uint notification)
    {
        var api = new ChangeApi();
        var calls = 0;
        using var subscription = new WindowsNetworkChangeSubscription(error => { Assert.Null(error); calls++; }, api);
        api.Callback!(0, (nint)1, notification);
        Assert.Equal(1, calls);
    }

    /// <summary>A synthetic registration confirmation is not treated as a network change.</summary>
    [Fact]
    public void InitialNotificationDoesNotInvalidate()
    {
        var api = new ChangeApi();
        var calls = 0;
        using var subscription = new WindowsNetworkChangeSubscription(_ => calls++, api);
        api.Callback!(0, 0, 3);
        Assert.Equal(0, calls);
    }

    /// <summary>A failed registration releases only the handles which were successfully acquired.</summary>
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void RegistrationFailureCleansUpPartialState(int failAt)
    {
        var api = new ChangeApi { FailRegistrationAt = failAt };
        var error = Assert.Throws<Win32Exception>(() => new WindowsNetworkChangeSubscription(_ => { }, api));
        Assert.Equal(5, error.NativeErrorCode);
        Assert.Equal(failAt - 1, api.Cancelled.Count);
    }

    /// <summary>Failed cancellation does not prevent other cleanup and is retryable without reusing released handles.</summary>
    [Fact]
    public void CancellationFailureRetainsOnlyFailedHandleForRetry()
    {
        var api = new ChangeApi { FailCancellation = true };
        var subscription = new WindowsNetworkChangeSubscription(_ => { }, api);
        Assert.Throws<AggregateException>(subscription.Dispose);
        Assert.Equal(3, api.Cancelled.Count);
        api.FailCancellation = false;
        subscription.Dispose();
        Assert.Equal(4, api.Cancelled.Count);
        Assert.Equal(2, api.Cancelled.Count(handle => handle == (nint)1));
    }

    /// <summary>Preserves both initialization and cleanup failures for diagnosis.</summary>
    [Fact]
    public void RegistrationAndCleanupFailuresAreBothRetained()
    {
        var api = new ChangeApi { FailRegistrationAt = 2, FailCancellation = true };
        try
        {
            var error = Assert.Throws<AggregateException>(() => new WindowsNetworkChangeSubscription(_ => { }, api));
            Assert.Equal(2, error.Flatten().InnerExceptions.Count);
        }
        finally
        {
            // The retained delegate roots its failed subscription until cancellation can be retried.
            api.FailCancellation = false;
            Assert.IsType<WindowsNetworkChangeSubscription>(api.Callback!.Target).Dispose();
        }
    }

    /// <summary>Missing successful handles fail initialization and release previously acquired registrations.</summary>
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void SuccessWithoutHandleIsRejected(int failAt)
    {
        var api = new ChangeApi { MissingHandleAt = failAt };
        Assert.Throws<InvalidOperationException>(() => new WindowsNetworkChangeSubscription(_ => { }, api));
        Assert.Equal(failAt - 1, api.Cancelled.Count);
    }

    /// <summary>Rejects cleanup on a native callback stack instead of entering the documented Windows deadlock.</summary>
    [Fact]
    public void CallbackCannotCancelItsOwnNativeSubscription()
    {
        var api = new ChangeApi();
        WindowsNetworkChangeSubscription? subscription = null;
        Exception? reported = null;
        using (subscription = new WindowsNetworkChangeSubscription(error =>
        {
            if (error is null) { subscription!.Dispose(); }
            else { reported = error; }
        }, api))
        {
            api.Callback!(0, 0, 0);
            Assert.IsType<InvalidOperationException>(reported);
            Assert.Empty(api.Cancelled);
        }
        Assert.Equal(3, api.Cancelled.Count);
    }

    /// <summary>Contains managed exceptions at the unmanaged boundary and reports a fault to the monitor.</summary>
    [Fact]
    public void CallbackFailureIsReportedWithoutEscaping()
    {
        var api = new ChangeApi();
        var failure = new InvalidOperationException("Invalidation failed.");
        Exception? reported = null;
        using var subscription = new WindowsNetworkChangeSubscription(error =>
        {
            if (error is null) { throw failure; }
            reported = error;
        }, api);
        api.Callback!(0, 0, 0);
        Assert.Same(failure, reported);
    }

    /// <summary>Models the read-only native API with deterministic registration and cleanup errors.</summary>
    private sealed class ChangeApi : INetworkChangeApi
    {
        /// <summary>Gets the categories registered so far.</summary>
        internal List<NetworkChangeKind> Registered { get; } = [];

        /// <summary>Gets every attempted cancellation, including retries.</summary>
        internal List<nint> Cancelled { get; } = [];

        /// <summary>Gets the callback retained by the fake native registrations.</summary>
        internal NativeNetworkChanged? Callback { get; private set; }

        /// <summary>Gets the registration attempt which should fail, or zero for none.</summary>
        internal int FailRegistrationAt { get; init; }

        /// <summary>Gets a successful registration which incorrectly returns no handle.</summary>
        internal int MissingHandleAt { get; init; }

        /// <summary>Gets or sets whether the first handle should resist cancellation.</summary>
        internal bool FailCancellation { get; set; }

        /// <summary>Assigns distinct handles and optionally rejects one registration.</summary>
        public uint Register(NetworkChangeKind kind, NativeNetworkChanged callback, out nint handle)
        {
            Registered.Add(kind);
            Callback = callback;
            handle = Registered.Count == FailRegistrationAt || Registered.Count == MissingHandleAt ? 0 : (nint)Registered.Count;
            return Registered.Count == FailRegistrationAt ? 5u : 0u;
        }

        /// <summary>Records cleanup attempts and optionally fails the first handle.</summary>
        public uint Cancel(nint handle)
        {
            Cancelled.Add(handle);
            return handle == (nint)1 && FailCancellation ? 5u : 0u;
        }
    }
}
