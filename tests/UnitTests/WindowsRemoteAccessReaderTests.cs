using System.ComponentModel;
using System.Runtime.InteropServices;
using IPGuard.Application.Network;
using IPGuard.Windows.Network;
using IPGuard.Windows.Network.Native;
using Xunit;

namespace UnitTests;

/// <summary>Exercises RAS enumeration and status interpretation without dialing or inspecting host connections.</summary>
public sealed class WindowsRemoteAccessReaderTests
{
    /// <summary>Grows a caller-owned buffer and copies every visible connection into a private result.</summary>
    [Fact]
    public void ResizesAndCopiesConnections()
    {
        var api = new RemoteApi { Connections = 2 };
        var result = new WindowsRemoteAccessReader(api).Read(TestContext.Current.CancellationToken);
        Assert.Equal(2, result.Count);
        Assert.Equal(2, api.Enumerations);
        Assert.Equal(2, api.StatusReads);
        Assert.All(result, connection =>
        {
            Assert.Equal(RemoteApi.Correlation.ToString("D"), connection.CorrelationId);
            Assert.True(connection.IsVpn);
            Assert.Equal(RemoteAccessState.Connected, connection.State);
        });
    }

    /// <summary>An empty provider list is preserved without claiming absence of third-party VPNs.</summary>
    [Fact]
    public void EmptyEnumerationDoesNotQueryStatus()
    {
        var api = new RemoteApi { Connections = 0 };
        Assert.Empty(new WindowsRemoteAccessReader(api).Read(TestContext.Current.CancellationToken));
        Assert.Equal(0, api.StatusReads);
    }

    /// <summary>Only explicit VPN device types are classified, independently of connection state.</summary>
    [Theory]
    [InlineData("vpn", true)]
    [InlineData("VPN", true)]
    [InlineData("modem", false)]
    [InlineData("", false)]
    public void ClassifiesDeviceTypeConservatively(string device, bool vpn)
    {
        var api = new RemoteApi { Device = device };
        var connection = Assert.Single(new WindowsRemoteAccessReader(api).Read(TestContext.Current.CancellationToken));
        Assert.Equal(vpn, connection.IsVpn);
    }

    /// <summary>Connection errors, IKEv2 transitions, and unknown provider states remain distinguishable.</summary>
    [Theory]
    [InlineData(8192u, 0u, 0u, RemoteAccessState.Connected)]
    [InlineData(8192u, 8192u, 0u, RemoteAccessState.Connected)]
    [InlineData(8192u, 1u, 0u, RemoteAccessState.Dormant)]
    [InlineData(8192u, 2u, 0u, RemoteAccessState.Reconnecting)]
    [InlineData(8192u, 99u, 0u, RemoteAccessState.Unknown)]
    [InlineData(8193u, 0u, 0u, RemoteAccessState.Disconnected)]
    [InlineData(0u, 0u, 0u, RemoteAccessState.Connecting)]
    [InlineData(24u, 0u, 0u, RemoteAccessState.Connecting)]
    [InlineData(4096u, 0u, 0u, RemoteAccessState.Connecting)]
    [InlineData(4100u, 0u, 0u, RemoteAccessState.Connecting)]
    [InlineData(65535u, 0u, 0u, RemoteAccessState.Unknown)]
    [InlineData(8192u, 0u, 691u, RemoteAccessState.Failed)]
    [InlineData(8193u, 0u, 691u, RemoteAccessState.Failed)]
    public void PreservesStatusAndConnectionErrors(uint state, uint substate, uint error, RemoteAccessState expected)
    {
        var api = new RemoteApi { State = state, Substate = substate, ConnectionError = error };
        var result = Assert.Single(new WindowsRemoteAccessReader(api).Read(TestContext.Current.CancellationToken));
        Assert.Equal(expected, result.State);
        Assert.Equal(error, result.ErrorCode);
        Assert.Equal(state, result.StateCode);
        Assert.Equal(substate, result.SubstateCode);
    }

    /// <summary>Enumeration and status API errors are distinct from a successful disconnected observation.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ApiFailureIsNotReportedAsNoVpn(bool enumerateFails)
    {
        var api = new RemoteApi { EnumerationError = enumerateFails ? 5u : 0, StatusError = enumerateFails ? 0 : 6u };
        var error = Assert.Throws<Win32Exception>(() => new WindowsRemoteAccessReader(api).Read(TestContext.Current.CancellationToken));
        Assert.Equal(enumerateFails ? 5 : 6, error.NativeErrorCode);
    }

    /// <summary>Malformed native counts, sizes, strings, or borrowed handles fail the entire observation.</summary>
    [Theory]
    [InlineData("bytes")]
    [InlineData("count")]
    [InlineData("handle")]
    [InlineData("duplicate")]
    [InlineData("device")]
    public void MalformedEnumerationFailsClosed(string failure)
    {
        var api = new RemoteApi
        {
            Connections = failure == "duplicate" ? 2 : 1,
            ReportedBytes = failure == "bytes" ? 0 : null,
            ReportedCount = failure == "count" ? 1025u : null,
            InvalidHandle = failure == "handle",
            DuplicateHandles = failure == "duplicate",
            Device = failure == "device" ? new string('x', 17) : "vpn"
        };
        Assert.Throws<InvalidDataException>(() => new WindowsRemoteAccessReader(api).Read(TestContext.Current.CancellationToken));
    }

    /// <summary>Unbounded connection growth and oversized requests do not cause unbounded allocation or retries.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BufferGrowthIsBounded(bool oversized)
    {
        var api = new RemoteApi { GrowForever = !oversized, Oversized = oversized };
        if (oversized)
        {
            Assert.Throws<InvalidDataException>(() => new WindowsRemoteAccessReader(api).Read(TestContext.Current.CancellationToken));
        }
        else
        {
            Assert.Throws<IOException>(() => new WindowsRemoteAccessReader(api).Read(TestContext.Current.CancellationToken));
        }
        Assert.InRange(api.Enumerations, 1, 4);
    }

    /// <summary>Caller cancellation is observed before enumeration and after every native boundary.</summary>
    [Theory]
    [InlineData("before")]
    [InlineData("enumerate")]
    [InlineData("status")]
    public void CallerCancellationPropagates(string when)
    {
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var api = new RemoteApi
        {
            AfterEnumerate = when == "enumerate" ? caller.Cancel : null,
            AfterStatus = when == "status" ? caller.Cancel : null
        };
        if (when == "before") { caller.Cancel(); }
        Assert.ThrowsAny<OperationCanceledException>(() => new WindowsRemoteAccessReader(api).Read(caller.Token));
        Assert.Equal(when == "before" ? 0 : 1, api.Enumerations);
    }

    /// <summary>Supplies native-shaped RAS output in caller memory without owning or closing any RAS handle.</summary>
    private sealed class RemoteApi : IRemoteAccessApi
    {
        internal static readonly Guid Correlation = Guid.Parse("6d1f4979-0fc6-4f09-89b3-3c45781465fe");

        /// <summary>Gets the number of controlled connections.</summary>
        internal int Connections { get; init; } = 1;

        /// <summary>Gets the device type stored in each native connection.</summary>
        internal string Device { get; init; } = "vpn";

        /// <summary>Gets the raw connection state.</summary>
        internal uint State { get; init; } = 8192;

        /// <summary>Gets the raw IKEv2 substate.</summary>
        internal uint Substate { get; init; }

        /// <summary>Gets a connection error returned by an otherwise successful status call.</summary>
        internal uint ConnectionError { get; init; }

        /// <summary>Gets an enumeration API failure.</summary>
        internal uint EnumerationError { get; init; }

        /// <summary>Gets a status API failure.</summary>
        internal uint StatusError { get; init; }

        /// <summary>Gets whether every call should request a larger buffer.</summary>
        internal bool GrowForever { get; init; }

        /// <summary>Gets whether the first call should request an excessive buffer.</summary>
        internal bool Oversized { get; init; }

        /// <summary>Gets whether output should contain an invalid handle.</summary>
        internal bool InvalidHandle { get; init; }

        /// <summary>Gets whether multiple rows should incorrectly reference the same handle.</summary>
        internal bool DuplicateHandles { get; init; }

        /// <summary>Gets an optional malformed output byte count.</summary>
        internal uint? ReportedBytes { get; init; }

        /// <summary>Gets an optional malformed output row count.</summary>
        internal uint? ReportedCount { get; init; }

        /// <summary>Gets an action performed before enumeration returns.</summary>
        internal Action? AfterEnumerate { get; init; }

        /// <summary>Gets an action performed before status returns.</summary>
        internal Action? AfterStatus { get; init; }

        /// <summary>Gets the number of enumeration attempts.</summary>
        internal int Enumerations { get; private set; }

        /// <summary>Gets the number of connection-status reads.</summary>
        internal int StatusReads { get; private set; }

        /// <summary>Checks structure versioning and fills bounded native rows or requests a larger buffer.</summary>
        public uint Enumerate(nint buffer, ref uint bytes, out uint count)
        {
            Enumerations++;
            Assert.Equal(1388, Marshal.ReadInt32(buffer));
            count = (uint)Connections;
            uint needed = Oversized ? 2_000_000u : GrowForever ? bytes + 1388 : checked(count * 1388);
            AfterEnumerate?.Invoke();
            if (needed > bytes) { bytes = needed; return 603; }
            if (EnumerationError != 0) { return EnumerationError; }
            for (int index = 0; index < Connections; index++)
            {
                nint row = buffer + index * 1388;
                Marshal.StructureToPtr(new NativeRemoteConnection
                {
                    Size = 1388,
                    Handle = InvalidHandle ? 0 : DuplicateHandles ? 1 : index + 1,
                    CorrelationId = Correlation
                }, row, false);
                char[] device = (Device.Length < 17 ? Device + '\0' : Device).ToCharArray();
                Marshal.Copy(device, 0, row + 526, device.Length);
            }
            bytes = ReportedBytes ?? needed;
            count = ReportedCount ?? count;
            return 0;
        }

        /// <summary>Returns a controlled state for one borrowed connection handle.</summary>
        public uint ReadStatus(nint connection, ref NativeRemoteStatus status)
        {
            Assert.NotEqual(0, connection);
            Assert.Equal(608u, status.Size);
            StatusReads++;
            status.State = State;
            status.Substate = Substate;
            status.Error = ConnectionError;
            AfterStatus?.Invoke();
            return StatusError;
        }
    }
}
