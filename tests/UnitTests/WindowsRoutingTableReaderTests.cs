using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using IPGuard.Windows.Network;
using IPGuard.Windows.Network.Native;
using Xunit;

namespace UnitTests;

/// <summary>Checks routing buffer ownership and decoding without reading or changing the host network.</summary>
public sealed class WindowsRoutingTableReaderTests
{
    /// <summary>Copies defaults, specific routes, scoped gateways, and interface metrics before freeing native memory.</summary>
    [Fact]
    public void CopiesBothFamiliesAndSpecificRoutes()
    {
        using var api = new RoutingApi([
            Row("0.0.0.0", 0, "192.168.1.1"), Row("10.0.0.0", 8, "192.168.1.2"),
            Row("::", 0, "fe80::1%12"), Row("2000::", 3, "::")]);
        var routes = new WindowsRoutingTableReader(api).Read(TestContext.Current.CancellationToken);
        Assert.Equal(4, routes.Count);
        Assert.Equal("0.0.0.0/0", routes[0].Destination);
        Assert.Equal("10.0.0.0/8", routes[1].Destination);
        Assert.Equal("::/0", routes[2].Destination);
        Assert.Equal("fe80::1%12", routes[2].NextHop);
        Assert.Equal("2000::/3", routes[3].Destination);
        Assert.Equal("::", routes[3].NextHop);
        Assert.All(routes, route =>
        {
            Assert.Equal("0000000000001234", route.InterfaceId);
            Assert.Equal(12u, route.InterfaceIndex);
            Assert.Equal(5u, route.RouteMetric);
            Assert.Equal(20u, route.InterfaceMetric);
            Assert.Equal(25ul, route.TotalMetric);
            Assert.True(route.Connected);
            Assert.False(route.DefaultRoutesDisabled);
            Assert.Equal(uint.MaxValue, route.ValidLifetimeSeconds);
        });
        Assert.Equal(2, api.InterfaceReads);
        Assert.Equal(1, api.Frees);
    }

    /// <summary>Empty tables produce empty diagnostics and do not prove absence of all network paths.</summary>
    [Fact]
    public void EmptyTableStillReleasesBuffer()
    {
        using var api = new RoutingApi([]);
        Assert.Empty(new WindowsRoutingTableReader(api).Read(TestContext.Current.CancellationToken));
        Assert.Equal(1, api.Frees);
        Assert.Equal(0, api.InterfaceReads);
    }

    /// <summary>Native failure and invalid table output fail explicitly, without partial rows.</summary>
    [Theory]
    [InlineData("native")]
    [InlineData("null")]
    [InlineData("count")]
    public void BadTableFailsAndReleasesOwnedMemory(string failure)
    {
        using var api = new RoutingApi([]) { TableError = failure == "native" ? 5u : 0, ReturnNull = failure == "null" };
        if (failure == "count") { Marshal.WriteInt32(api.Table, 65537); }
        var error = Record.Exception(() => new WindowsRoutingTableReader(api).Read(TestContext.Current.CancellationToken));
        if (failure == "native") { Assert.Equal(5, Assert.IsType<Win32Exception>(error).NativeErrorCode); }
        else { Assert.IsType<InvalidDataException>(error); }
        Assert.Equal(failure == "null" ? 0 : 1, api.Frees);
    }

    /// <summary>Malformed rows and mismatched interface data fail the entire native read.</summary>
    [Theory]
    [InlineData("family")]
    [InlineData("prefix-length")]
    [InlineData("host-bits")]
    [InlineData("ipv6-host-bits")]
    [InlineData("ipv6-prefix-length")]
    [InlineData("mapped")]
    [InlineData("next-hop")]
    [InlineData("luid")]
    [InlineData("index")]
    [InlineData("interface")]
    [InlineData("interface-identity")]
    public void InvalidRowReleasesTable(string failure)
    {
        var row = Row("10.0.0.0", 8, "192.168.1.1");
        switch (failure)
        {
            case "family": row.Prefix.Family = 0; break;
            case "prefix-length": row.PrefixLength = 33; break;
            case "host-bits": row.Prefix = Address("10.1.2.3"); break;
            case "ipv6-host-bits": row.Prefix = Address("2001:db8::1"); row.PrefixLength = 32; row.NextHop = Address("::"); break;
            case "ipv6-prefix-length": row.Prefix = Address("::"); row.PrefixLength = 129; row.NextHop = Address("::"); break;
            case "mapped": row.Prefix = Address("::"); row.PrefixLength = 0; row.NextHop = Address("::ffff:192.168.1.1"); break;
            case "next-hop": row.NextHop = Address("::1"); break;
            case "luid": row.InterfaceLuid = 0; break;
            case "index": row.InterfaceIndex = 0; break;
        }
        using var api = new RoutingApi([row])
        {
            InterfaceError = failure == "interface" ? 1168u : 0,
            CorruptInterfaceIdentity = failure == "interface-identity"
        };
        var error = Record.Exception(() => new WindowsRoutingTableReader(api).Read(TestContext.Current.CancellationToken));
        if (failure == "interface") { Assert.IsType<Win32Exception>(error); }
        else { Assert.IsType<InvalidDataException>(error); }
        Assert.Equal(1, api.Frees);
    }

    /// <summary>Cancellation before allocation performs no reads; cancellation after allocation still frees the table.</summary>
    [Theory]
    [InlineData("before")]
    [InlineData("table")]
    [InlineData("interface")]
    [InlineData("free")]
    public void CancellationDoesNotLeakBuffers(string when)
    {
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        using var api = new RoutingApi([Row("0.0.0.0", 0, "192.168.1.1")])
        {
            AfterTable = when == "table" ? caller.Cancel : null,
            AfterInterface = when == "interface" ? caller.Cancel : null,
            AfterFree = when == "free" ? caller.Cancel : null
        };
        if (when == "before") { caller.Cancel(); }
        Assert.ThrowsAny<OperationCanceledException>(() => new WindowsRoutingTableReader(api).Read(caller.Token));
        Assert.Equal(when == "before" ? 0 : 1, api.Frees);
    }

    /// <summary>Cleanup failure retains the original read error instead of overwriting it.</summary>
    [Fact]
    public void ReadAndCleanupFailureAreBothRetained()
    {
        using var api = new RoutingApi([]) { TableError = 5, FailFree = true };
        var error = Assert.Throws<AggregateException>(() => new WindowsRoutingTableReader(api).Read(TestContext.Current.CancellationToken));
        Assert.Contains(error.InnerExceptions, failure => failure is Win32Exception);
        Assert.Contains(error.InnerExceptions, failure => failure is IOException);
        Assert.Equal(1, api.Frees);
    }

    /// <summary>Creates native rows with a stable interface identity and distinct per-route diagnostics.</summary>
    private static NativeRouteRow Row(string prefix, byte length, string gateway) => new()
    {
        InterfaceLuid = 0x1234,
        InterfaceIndex = 12,
        Prefix = Address(prefix),
        PrefixLength = length,
        NextHop = Address(gateway),
        ValidLifetime = uint.MaxValue,
        Metric = 5
    };

    /// <summary>Encodes native address bytes in memory order, including IPv6 scope.</summary>
    private static NativeRouteAddress Address(string text)
    {
        var address = IPAddress.Parse(text);
        var bytes = address.GetAddressBytes();
        return bytes.Length == 4
            ? new() { Family = 2, Ipv4 = BinaryPrimitives.ReadUInt32LittleEndian(bytes) }
            : new()
            {
                Family = 23,
                Ipv6First = BinaryPrimitives.ReadUInt64LittleEndian(bytes),
                Ipv6Second = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(8)),
                ScopeId = checked((uint)address.ScopeId)
            };
    }

    /// <summary>Owns controlled native-shaped memory, without calling any IP Helper API.</summary>
    private sealed class RoutingApi : IRoutingApi, IDisposable
    {
        /// <summary>Allocates the SDK-aligned header followed by complete route row strides.</summary>
        internal RoutingApi(NativeRouteRow[] rows)
        {
            Table = Marshal.AllocHGlobal(8 + rows.Length * 104);
            Marshal.WriteInt32(Table, rows.Length);
            for (int index = 0; index < rows.Length; index++)
            {
                Marshal.StructureToPtr(rows[index], Table + 8 + index * 104, false);
            }
        }

        /// <summary>Gets the controlled allocation, owned by the test fixture.</summary>
        internal nint Table { get; }

        /// <summary>Gets a native failure to report after assigning the output pointer.</summary>
        internal uint TableError { get; init; }

        /// <summary>Gets a per-interface native failure.</summary>
        internal uint InterfaceError { get; init; }

        /// <summary>Gets whether table allocation should incorrectly return null.</summary>
        internal bool ReturnNull { get; init; }

        /// <summary>Gets whether the interface result should mismatch its requested identity.</summary>
        internal bool CorruptInterfaceIdentity { get; init; }

        /// <summary>Gets whether cleanup should fail after recording its attempt.</summary>
        internal bool FailFree { get; init; }

        /// <summary>Gets a controlled cancellation or change after the table API returns.</summary>
        internal Action? AfterTable { get; init; }

        /// <summary>Gets a controlled cancellation or change during interface metadata reading.</summary>
        internal Action? AfterInterface { get; init; }

        /// <summary>Gets a controlled cancellation while the final native buffer is released.</summary>
        internal Action? AfterFree { get; init; }

        /// <summary>Gets the number of attempted native table releases.</summary>
        internal int Frees { get; private set; }

        /// <summary>Gets the number of distinct interface metadata requests.</summary>
        internal int InterfaceReads { get; private set; }

        /// <summary>Returns controlled memory and optionally changes state before returning.</summary>
        public uint ReadTable(out nint table)
        {
            table = ReturnNull ? 0 : Table;
            AfterTable?.Invoke();
            return TableError;
        }

        /// <summary>Preserves requested identity while supplying a controlled metric and connection flag.</summary>
        public uint ReadInterface(ref NativeRouteInterface row)
        {
            InterfaceReads++;
            row.Metric = 20;
            row.Connected = 1;
            if (CorruptInterfaceIdentity) { row.InterfaceIndex++; }
            AfterInterface?.Invoke();
            return InterfaceError;
        }

        /// <summary>Records the adapter's release while fixture ownership prevents double-free in failed tests.</summary>
        public void FreeTable(nint table)
        {
            Assert.Equal(Table, table);
            Frees++;
            AfterFree?.Invoke();
            if (FailFree) { throw new IOException("Free failed."); }
        }

        /// <summary>Releases controlled memory exactly once at test cleanup.</summary>
        public void Dispose() => Marshal.FreeHGlobal(Table);
    }
}
