using System.Net;
using System.Runtime.InteropServices;
using IPGuard.Application.Network;
using IPGuard.Windows.Network.Native;
using Xunit;

namespace UnitTests;

/// <summary>Checks immutable diagnostic values and independently verified Windows x64 layout constants.</summary>
public sealed class NetworkRouteTests
{
    /// <summary>Metric sums use 64 bits and unspecified components never become an apparent best route.</summary>
    [Theory]
    [InlineData(5u, 20u, 25ul)]
    [InlineData(4294967294u, 4294967294u, 8589934588ul)]
    [InlineData(uint.MaxValue, 20u, null)]
    [InlineData(5u, uint.MaxValue, null)]
    public void MetricSumPreservesUnknownAndAvoidsOverflow(uint routeMetric, uint interfaceMetric, ulong? expected)
    {
        var route = new NetworkRoute(new IPNetwork(IPAddress.Any, 0), IPAddress.Parse("192.168.1.1"), "interface-a", 12,
            routeMetric, interfaceMetric, true, false, 0, true);
        Assert.Equal(expected, route.TotalMetric);
        Assert.Equal(0u, route.ValidLifetimeSeconds);
        Assert.True(route.Loopback);
    }

    /// <summary>Changing the caller's IPv6 scope cannot mutate published diagnostic text.</summary>
    [Fact]
    public void CopiesMutableAddressText()
    {
        var prefix = IPAddress.Parse("2001:db8::");
        var gateway = IPAddress.Parse("fe80::1%12");
        var route = new NetworkRoute(new IPNetwork(prefix, 32), gateway, "interface-a", 12, 5, 20, false, true, 60, false);
        prefix.ScopeId = 99;
        gateway.ScopeId = 99;
        Assert.Equal("2001:db8::/32", route.Destination);
        Assert.Equal("fe80::1%12", route.NextHop);
        Assert.False(route.Connected);
        Assert.True(route.DefaultRoutesDisabled);
        Assert.Equal(60u, route.ValidLifetimeSeconds);
    }

    /// <summary>Mixed and mapped families do not enter the diagnostic contract.</summary>
    [Theory]
    [InlineData("0.0.0.0", "::1")]
    [InlineData("::", "192.168.1.1")]
    [InlineData("::", "::ffff:192.168.1.1")]
    public void RejectsInconsistentFamilies(string prefix, string gateway)
    {
        Assert.Throws<ArgumentException>(() => new NetworkRoute(new IPNetwork(IPAddress.Parse(prefix), 0), IPAddress.Parse(gateway),
            "interface-a", 12, 5, 20, true, false, 60, false));
    }

    /// <summary>Sizes and offsets match a native clang-cl probe against Windows SDK 10.0.26100.0 on x64.</summary>
    [Fact]
    public void NativeLayoutMatchesSdk()
    {
        Assert.Equal(28, Marshal.SizeOf<NativeRouteAddress>());
        Assert.Equal(104, Marshal.SizeOf<NativeRouteRow>());
        Assert.Equal(168, Marshal.SizeOf<NativeRouteInterface>());
        Assert.Equal(8, Marshal.OffsetOf<NativeRouteTable>(nameof(NativeRouteTable.FirstRow)).ToInt32());
        Assert.Equal(12, Marshal.OffsetOf<NativeRouteRow>(nameof(NativeRouteRow.Prefix)).ToInt32());
        Assert.Equal(40, Marshal.OffsetOf<NativeRouteRow>(nameof(NativeRouteRow.PrefixLength)).ToInt32());
        Assert.Equal(44, Marshal.OffsetOf<NativeRouteRow>(nameof(NativeRouteRow.NextHop)).ToInt32());
        Assert.Equal(84, Marshal.OffsetOf<NativeRouteRow>(nameof(NativeRouteRow.Metric)).ToInt32());
        Assert.Equal(148, Marshal.OffsetOf<NativeRouteInterface>(nameof(NativeRouteInterface.Metric)).ToInt32());
        Assert.Equal(166, Marshal.OffsetOf<NativeRouteInterface>(nameof(NativeRouteInterface.DisableDefaultRoutes)).ToInt32());
    }
}
