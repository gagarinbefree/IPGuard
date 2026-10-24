using System.Net;
using IPGuard.Domain;
using IPGuard.Windows.Network;
using Xunit;

namespace UnitTests;

/// <summary>Checks conservative family classification independently of the host configuration.</summary>
public sealed class WindowsNetworkFamiliesTests
{
    /// <summary>Configured private and link-local addresses select probes without claiming public reachability.</summary>
    [Theory]
    [InlineData("192.168.1.2", true, false)]
    [InlineData("169.254.1.2", true, false)]
    [InlineData("fe80::1", false, true)]
    [InlineData("2001:db8::1", false, true)]
    [InlineData("127.0.0.1", false, false)]
    [InlineData("::1", false, false)]
    [InlineData("0.0.0.0", false, false)]
    [InlineData("::", false, false)]
    [InlineData("::ffff:192.168.1.2", false, false)]
    public void ConfiguredFamilyIsOnlyACandidate(string address, bool ipv4, bool ipv6)
    {
        var result = WindowsNetworkFamilies.Classify([new(true, false, [IPAddress.Parse(address)])]);
        Assert.Equal(ipv4 ? IpFamilyAvailability.Available : IpFamilyAvailability.Unknown, result.Ipv4);
        Assert.Equal(ipv6 ? IpFamilyAvailability.Available : IpFamilyAvailability.Unknown, result.Ipv6);
    }

    /// <summary>Down and loopback interfaces cannot make a family available.</summary>
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public void NonUsableInterfaceRemainsUnknown(bool up, bool loopback)
    {
        var result = WindowsNetworkFamilies.Classify([new(up, loopback, [IPAddress.Parse("192.168.1.2"), IPAddress.Parse("fe80::1")])]);
        Assert.Equal(IpFamilyAvailability.Unknown, result.Ipv4);
        Assert.Equal(IpFamilyAvailability.Unknown, result.Ipv6);
    }

    /// <summary>Missing interfaces and missing addresses are uncertainty rather than evidence of absence.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingCandidatesNeverProveUnavailability(bool emptyInterface)
    {
        var result = WindowsNetworkFamilies.Classify(emptyInterface ? [new(true, false, [])] : []);
        Assert.Equal(IpFamilyAvailability.Unknown, result.Ipv4);
        Assert.Equal(IpFamilyAvailability.Unknown, result.Ipv6);
    }

    /// <summary>Candidates on separate physical or VPN interfaces are retained without asserting a common route.</summary>
    [Fact]
    public void CombinesCandidatesFromDifferentInterfaces()
    {
        var result = WindowsNetworkFamilies.Classify([
            new(true, false, [IPAddress.Parse("192.168.1.2")]),
            new(true, false, [IPAddress.Parse("fe80::1")])]);
        Assert.Equal(IpFamilyAvailability.Available, result.Ipv4);
        Assert.Equal(IpFamilyAvailability.Available, result.Ipv6);
    }
}
