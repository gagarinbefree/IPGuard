using System.Net.Sockets;
using System.Text;
using IPGuard.Infrastructure.PublicIp;
using Xunit;

namespace UnitTests;

/// <summary>Checks untrusted plaintext syntax and conservative public-unicast classification.</summary>
public sealed class PublicAddressParserTests
{
    /// <summary>Ordinary unicast addresses and range boundaries outside special blocks remain candidates.</summary>
    [Theory]
    [InlineData("1.1.1.1", AddressFamily.InterNetwork, "1.1.1.1")]
    [InlineData(" \t8.8.8.8\r\n", AddressFamily.InterNetwork, "8.8.8.8")]
    [InlineData("100.63.255.254", AddressFamily.InterNetwork, "100.63.255.254")]
    [InlineData("100.128.0.1", AddressFamily.InterNetwork, "100.128.0.1")]
    [InlineData("172.15.255.254", AddressFamily.InterNetwork, "172.15.255.254")]
    [InlineData("172.32.0.1", AddressFamily.InterNetwork, "172.32.0.1")]
    [InlineData("192.0.1.1", AddressFamily.InterNetwork, "192.0.1.1")]
    [InlineData("198.17.255.254", AddressFamily.InterNetwork, "198.17.255.254")]
    [InlineData("198.20.0.1", AddressFamily.InterNetwork, "198.20.0.1")]
    [InlineData("2606:4700:4700:0:0:0:0:1111\n", AddressFamily.InterNetworkV6, "2606:4700:4700::1111")]
    [InlineData("2001:4860:4860::8888", AddressFamily.InterNetworkV6, "2001:4860:4860::8888")]
    [InlineData("2A02:6B8::1", AddressFamily.InterNetworkV6, "2a02:6b8::1")]
    [InlineData("2410::1", AddressFamily.InterNetworkV6, "2410::1")]
    [InlineData("2001:200::1", AddressFamily.InterNetworkV6, "2001:200::1")]
    public void Parse_ValidCandidate_ReturnsCanonicalAddress(string body, AddressFamily family, string expected)
    {
        Assert.Equal(expected, PublicAddressParser.Parse(Encoding.UTF8.GetBytes(body), family)?.ToString());
    }

    /// <summary>IPv4 special-purpose blocks, multicast, and reserved addresses cannot identify the public host.</summary>
    [Theory]
    [InlineData("0.1.2.3")]
    [InlineData("10.0.0.1")]
    [InlineData("100.64.0.0")]
    [InlineData("100.127.255.255")]
    [InlineData("127.0.0.2")]
    [InlineData("169.254.1.2")]
    [InlineData("172.16.0.0")]
    [InlineData("172.31.255.255")]
    [InlineData("192.0.0.9")]
    [InlineData("192.0.0.170")]
    [InlineData("192.0.2.1")]
    [InlineData("192.31.196.1")]
    [InlineData("192.52.193.1")]
    [InlineData("192.88.99.2")]
    [InlineData("192.168.1.1")]
    [InlineData("192.175.48.1")]
    [InlineData("198.18.0.1")]
    [InlineData("198.19.255.255")]
    [InlineData("198.51.100.1")]
    [InlineData("203.0.113.1")]
    [InlineData("224.0.0.1")]
    [InlineData("239.255.255.255")]
    [InlineData("240.0.0.1")]
    [InlineData("255.255.255.255")]
    public void Parse_SpecialIpv4_IsRejected(string body)
    {
        Assert.Null(PublicAddressParser.Parse(Encoding.ASCII.GetBytes(body), AddressFamily.InterNetwork));
    }

    /// <summary>IPv6 local, transition, special-purpose, documentation, and unallocated ranges remain ineligible.</summary>
    [Theory]
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("::ffff:1.1.1.1")]
    [InlineData("64:ff9b::808:808")]
    [InlineData("64:ff9b:1::1")]
    [InlineData("100::1")]
    [InlineData("100:0:0:1::1")]
    [InlineData("2001::1")]
    [InlineData("2001:1::1")]
    [InlineData("2001:20::1")]
    [InlineData("2001:db8::1")]
    [InlineData("2002:808:808::1")]
    [InlineData("2620:4f:8000::1")]
    [InlineData("2d00::1")]
    [InlineData("3000::1")]
    [InlineData("3fff::1")]
    [InlineData("5f00::1")]
    [InlineData("fc00::1")]
    [InlineData("fe80::1")]
    [InlineData("ff02::1")]
    public void Parse_NonordinaryIpv6_IsRejected(string body)
    {
        Assert.Null(PublicAddressParser.Parse(Encoding.ASCII.GetBytes(body), AddressFamily.InterNetworkV6));
    }

    /// <summary>Ambiguous numeric formats, multiple addresses, non-ASCII input, and structured documents are rejected.</summary>
    [Theory]
    [InlineData("")]
    [InlineData(" \r\n")]
    [InlineData("1")]
    [InlineData("1.1.1")]
    [InlineData("010.1.1.1")]
    [InlineData("0x08.8.8.8")]
    [InlineData("134744072")]
    [InlineData("8.8.8.256")]
    [InlineData("8.8.8.8:443")]
    [InlineData("8.8.8.8\n1.1.1.1")]
    [InlineData("{\"ip\":\"8.8.8.8\"}")]
    [InlineData("<html>8.8.8.8</html>")]
    [InlineData("\uFEFF8.8.8.8")]
    [InlineData("\u00a08.8.8.8")]
    [InlineData("８.８.８.８")]
    [InlineData("8.8.8.8\0")]
    public void Parse_MalformedPlaintext_IsRejected(string body)
    {
        Assert.Null(PublicAddressParser.Parse(Encoding.UTF8.GetBytes(body), AddressFamily.InterNetwork));
    }

    /// <summary>Neither mapped values nor URI or zone syntax can bypass per-family parsing.</summary>
    [Theory]
    [InlineData("1.1.1.1", AddressFamily.InterNetworkV6)]
    [InlineData("2606:4700::1111", AddressFamily.InterNetwork)]
    [InlineData("::ffff:1.1.1.1", AddressFamily.InterNetwork)]
    [InlineData("2606:4700::1111%0", AddressFamily.InterNetworkV6)]
    [InlineData("2606:4700::1111%7", AddressFamily.InterNetworkV6)]
    [InlineData("[2606:4700::1111]", AddressFamily.InterNetworkV6)]
    [InlineData("1.1.1.1", AddressFamily.Unspecified)]
    public void Parse_InvalidFamilyOrDecoratedAddress_IsRejected(string body, AddressFamily family)
    {
        Assert.Null(PublicAddressParser.Parse(Encoding.ASCII.GetBytes(body), family));
    }

    /// <summary>The parser checks its own complete byte limit, including otherwise ignorable whitespace.</summary>
    [Theory]
    [InlineData(128, true)]
    [InlineData(129, false)]
    public void Parse_BodyLimit_IsBounded(int length, bool accepted)
    {
        byte[] body = Encoding.ASCII.GetBytes("1.1.1.1".PadRight(length));

        Assert.Equal(accepted, PublicAddressParser.Parse(body, AddressFamily.InterNetwork) is not null);
    }
}
