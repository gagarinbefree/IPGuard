using System.Net.Sockets;
using IPGuard.Application.PublicIp;
using IPGuard.Infrastructure.PublicIp;
using Xunit;

namespace UnitTests;

/// <summary>Checks trusted source configuration before any network request can begin.</summary>
public sealed class PublicIpSourceTests
{
    /// <summary>Each family has two different configured operators, with family-specific HTTPS endpoints.</summary>
    [Theory]
    [InlineData(AddressFamily.InterNetwork, "api.ipify.org", "4.ident.me")]
    [InlineData(AddressFamily.InterNetworkV6, "api6.ipify.org", "6.ident.me")]
    public void Defaults_ContainIndependentOperatorsForEachFamily(AddressFamily family, string firstHost, string secondHost)
    {
        PublicIpSource[] sources = PublicIpSources.Defaults.Where(source => source.Family == family).ToArray();

        Assert.Equal(2, sources.Length);
        Assert.Equal(2, sources.Select(source => source.OperatorId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Equal(new[] { firstHost, secondHost }, sources.Select(source => source.Endpoint.Host));
        Assert.All(sources, source => Assert.Equal("https", source.Endpoint.Scheme));
    }

    /// <summary>Explicit HTTPS endpoints retain their selected family and normalized configured operator.</summary>
    [Theory]
    [InlineData(AddressFamily.InterNetwork)]
    [InlineData(AddressFamily.InterNetworkV6)]
    public void Constructor_ValidSource_PreservesEndpoint(AddressFamily family)
    {
        var endpoint = new Uri("https://source.example/ip?plain=true");
        var source = new PublicIpSource(" operator-a ", endpoint, family);

        Assert.Equal("operator-a", source.OperatorId);
        Assert.Equal(endpoint, source.Endpoint);
        Assert.Equal(family, source.Family);
    }

    /// <summary>Insecure URLs, embedded credentials, fragments, and relative paths are configuration errors.</summary>
    [Theory]
    [InlineData("http://source.example/")]
    [InlineData("ftp://source.example/")]
    [InlineData("https://user:password@source.example/")]
    [InlineData("https://source.example/#fragment")]
    [InlineData("/ip")]
    public void Constructor_InvalidEndpoint_IsRejected(string endpoint)
    {
        Assert.Throws<ArgumentException>(() => new PublicIpSource("operator-a",
            new Uri(endpoint, UriKind.RelativeOrAbsolute), AddressFamily.InterNetwork));
    }

    /// <summary>Missing operators cannot count toward independent agreement.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Constructor_InvalidOperator_IsRejected(string? operatorId)
    {
        Assert.ThrowsAny<ArgumentException>(() => new PublicIpSource(operatorId!, new Uri("https://source.example/"), AddressFamily.InterNetwork));
    }

    /// <summary>Unspecified or unrelated socket families cannot silently select dual-stack transport.</summary>
    [Theory]
    [InlineData(AddressFamily.Unspecified)]
    [InlineData(AddressFamily.Unix)]
    public void Constructor_UnsupportedFamily_IsRejected(AddressFamily family)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new PublicIpSource("operator-a", new Uri("https://source.example/"), family));
    }
}
