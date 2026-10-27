using System.Text;
using System.Diagnostics;
using IPGuard.Windows.Control;
using Xunit;

namespace UnitTests;

/// <summary>Checks bounded protocol negotiation without native pipes or application commands.</summary>
public sealed class ControlPipeHandshakeTests
{
    /// <summary>One supported marker is consumed without reading the following application byte.</summary>
    [Fact]
    public async Task SupportedMarkerLeavesPayloadUnread()
    {
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes("IPGuard.Control/1\nX"));
        await ControlPipeHandshake.ReadAsync(stream, TestContext.Current.CancellationToken);
        Assert.Equal('X', stream.ReadByte());
        Assert.True(stream.CanRead);
    }

    /// <summary>Empty and partial markers fail explicitly instead of accepting a disconnected peer.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("IPGuard.")]
    [InlineData("IPGuard.Control/1")]
    public async Task TruncatedMarkerIsRejected(string text)
    {
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        await Assert.ThrowsAsync<EndOfStreamException>(() => ControlPipeHandshake.ReadAsync(stream, TestContext.Current.CancellationToken));
    }

    /// <summary>Same-length unsupported versions and malformed bytes are not negotiated implicitly.</summary>
    [Theory]
    [InlineData("IPGuard.Control/2\n")]
    [InlineData("ipguard.Control/1\n")]
    [InlineData("IPGuard.Control/1\0")]
    public async Task UnsupportedMarkerIsRejected(string text)
    {
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        await Assert.ThrowsAsync<InvalidDataException>(() => ControlPipeHandshake.ReadAsync(stream, TestContext.Current.CancellationToken));
    }

    /// <summary>The outgoing marker is fixed and does not close its caller's stream.</summary>
    [Fact]
    public async Task WriteUsesFixedMarker()
    {
        using var stream = new MemoryStream();
        await ControlPipeHandshake.WriteAsync(stream, TestContext.Current.CancellationToken);
        Assert.Equal("IPGuard.Control/1\n", Encoding.ASCII.GetString(stream.ToArray()));
        Assert.True(stream.CanWrite);
    }

    /// <summary>Only locally generated endpoint names are accepted.</summary>
    [Fact]
    public void GeneratedNameIsAccepted() => WindowsControlPipe.ValidateName("IPGuard.Control.0123456789abcdef0123456789abcdef");

    /// <summary>Paths, alternate namespaces, empty identifiers, and malformed names are rejected before connecting.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("IPGuard.Control.")]
    [InlineData("IPGuard.Control.0123456789abcdef0123456789abcdeg")]
    [InlineData("IPGuard.Control.01234567-89ab-cdef-0123-456789abcdef")]
    [InlineData("IPGuard.Control.0123456789abcdef0123456789abcdef/extra")]
    [InlineData("\\\\server\\pipe\\IPGuard.Control.0123456789abcdef0123456789abcdef")]
    [InlineData("Other.Control.0123456789abcdef0123456789abcdef")]
    public void InvalidNameIsRejected(string name) => Assert.Throws<ArgumentException>(() => WindowsControlPipe.ValidateName(name));

    /// <summary>Invalid deadlines are rejected before token reads, pipe creation, or waiting.</summary>
    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(0.5)]
    [InlineData(60001)]
    public async Task InvalidTimeoutIsRejected(double milliseconds)
    {
        using var peer = Process.GetCurrentProcess();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => WindowsControlPipe.ConnectAsync(
            "IPGuard.Control.0123456789abcdef0123456789abcdef", peer, TimeSpan.FromMilliseconds(milliseconds), TestContext.Current.CancellationToken));
    }
}
