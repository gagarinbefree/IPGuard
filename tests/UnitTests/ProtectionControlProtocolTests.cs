using System.Buffers.Binary;
using System.Text;
using IPGuard.Application.Protection;
using IPGuard.Infrastructure.Control;
using Xunit;

namespace UnitTests;

/// <summary>Checks strict bounded command and report framing without Windows or native policy access.</summary>
public sealed class ProtectionControlProtocolTests
{
    /// <summary>Each fixed operation round-trips without closing its caller-owned stream.</summary>
    [Theory]
    [InlineData(ProtectionCommand.Status)]
    [InlineData(ProtectionCommand.Recheck)]
    [InlineData(ProtectionCommand.Stop)]
    public async Task CommandsRoundTrip(ProtectionCommand command)
    {
        using var stream = new MemoryStream();
        await ProtectionControlProtocol.WriteCommandAsync(stream, command, TestContext.Current.CancellationToken);
        Assert.InRange(stream.Length, 5, 260);
        stream.Position = 0;
        Assert.Equal(command, await ProtectionControlProtocol.ReadCommandAsync(stream, TestContext.Current.CancellationToken));
        Assert.Equal(stream.Length, stream.Position);
        Assert.True(stream.CanWrite);
    }

    /// <summary>Unknown, omitted, duplicated, incorrectly typed, and path-bearing commands are rejected.</summary>
    [Theory]
    [InlineData("null")]
    [InlineData("{}")]
    [InlineData("{\"version\":2,\"command\":\"status\"}")]
    [InlineData("{\"version\":1,\"command\":\"allow\"}")]
    [InlineData("{\"version\":1,\"command\":\"uninstall\"}")]
    [InlineData("{\"version\":1,\"command\":1}")]
    [InlineData("{\"version\":1,\"command\":\"STATUS\"}")]
    [InlineData("{\"version\":1,\"command\":\"1\"}")]
    [InlineData("{\"version\":1,\"command\":\"status, recheck\"}")]
    [InlineData("{\"version\":1,\"command\":\"status\",\"path\":\"pwsh.exe\"}")]
    [InlineData("{\"version\":1,\"command\":\"status\",\"command\":\"stop\"}")]
    [InlineData("{\"version\":1,\"Command\":\"status\"}")]
    [InlineData("{\"version\":1,\"command\":null}")]
    [InlineData("{\"version\":1,\"command\":\"status\",}")]
    public async Task UnsafeCommandsAreRejected(string json)
    {
        using var stream = Frame(json);
        await Assert.ThrowsAsync<InvalidDataException>(() => ProtectionControlProtocol.ReadCommandAsync(stream, TestContext.Current.CancellationToken));
    }

    /// <summary>Declared sizes are checked before body allocation or reading missing bytes.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(257)]
    [InlineData(uint.MaxValue)]
    public async Task UnsafeCommandLengthsAreRejected(uint length)
    {
        using var stream = FrameHeader(length);
        await Assert.ThrowsAsync<InvalidDataException>(() => ProtectionControlProtocol.ReadCommandAsync(stream, TestContext.Current.CancellationToken));
    }

    /// <summary>Truncated headers and bodies cannot become valid commands.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TruncatedFramesAreRejected(bool header)
    {
        using var stream = header ? new MemoryStream(new byte[3]) : FrameHeader(20);
        await Assert.ThrowsAsync<EndOfStreamException>(() => ProtectionControlProtocol.ReadCommandAsync(stream, TestContext.Current.CancellationToken));
    }

    /// <summary>Diagnostic serialization retains counts and observation time without transporting private exception text.</summary>
    [Fact]
    public async Task ReportsRoundTrip()
    {
        var report = new ProtectionControlReport(ProtectionPhase.Running, ProtectionReason.AssessmentUnavailable,
            BlockPolicyState.Present, 4, 4, DateTimeOffset.Parse("2026-10-27T10:00:00Z"), false);
        using var stream = new MemoryStream();
        await ProtectionControlProtocol.WriteReportAsync(stream, report, TestContext.Current.CancellationToken);
        Assert.InRange(stream.Length, 5, 4100);
        stream.Position = 0;
        var result = await ProtectionControlProtocol.ReadReportAsync(stream, TestContext.Current.CancellationToken);
        Assert.Equal(report.Phase, result.Phase);
        Assert.Equal(report.Reason, result.Reason);
        Assert.Equal(report.PolicyState, result.PolicyState);
        Assert.Equal(report.ExpectedRules, result.ExpectedRules);
        Assert.Equal(report.MatchingRules, result.MatchingRules);
        Assert.Equal(report.PolicyObservedAt, result.PolicyObservedAt);
        Assert.False(result.HasError);
    }

    /// <summary>Absent inspection data and error flags remain explicit rather than defaulting to success.</summary>
    [Fact]
    public async Task UnavailableReportRoundTrips()
    {
        var report = new ProtectionControlReport(ProtectionPhase.Stopped, ProtectionReason.PolicyUnavailable, null, 0, 0, null, true);
        using var stream = new MemoryStream();
        await ProtectionControlProtocol.WriteReportAsync(stream, report, TestContext.Current.CancellationToken);
        stream.Position = 0;
        var result = await ProtectionControlProtocol.ReadReportAsync(stream, TestContext.Current.CancellationToken);
        Assert.Null(result.PolicyState);
        Assert.Null(result.PolicyObservedAt);
        Assert.True(result.HasError);
    }

    /// <summary>Malformed reports cannot invent successful inspection data or omit required diagnostic fields.</summary>
    [Theory]
    [InlineData("null")]
    [InlineData("{\"version\":1,\"report\":null}")]
    [InlineData("{\"version\":1,\"report\":{}}")]
    [InlineData("{\"version\":1,\"report\":{\"phase\":\"running\",\"reason\":\"allow\"}}")]
    [InlineData("{\"version\":1,\"report\":{\"phase\":\"running\",\"reason\":\"policyUnavailable\",\"policyState\":null,\"expectedRules\":0,\"matchingRules\":0,\"policyObservedAt\":null}}")]
    [InlineData("{\"version\":1,\"report\":{\"phase\":\"running\",\"reason\":\"policyUnavailable\",\"policyState\":\"present\",\"expectedRules\":4,\"matchingRules\":3,\"policyObservedAt\":\"2026-10-27T10:00:00Z\",\"hasError\":false}}")]
    public async Task UnsafeReportsAreRejected(string json)
    {
        using var stream = Frame(json);
        await Assert.ThrowsAsync<InvalidDataException>(() => ProtectionControlProtocol.ReadReportAsync(stream, TestContext.Current.CancellationToken));
    }

    /// <summary>The report frame has its own bounded maximum before allocation.</summary>
    [Fact]
    public async Task OversizedReportIsRejected()
    {
        using var stream = FrameHeader(4097);
        await Assert.ThrowsAsync<InvalidDataException>(() => ProtectionControlProtocol.ReadReportAsync(stream, TestContext.Current.CancellationToken));
    }

    /// <summary>Contradictory counts, missing state, and undefined values cannot be constructed as valid diagnostics.</summary>
    [Theory]
    [InlineData(null, 4, 4)]
    [InlineData(BlockPolicyState.Present, 4, 3)]
    [InlineData(BlockPolicyState.Unknown, 4, 1)]
    [InlineData(BlockPolicyState.Incomplete, 4, 5)]
    [InlineData(BlockPolicyState.Incomplete, -1, 0)]
    [InlineData((BlockPolicyState)99, 4, 4)]
    public void ContradictoryReportsAreRejected(BlockPolicyState? state, int expected, int matching)
        => Assert.Throws<ArgumentException>(() => new ProtectionControlReport(ProtectionPhase.Running,
            ProtectionReason.PolicyUnavailable, state, expected, matching, state.HasValue ? DateTimeOffset.UtcNow : null, true));

    /// <summary>Writes a synthetic length-prefixed peer message.</summary>
    private static MemoryStream Frame(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var stream = FrameHeader((uint)bytes.Length);
        stream.Position = 4;
        stream.Write(bytes);
        stream.Position = 0;
        return stream;
    }

    /// <summary>Writes only a declared unsigned network-order length.</summary>
    private static MemoryStream FrameHeader(uint length)
    {
        var stream = new MemoryStream();
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, length);
        stream.Write(header);
        stream.Position = 0;
        return stream;
    }
}
