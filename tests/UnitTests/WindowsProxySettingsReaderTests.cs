using System.ComponentModel;
using System.Runtime.InteropServices;
using IPGuard.Windows.Network;
using IPGuard.Windows.Network.Native;
using Xunit;

namespace UnitTests;

/// <summary>Checks configuration separation and allocation cleanup without reading or changing host settings.</summary>
public sealed class WindowsProxySettingsReaderTests
{
    /// <summary>User, WinHTTP, and environment configuration remain independent and contain no raw credentials.</summary>
    [Fact]
    public void ReadsIndependentFlagsAndFreesAllStrings()
    {
        using var api = new ProxyApi();
        api.User = new() { AutoDetect = 1, AutoConfigUrl = api.Text("https://private/pac"), Proxy = api.Text("user:secret@proxy"), Bypass = api.Text("local") };
        api.Default = new() { AccessType = 3, Proxy = api.Text("machine:8080"), Bypass = api.Text("private") };
        var result = new WindowsProxySettingsReader(api, name => name == "HTTPS_PROXY" ? "secret" : null).Read(TestContext.Current.CancellationToken);
        Assert.True(result.UserProxy);
        Assert.True(result.UserBypass);
        Assert.True(result.AutoDetect);
        Assert.True(result.AutoConfigScript);
        Assert.True(result.LegacyWinHttpProxy);
        Assert.True(result.LegacyWinHttpBypass);
        Assert.True(result.ProcessProxy);
        Assert.False(result.ProcessBypass);
        Assert.Equal(5, api.Freed.Count);
    }

    /// <summary>Empty native strings and whitespace environment values are not configured mechanisms.</summary>
    [Fact]
    public void EmptyConfigurationDoesNotInventSettings()
    {
        using var api = new ProxyApi();
        api.User = new() { Proxy = api.Text(""), AutoConfigUrl = api.Text("") };
        var result = new WindowsProxySettingsReader(api, _ => " ").Read(TestContext.Current.CancellationToken);
        Assert.False(result.UserProxy);
        Assert.False(result.UserBypass);
        Assert.False(result.AutoDetect);
        Assert.False(result.AutoConfigScript);
        Assert.False(result.LegacyWinHttpProxy);
        Assert.False(result.ProcessProxy);
        Assert.False(result.ProcessBypass);
        Assert.Equal(2, api.Freed.Count);
    }

    /// <summary>Every relevant environment mechanism is read afresh, without writing process or machine settings.</summary>
    [Theory]
    [InlineData("HTTP_PROXY", true, false)]
    [InlineData("HTTPS_PROXY", true, false)]
    [InlineData("ALL_PROXY", true, false)]
    [InlineData("NO_PROXY", false, true)]
    public void ObservesProcessVariables(string variable, bool proxy, bool bypass)
    {
        using var api = new ProxyApi();
        var result = new WindowsProxySettingsReader(api, name => name == variable ? "configured" : null).Read(TestContext.Current.CancellationToken);
        Assert.Equal(proxy, result.ProcessProxy);
        Assert.Equal(bypass, result.ProcessBypass);
    }

    /// <summary>Unknown or inconsistent WinHTTP access types never become a direct observation.</summary>
    [Theory]
    [InlineData(0u, false)]
    [InlineData(4u, false)]
    [InlineData(99u, false)]
    [InlineData(3u, false)]
    [InlineData(1u, true)]
    public void RejectsInconsistentDefaultConfiguration(uint access, bool hasProxy)
    {
        using var api = new ProxyApi();
        api.Default = new() { AccessType = access, Proxy = hasProxy ? api.Text("proxy") : 0 };
        Assert.Throws<InvalidDataException>(() => new WindowsProxySettingsReader(api, _ => null).Read(TestContext.Current.CancellationToken));
        Assert.Equal(hasProxy ? 1 : 0, api.Freed.Count);
    }

    /// <summary>Native failures keep their error code and release strings even from partial results.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void NativeErrorsDoNotBecomeEmptySettings(bool userFails)
    {
        using var api = new ProxyApi { UserError = userFails ? 2u : 0, DefaultError = userFails ? 0 : 5u };
        api.User = new() { Proxy = api.Text("user-proxy") };
        api.Default = new() { AccessType = 1, Bypass = api.Text("bypass") };
        var error = Assert.Throws<Win32Exception>(() => new WindowsProxySettingsReader(api, _ => null).Read(TestContext.Current.CancellationToken));
        Assert.Equal(userFails ? 2 : 5, error.NativeErrorCode);
        Assert.Equal(userFails ? 1 : 2, api.Freed.Count);
    }

    /// <summary>Caller cancellation still frees every allocation already returned.</summary>
    [Theory]
    [InlineData("before")]
    [InlineData("user")]
    [InlineData("default")]
    [InlineData("environment")]
    [InlineData("free")]
    public void CancellationReleasesOwnedStrings(string when)
    {
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        using var api = new ProxyApi
        {
            AfterUser = when == "user" ? caller.Cancel : null,
            AfterDefault = when == "default" ? caller.Cancel : null,
            AfterFree = when == "free" ? caller.Cancel : null
        };
        api.User = new() { Proxy = api.Text("proxy") };
        if (when == "before") { caller.Cancel(); }
        var reader = new WindowsProxySettingsReader(api, _ => { if (when == "environment") { caller.Cancel(); } return null; });
        Assert.ThrowsAny<OperationCanceledException>(() => reader.Read(caller.Token));
        Assert.Equal(when == "before" ? 0 : 1, api.Freed.Count);
    }

    /// <summary>Cleanup attempts every unique pointer and preserves the original native error.</summary>
    [Fact]
    public void CleanupErrorsDoNotHideReadErrorOrDoubleFreeAliasedStrings()
    {
        using var api = new ProxyApi { DefaultError = 5, FailFree = true };
        var shared = api.Text("shared");
        api.User = new() { Proxy = shared, Bypass = shared, AutoConfigUrl = api.Text("pac") };
        var error = Assert.Throws<AggregateException>(() => new WindowsProxySettingsReader(api, _ => null).Read(TestContext.Current.CancellationToken));
        Assert.Equal(3, error.Flatten().InnerExceptions.Count);
        Assert.Equal(2, api.Freed.Count);
        Assert.Equal(2, api.Freed.Distinct().Count());
    }

    /// <summary>A successful native read cannot publish settings when cleanup fails.</summary>
    [Fact]
    public void CleanupFailurePreventsPublication()
    {
        using var api = new ProxyApi { FailFree = true };
        api.User = new() { Proxy = api.Text("proxy") };
        var error = Assert.Throws<AggregateException>(() => new WindowsProxySettingsReader(api, _ => null).Read(TestContext.Current.CancellationToken));
        Assert.Single(error.InnerExceptions);
        Assert.Single(api.Freed);
    }

    /// <summary>Environment failures remain explicit and release all already-returned settings.</summary>
    [Fact]
    public void EnvironmentFailureRetainsErrorAndReleasesStrings()
    {
        using var api = new ProxyApi();
        api.User = new() { AutoConfigUrl = api.Text("pac") };
        var failure = new IOException("Environment unavailable.");
        var error = Assert.Throws<IOException>(() => new WindowsProxySettingsReader(api, _ => throw failure).Read(TestContext.Current.CancellationToken));
        Assert.Same(failure, error);
        Assert.Single(api.Freed);
    }

    /// <summary>The reader does not retain proxy flags between independent observations.</summary>
    [Fact]
    public void RepeatedReadUsesCurrentSettingsWithoutChangingPreviousResult()
    {
        using var api = new ProxyApi();
        string? environment = null;
        var reader = new WindowsProxySettingsReader(api, _ => environment);
        var first = reader.Read(TestContext.Current.CancellationToken);
        api.User = new() { Proxy = api.Text("proxy") };
        environment = "configured";
        var second = reader.Read(TestContext.Current.CancellationToken);
        Assert.False(first.UserProxy);
        Assert.False(first.ProcessProxy);
        Assert.True(second.UserProxy);
        Assert.True(second.ProcessProxy);
    }

    /// <summary>Owns test-only UTF-16 allocations, keeping native cleanup observable without risking double-free.</summary>
    private sealed class ProxyApi : IProxyApi, IDisposable
    {
        private readonly List<nint> allocations = [];

        /// <summary>Gets or sets current-user native data.</summary>
        internal NativeUserProxy User { get; set; }

        /// <summary>Gets or sets legacy defaults.</summary>
        internal NativeDefaultProxy Default { get; set; } = new() { AccessType = 1 };

        /// <summary>Gets an optional user-read failure.</summary>
        internal uint UserError { get; init; }

        /// <summary>Gets an optional default-read failure.</summary>
        internal uint DefaultError { get; init; }

        /// <summary>Gets whether every attempted string release fails.</summary>
        internal bool FailFree { get; init; }

        /// <summary>Gets a controlled cancellation after the user read.</summary>
        internal Action? AfterUser { get; init; }

        /// <summary>Gets a controlled cancellation after the default read.</summary>
        internal Action? AfterDefault { get; init; }

        /// <summary>Gets a controlled cancellation during cleanup.</summary>
        internal Action? AfterFree { get; init; }

        /// <summary>Gets all attempted native releases.</summary>
        internal List<nint> Freed { get; } = [];

        /// <summary>Allocates a controlled UTF-16 string, with lifetime owned by this fixture.</summary>
        internal nint Text(string value)
        {
            var pointer = Marshal.StringToHGlobalUni(value);
            allocations.Add(pointer);
            return pointer;
        }

        /// <summary>Returns controlled user data and an optional failure.</summary>
        public uint ReadUser(out NativeUserProxy settings) { settings = User; AfterUser?.Invoke(); return UserError; }

        /// <summary>Returns controlled registry defaults.</summary>
        public uint ReadDefault(out NativeDefaultProxy settings) { settings = Default; AfterDefault?.Invoke(); return DefaultError; }

        /// <summary>Records cleanup without freeing fixture-owned memory prematurely.</summary>
        public uint Free(nint memory) { Freed.Add(memory); AfterFree?.Invoke(); return FailFree ? 5u : 0; }

        /// <summary>Releases only the fixture's unique allocations.</summary>
        public void Dispose() { foreach (var pointer in allocations) { Marshal.FreeHGlobal(pointer); } }
    }
}
