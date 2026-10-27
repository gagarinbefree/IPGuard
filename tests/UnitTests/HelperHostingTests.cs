using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Text;
using IPGuard.Windows.Hosting;
using Xunit;

namespace UnitTests;

/// <summary>Checks privileged inputs and installation trust without starting processes or opening WFP.</summary>
[SupportedOSPlatform("windows")]
public sealed class HelperHostingTests
{
    private const string Pipe = "IPGuard.Control.0123456789abcdef0123456789abcdef";
    private const string Config = """{"version":1,"powerShellPaths":["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","C:\\Program Files\\PowerShell\\7\\pwsh.exe"],"checkIntervalSeconds":30}""";

    /// <summary>Only a complete local helper request produces an accepted identity.</summary>
    [Fact]
    public void ValidRequestPreservesPeer()
    {
        var request = HelperRequest.Parse(["--helper", "--pipe", Pipe, "--parent", "42"]);
        Assert.Equal(Pipe, request.PipeName);
        Assert.Equal(42, request.ParentId);
    }

    /// <summary>Malformed modes and identifiers never become a privileged request.</summary>
    [Theory]
    [InlineData("missing")]
    [InlineData("extra")]
    [InlineData("mode")]
    [InlineData("pipe")]
    [InlineData("remote")]
    [InlineData("parent")]
    [InlineData("zero")]
    [InlineData("negative")]
    [InlineData("overflow")]
    [InlineData("space")]
    public void InvalidRequestIsRejected(string change)
    {
        string[] args = ["--helper", "--pipe", Pipe, "--parent", "42"];
        args = change switch
        {
            "missing" => args[..4],
            "extra" => [.. args, "--allow"],
            "mode" => ["--allow", .. args[1..]],
            "pipe" => [args[0], args[1], "other", args[3], args[4]],
            "remote" => [args[0], args[1], @"\\server\pipe\" + Pipe, args[3], args[4]],
            "parent" => [args[0], args[1], args[2], "--scope", args[4]],
            "zero" => [.. args[..4], "0"],
            "negative" => [.. args[..4], "-1"],
            "overflow" => [.. args[..4], "2147483648"],
            "space" => [.. args[..4], " 42"],
            _ => args
        };
        Assert.Throws<ArgumentException>(() => HelperRequest.Parse(args));
    }

    /// <summary>Explicit local PowerShell paths and cadence survive strict deserialization.</summary>
    [Fact]
    public void ConfigurationPreservesScope()
    {
        var config = Parse(Config);
        Assert.Equal(2, config.PowerShellPaths.Count);
        Assert.Equal(TimeSpan.FromSeconds(30), config.CheckInterval);
        Assert.Equal(@"C:\Program Files\PowerShell\7\pwsh.exe", config.PowerShellPaths[1]);
        Assert.False(config.PowerShellPaths is string[]);
    }

    /// <summary>Incomplete, unbounded, or contradictory configuration is rejected before native policy work.</summary>
    [Theory]
    [InlineData("{}")]
    [InlineData("null")]
    [InlineData("{\"version\":1,\"powerShellPaths\":[],\"checkIntervalSeconds\":30}")]
    [InlineData("{\"version\":1,\"powerShellPaths\":null,\"checkIntervalSeconds\":30}")]
    [InlineData("{\"version\":1,\"powerShellPaths\":[null],\"checkIntervalSeconds\":30}")]
    [InlineData("{\"version\":1,\"powerShellPaths\":[\"pwsh.exe\"],\"checkIntervalSeconds\":30}")]
    [InlineData("{\"version\":1,\"powerShellPaths\":[\"C:\\\\tools\\\\curl.exe\"],\"checkIntervalSeconds\":30}")]
    public void InvalidConfigurationIsRejected(string json)
        => Assert.Throws<InvalidDataException>(() => Parse(json));

    /// <summary>Strict schema rejects hidden extensions, duplicate keys, versions, remote scopes, and unsafe timers.</summary>
    [Theory]
    [InlineData("version", "2")]
    [InlineData("checkIntervalSeconds", "0")]
    [InlineData("checkIntervalSeconds", "3601")]
    [InlineData("checkIntervalSeconds", "1.5")]
    [InlineData("extra", "true")]
    [InlineData("duplicate", "1")]
    [InlineData("remote", "1")]
    [InlineData("device", "1")]
    public void UnsupportedConfigurationIsRejected(string field, string value)
    {
        string json = field switch
        {
            "extra" => Config[..^1] + ",\"allow\":true}",
            "duplicate" => Config[..^1] + ",\"version\":1}",
            "remote" => Config.Replace("C:\\\\Windows", "\\\\\\\\server\\\\Windows", StringComparison.Ordinal),
            "device" => Config.Replace("C:\\\\Windows", "\\\\\\\\?\\\\C:\\\\Windows", StringComparison.Ordinal),
            _ => Config.Replace(field == "version" ? "\"version\":1" : "\"checkIntervalSeconds\":30", $"\"{field}\":{value}", StringComparison.Ordinal)
        };
        Assert.Throws<InvalidDataException>(() => Parse(json));
    }

    /// <summary>Configuration size is bounded before decoding or allocation by the JSON parser.</summary>
    [Fact]
    public void OversizedConfigurationIsRejected()
        => Assert.Throws<InvalidDataException>(() => HelperConfiguration.Parse(new byte[16385]));

    /// <summary>Trusted ownership and read-only Users access support files and installation ancestors.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReadOnlyInstallationIsAccepted(bool ancestor)
        => InstallationSecurity.Validate(Descriptor("O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)"), ancestor);

    /// <summary>Writable owners, null ACLs, and untrusted mutation grants cannot authorize elevated input.</summary>
    [Theory]
    [InlineData("O:BUD:P(A;;FA;;;BA)(A;;FR;;;BU)")]
    [InlineData("O:BAD:NO_ACCESS_CONTROL")]
    [InlineData("O:BAD:P(A;;FW;;;BU)")]
    [InlineData("O:BAD:P(A;;WD;;;BU)")]
    [InlineData("O:BAD:P(A;;WO;;;BU)")]
    [InlineData("O:BAD:P(A;;SD;;;BU)")]
    [InlineData("O:BAD:P(A;;0x40;;;BU)")]
    public void UnsafeInstallationIsRejected(string sddl)
        => Assert.Throws<UnauthorizedAccessException>(() => InstallationSecurity.Validate(Descriptor(sddl), false));

    /// <summary>An ancestor may allow new children while existing protected children cannot be replaced.</summary>
    [Fact]
    public void AncestorCreationIsDistinctFromReplacement()
    {
        var descriptor = Descriptor("O:BAD:P(A;;FA;;;BA)(A;;0x6;;;BU)(A;OIIO;FA;;;CO)");
        InstallationSecurity.Validate(descriptor, true);
        Assert.Throws<UnauthorizedAccessException>(() => InstallationSecurity.Validate(descriptor, false));
        Assert.Throws<UnauthorizedAccessException>(() => InstallationSecurity.Validate(Descriptor("O:BAD:P(A;;0x40;;;BU)"), true));
    }

    /// <summary>UAC uses the exact installed binary and fixed argument tokens with no shell text interpolation.</summary>
    [Fact]
    public void LauncherUsesRunasAndFixedArguments()
    {
        var start = WindowsHelperLauncher.CreateStartInfo(@"C:\Program Files\IPGuard\IPGuard.exe", Pipe, 42);
        Assert.Equal(@"C:\Program Files\IPGuard\IPGuard.exe", start.FileName);
        Assert.Equal("runas", start.Verb);
        Assert.True(start.UseShellExecute);
        Assert.Equal(System.Diagnostics.ProcessWindowStyle.Hidden, start.WindowStyle);
        Assert.Equal(["--helper", "--pipe", Pipe, "--parent", "42"], start.ArgumentList);
        Assert.Empty(start.Arguments);
        Assert.False(start.RedirectStandardOutput);
        Assert.False(start.RedirectStandardError);
    }

    /// <summary>Object metadata cannot hide reparse traversal, directory substitution, or hard-linked policy input.</summary>
    [Theory]
    [InlineData(FileAttributes.ReparsePoint, 1u, false)]
    [InlineData(FileAttributes.Directory, 1u, false)]
    [InlineData(FileAttributes.Normal, 1u, true)]
    [InlineData(FileAttributes.Normal, 2u, false)]
    [InlineData(FileAttributes.Normal, 0u, false)]
    public void UnsafeObjectMetadataIsRejected(FileAttributes attributes, uint links, bool directory)
        => Assert.Throws<UnauthorizedAccessException>(() => ProtectedInstallationFile.ValidateMetadata(attributes, links, directory));

    /// <summary>Ordinary single-link files and genuine directories can proceed to descriptor validation.</summary>
    [Theory]
    [InlineData(FileAttributes.Normal, 1u, false)]
    [InlineData(FileAttributes.Directory, 1u, true)]
    public void OrdinaryObjectMetadataIsAccepted(FileAttributes attributes, uint links, bool directory)
        => ProtectedInstallationFile.ValidateMetadata(attributes, links, directory);

    /// <summary>A matching folder deployment is required before the launcher can request elevation.</summary>
    [Fact]
    public void FolderDeploymentHasFixedIdentity()
        => Assert.Equal(@"C:\Program Files\IPGuard\Desktop.exe", ProtectedHelperInstallation.ValidateLocation(
            @"C:\Program Files\IPGuard\Desktop.exe", @"C:\Program Files\IPGuard\Desktop.dll", @"C:\Program Files"));

    /// <summary>Unknown and single-file entry locations are refused before any file or policy access.</summary>
    [Theory]
    [InlineData(null, null)]
    [InlineData("C:\\Program Files\\IPGuard\\Desktop.exe", "")]
    [InlineData("C:\\Downloads\\Desktop.exe", "C:\\Downloads\\Desktop.dll")]
    [InlineData("C:\\Program Files\\IPGuard\\other.exe", "C:\\Program Files\\IPGuard\\Desktop.dll")]
    [InlineData("C:\\Program Files\\IPGuard\\Desktop.exe", "C:\\Downloads\\Desktop.dll")]
    public void UnsupportedDeploymentIsRejected(string? executable, string? entry)
        => Assert.Throws<UnauthorizedAccessException>(() => ProtectedHelperInstallation.ValidateLocation(executable, entry, @"C:\Program Files"));

    /// <summary>Encodes controlled test input without reading production configuration.</summary>
    private static HelperConfiguration Parse(string json) => HelperConfiguration.Parse(Encoding.UTF8.GetBytes(json));
    /// <summary>Creates a synthetic security descriptor without modifying file system security.</summary>
    private static byte[] Descriptor(string sddl)
    {
        var raw = new RawSecurityDescriptor(sddl);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        return bytes;
    }
}
