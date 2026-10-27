using System.Diagnostics;
using System.Globalization;

namespace IPGuard.Windows.Hosting;

/// <summary>Builds the fixed helper invocation used by the installed application.</summary>
public static class WindowsHelperLauncher
{
    /// <summary>Requests consent for the pinned folder deployment; cancellation or launch errors propagate to the caller.</summary>
    /// <remarks>Call on a worker and retain the installation and returned process through pipe authentication. No UAC is requested automatically.</remarks>
    public static Process Start(ProtectedHelperInstallation installation, string pipeName)
    {
        ArgumentNullException.ThrowIfNull(installation);
        _ = installation.ReadConfiguration();
        return installation.StartHelper(pipeName);
    }

    /// <summary>Creates a hidden shell-elevated invocation with individually escaped arguments.</summary>
    internal static ProcessStartInfo CreateStartInfo(string executable, string pipeName, int parentId)
    {
        string[] args = ["--helper", "--pipe", pipeName, "--parent", parentId.ToString(CultureInfo.InvariantCulture)];
        _ = HelperRequest.Parse(args);
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = Path.GetDirectoryName(executable)!
        };
        foreach (var argument in args) start.ArgumentList.Add(argument);
        return start;
    }
}
