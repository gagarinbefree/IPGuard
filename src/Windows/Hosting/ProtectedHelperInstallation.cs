using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace IPGuard.Windows.Hosting;

/// <summary>Pins the trusted installed folder and its configuration for one helper session.</summary>
public sealed class ProtectedHelperInstallation : IDisposable
{
    private readonly Dictionary<string, SafeFileHandle> handles = new(StringComparer.OrdinalIgnoreCase);
    private bool disposed;

    /// <summary>Creates a pending installation; failure while pinning releases every already opened handle.</summary>
    private ProtectedHelperInstallation(string executable) => ExecutablePath = executable;
    /// <summary>Gets the fixed executable path; callers must retain this installation throughout helper startup.</summary>
    public string ExecutablePath { get; }

    /// <summary>Opens the current non-bundled executable only in the fixed Program Files installation.</summary>
    [UnconditionalSuppressMessage("SingleFile", "IL3000", Justification = "An empty entry assembly location deliberately rejects single-file elevation.")]
    public static ProtectedHelperInstallation OpenCurrent()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows installation security is required.");
        var executable = ValidateLocation(Environment.ProcessPath, Assembly.GetEntryAssembly()?.Location,
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        var installation = new ProtectedHelperInstallation(executable);
        try
        {
            string directory = Path.GetDirectoryName(executable)!;
            var ancestors = new Stack<string>();
            for (var parent = Directory.GetParent(directory); parent is not null; parent = parent.Parent)
                ancestors.Push(parent.FullName);
            foreach (string ancestor in ancestors) installation.Pin(ancestor, true, true);
            installation.PinTree(directory);
            return installation;
        }
        catch { installation.Dispose(); throw; }
    }
    /// <summary>Rejects portable, bundled, remote, renamed, or unrelated managed entry locations.</summary>
    internal static string ValidateLocation(string? executable, string? managedEntry, string programFiles)
    {
        if (string.IsNullOrWhiteSpace(programFiles) || !Path.IsPathFullyQualified(programFiles) ||
            programFiles.StartsWith("\\\\", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("A local Program Files installation is required.");
        string directory = Path.Combine(programFiles, "IPGuard");
        string expected = Path.Combine(directory, "Desktop.exe");
        if (!string.Equals(executable, expected, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(managedEntry, Path.Combine(directory, "Desktop.dll"), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Helper hosting requires the fixed non-bundled Program Files installation.");
        return expected;
    }

    /// <summary>Reads the bounded helper file from the same retained handle whose owner and DACL were validated.</summary>
    public HelperConfiguration ReadConfiguration()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        string path = Path.Combine(Path.GetDirectoryName(ExecutablePath)!, "helper.json");
        if (!handles.TryGetValue(path, out var handle)) throw new FileNotFoundException("The protected helper configuration is missing.");
        var bytes = new byte[HelperConfiguration.MaximumBytes + 1];
        int count = 0;
        while (count < bytes.Length)
        {
            int read = RandomAccess.Read(handle, bytes.AsSpan(count), count);
            if (read == 0) break;
            count += read;
        }
        return HelperConfiguration.Parse(bytes.AsSpan(0, count));
    }

    /// <summary>Starts only the pinned current installation; this synchronous UAC operation must run off the UI thread.</summary>
    internal Process StartHelper(string pipeName)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return Process.Start(WindowsHelperLauncher.CreateStartInfo(ExecutablePath, pipeName, Environment.ProcessId))
            ?? throw new InvalidOperationException("Windows did not return the elevated helper process.");
    }

    /// <summary>Validates every deployed dependency before it can be used by a later elevated process.</summary>
    [SupportedOSPlatform("windows")]
    private void PinTree(string directory)
    {
        Pin(directory, true, false);
        foreach (string path in Directory.EnumerateFileSystemEntries(directory))
        {
            // The parent is already protected and pinned. Reparse validation still happens on each opened child.
            if (Directory.Exists(path)) PinTree(path);
            else Pin(path, false, false);
        }
    }

    /// <summary>Retains a checked object, rejecting oversized deployments without partial trust or ACL repair.</summary>
    [SupportedOSPlatform("windows")]
    private void Pin(string path, bool directory, bool ancestor)
    {
        if (handles.Count >= 512) throw new InvalidDataException("The helper installation exceeds the object limit.");
        var handle = ProtectedInstallationFile.Open(path, directory);
        try
        {
            InstallationSecurity.Validate(ProtectedInstallationFile.ReadSecurity(handle), ancestor);
            handles.Add(path, handle);
        }
        catch { handle.Dispose(); throw; }
    }

    /// <summary>Releases the pinned installation objects.</summary>
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        foreach (var handle in handles.Values.Reverse()) handle.Dispose();
        handles.Clear();
    }
}
