using System.Diagnostics;
using IPGuard.Application.Network;
using IPGuard.Application.Protection;
using IPGuard.Infrastructure.Control;
using IPGuard.Windows.Control;
using IPGuard.Windows.Filtering;
using IPGuard.Windows.Hosting;
using IPGuard.Windows.Network;

namespace IPGuard.Desktop;

/// <summary>Runs the explicitly requested block-only helper without initializing Avalonia.</summary>
public static class HelperEntryPoint
{
    /// <summary>Returns a nonzero diagnostic exit code for invalid or untrusted startup, with no automatic UAC.</summary>
    public static async Task<int> RunAsync(string[] args)
    {
        HelperRequest request;
        try { request = HelperRequest.Parse(args); }
        catch (ArgumentException) { return 2; }

        ProtectedHelperInstallation installation;
        try { installation = ProtectedHelperInstallation.OpenCurrent(); }
        catch (Exception) { return 3; }
        using (installation)
        {
            try
            {
                var configuration = installation.ReadConfiguration();
                using var parent = Process.GetProcessById(request.ParentId);
                // Retain the original process before reading identity or waiting for the kernel-bound pipe.
                _ = parent.Handle;
                if (parent.HasExited || parent.Id == Environment.ProcessId ||
                    !string.Equals(parent.MainModule?.FileName, installation.ExecutablePath, StringComparison.OrdinalIgnoreCase))
                    throw new UnauthorizedAccessException("The expected GUI must use the same installed executable.");
                return await RunOwnedAsync(request, configuration, parent).ConfigureAwait(false);
            }
            catch (Exception) { return 1; }
        }
    }

    /// <summary>Owns all native-shaped resources and preserves blocks before every normal startup or session exit.</summary>
    private static async Task<int> RunOwnedAsync(HelperRequest request, HelperConfiguration configuration, Process parent)
    {
        var backend = new WindowsBlockPolicy(configuration.PowerShellPaths);
        var owner = await WindowsPolicyOwner.TryAcquireAsync(CancellationToken.None).ConfigureAwait(false);
        if (owner is null) return 4;
        WindowsNetworkMonitor? network = null;
        NetworkDiagnosticsMonitor? diagnostics = null;
        ProtectionRuntime? runtime = null;
        try
        {
            network = new WindowsNetworkMonitor();
            diagnostics = new NetworkDiagnosticsMonitor(new NetworkDiagnosticsCollector(new WindowsRoutingTableReader(),
                new WindowsProxySettingsReader(), new WindowsRemoteAccessReader(), network, configuration.CheckInterval),
                configuration.CheckInterval);
            var ownedNetwork = network;
            var ownedDiagnostics = diagnostics;
            runtime = new ProtectionRuntime(backend, owner, diagnostics, () => CloseDiagnosticsAsync(ownedDiagnostics, ownedNetwork));
            var result = await ProtectionControlServer.ConnectAndRunAsync(token => WindowsControlPipe.ConnectAsync(
                request.PipeName, parent, TimeSpan.FromSeconds(30), token), runtime, TimeSpan.FromSeconds(30), CancellationToken.None)
                .ConfigureAwait(false);
            return result.Error is null ? 0 : 1;
        }
        finally
        {
            if (runtime is not null) await runtime.StopAsync(CancellationToken.None).ConfigureAwait(false);
            else
            {
                // Diagnostic construction can fail before the shared runtime takes ownership. Keep the baseline then too.
                try { await backend.EnsureAsync(CancellationToken.None).ConfigureAwait(false); }
                finally
                {
                    try { await CloseDiagnosticsAsync(diagnostics, network).ConfigureAwait(false); }
                    finally { await owner.DisposeAsync().ConfigureAwait(false); }
                }
            }
        }
    }

    /// <summary>Stops both real readers and drains native work before the runtime releases policy ownership.</summary>
    private static async ValueTask CloseDiagnosticsAsync(NetworkDiagnosticsMonitor? diagnostics, WindowsNetworkMonitor? network)
    {
        var errors = new List<Exception>();
        try { diagnostics?.Dispose(); } catch (Exception error) { errors.Add(error); }
        try { network?.Dispose(); } catch (Exception error) { errors.Add(error); }
        try { if (diagnostics is not null) await diagnostics.Completion.ConfigureAwait(false); } catch (Exception error) { errors.Add(error); }
        try { if (network is not null) await network.Completion.ConfigureAwait(false); } catch (Exception error) { errors.Add(error); }
        if (errors.Count > 0) throw new AggregateException("Helper diagnostic shutdown failed.", errors);
    }
}
