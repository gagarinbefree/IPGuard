using IPGuard.Application.Protection;
using System.Diagnostics;
using IPGuard.Infrastructure.Control;
using IPGuard.Windows.Control;
using IPGuard.Windows.Hosting;

namespace IPGuard.Desktop.Hosting;

/// <summary>Composes trusted installation, explicit UAC startup, process-bound IPC, and the shared command client.</summary>
public static class WindowsProtectionSession
{
    /// <summary>Runs all startup off the caller thread and owns cleanup after cancelled or failed consent/authentication.</summary>
    public static Task<IProtectionSession> ConnectAsync(CancellationToken cancellationToken)
        => Task.Run(() => ConnectCoreAsync(cancellationToken));

    /// <summary>Keeps ownership of a late-started process until authentication or complete startup cleanup.</summary>
    private static async Task<IProtectionSession> ConnectCoreAsync(CancellationToken token)
    {
        ProtectedHelperInstallation? installation = null;
        Process? helper = null;
        Stream? stream = null;
        try
        {
            token.ThrowIfCancellationRequested();
            installation = ProtectedHelperInstallation.OpenCurrent();
            using var listener = WindowsControlPipe.Create();
            token.ThrowIfCancellationRequested();
            // Shell consent cannot be interrupted by a CancellationToken. Recheck after it returns, without abandoning a process.
            helper = WindowsHelperLauncher.Start(installation, listener.Name);
            token.ThrowIfCancellationRequested();
            stream = await listener.AcceptAsync(helper, TimeSpan.FromSeconds(30), token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            return new Connection(new ProtectionControlClient(stream, TimeSpan.FromSeconds(10)), helper, installation);
        }
        catch (Exception original)
        {
            var errors = new List<Exception> { original };
            try { if (stream is not null) await stream.DisposeAsync().ConfigureAwait(false); } catch (Exception error) { errors.Add(error); }
            try { helper?.Dispose(); } catch (Exception error) { errors.Add(error); }
            try { installation?.Dispose(); } catch (Exception error) { errors.Add(error); }
            if (errors.Count > 1) throw new AggregateException("Helper startup and cleanup failed.", errors);
            throw;
        }
    }

    /// <summary>Retains the command client, process handle and installation pins for an authenticated session.</summary>
    private sealed class Connection : IProtectionSession
    {
        private readonly ProtectionControlClient client;
        private readonly Process helper;
        private readonly ProtectedHelperInstallation installation;
        private readonly object gate = new();
        private Task? closing;
        /// <summary>Takes ownership only after the expected helper authenticated successfully.</summary>
        internal Connection(ProtectionControlClient client, Process helper, ProtectedHelperInstallation installation)
        { this.client = client; this.helper = helper; this.installation = installation; }
        /// <summary>Uses the shared bounded protocol without adding native operations to the GUI.</summary>
        public Task<ProtectionControlReport> SendAsync(ProtectionCommand command, CancellationToken token)
            => client.SendAsync(command, token);
        /// <summary>Closes transport and retained handles once, without killing the helper or deleting rules.</summary>
        public ValueTask DisposeAsync()
        {
            lock (gate) { closing ??= Task.Run(CloseAsync); return new(closing); }
        }
        /// <summary>Attempts every release even when transport cleanup fails.</summary>
        private async Task CloseAsync()
        {
            var errors = new List<Exception>();
            try { await client.DisposeAsync().ConfigureAwait(false); } catch (Exception error) { errors.Add(error); }
            try { helper.Dispose(); } catch (Exception error) { errors.Add(error); }
            try { installation.Dispose(); } catch (Exception error) { errors.Add(error); }
            if (errors.Count > 0) throw new AggregateException("Helper connection cleanup failed.", errors);
        }
    }
}
