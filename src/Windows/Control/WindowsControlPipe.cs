using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace IPGuard.Windows.Control;

/// <summary>Creates one GUI-owned channel for a known helper process without elevation or network policy changes.</summary>
public sealed class WindowsControlPipe : IDisposable
{
    private const string Prefix = "IPGuard.Control.";
    private readonly object lifetime = new();
    private NamedPipeServerStream? server;
    private bool claimed;
    private bool disposed;

    /// <summary>Creates an unconnected listener; the static factory supplies its unique name.</summary>
    private WindowsControlPipe(string name, NamedPipeServerStream server)
    {
        Name = name;
        this.server = server;
    }

    /// <summary>Gets the unique local endpoint name to pass to the expected helper.</summary>
    public string Name { get; }

    /// <summary>Creates a fresh one-shot listener with a protected current-logon descriptor.</summary>
    public static WindowsControlPipe Create() => Create($"{Prefix}{Guid.NewGuid():N}");

    /// <summary>Creates a specified unique endpoint for collision tests without taking over existing objects.</summary>
    internal static WindowsControlPipe Create(string name)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows control IPC is required.");
        ValidateName(name);
        var security = ControlPipeSecurity.Current();
        var pipe = NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 4096, 4096, security.Create(), HandleInheritability.None);
        try
        {
            security.Validate(pipe.GetAccessControl().GetSecurityDescriptorBinaryForm());
            return new(name, pipe);
        }
        catch { pipe.Dispose(); throw; }
    }

    /// <summary>Accepts only the expected live process and transfers stream ownership after a bounded handshake.</summary>
    /// <remarks>The caller keeps the supplied Process alive and undisposed throughout authentication.</remarks>
    /// <exception cref="OperationCanceledException">The caller cancels or the connection/handshake deadline expires.</exception>
    public async Task<Stream> AcceptAsync(Process expectedClient, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expectedClient);
        using var deadline = Deadline(timeout, cancellationToken);
        ControlPipePeer.RequireLive(expectedClient);
        NamedPipeServerStream pipe;
        lock (lifetime)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (claimed) throw new InvalidOperationException("The control pipe accepts only one connection.");
            claimed = true;
            pipe = server!;
        }
        try
        {
            await pipe.WaitForConnectionAsync(deadline.Token).ConfigureAwait(false);
            ControlPipePeer.VerifyClient(pipe, expectedClient);
            await ControlPipeHandshake.ReadAsync(pipe, deadline.Token).ConfigureAwait(false);
            await ControlPipeHandshake.WriteAsync(pipe, deadline.Token).ConfigureAwait(false);
            ControlPipePeer.VerifyClient(pipe, expectedClient);
            deadline.Token.ThrowIfCancellationRequested();
            lock (lifetime)
            {
                ObjectDisposedException.ThrowIf(disposed, this);
                server = null;
                return pipe;
            }
        }
        catch { Dispose(); throw; }
    }

    /// <summary>Connects locally, validates the actual server descriptor and process, then transfers stream ownership.</summary>
    /// <remarks>The expected GUI token supplies the logon identity. This does not prove elevated rights or binary integrity.</remarks>
    /// <exception cref="OperationCanceledException">The caller cancels or the connection/handshake deadline expires.</exception>
    public static async Task<Stream> ConnectAsync(string name, Process expectedServer, TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows control IPC is required.");
        ValidateName(name);
        ArgumentNullException.ThrowIfNull(expectedServer);
        using var deadline = Deadline(timeout, cancellationToken);
        ControlPipePeer.RequireLive(expectedServer);
        var security = ControlPipeSecurity.ForServer(expectedServer);
        // Identification prevents an unexpected server from acting with the client's elevated credentials.
        var pipe = new NamedPipeClientStream(".", name, PipeAccessRights.ReadWrite, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification, HandleInheritability.None);
        try
        {
            await pipe.ConnectAsync(deadline.Token).ConfigureAwait(false);
            ControlPipePeer.VerifyServer(pipe, expectedServer);
            security.Validate(pipe.GetAccessControl().GetSecurityDescriptorBinaryForm());
            await ControlPipeHandshake.WriteAsync(pipe, deadline.Token).ConfigureAwait(false);
            await ControlPipeHandshake.ReadAsync(pipe, deadline.Token).ConfigureAwait(false);
            ControlPipePeer.VerifyServer(pipe, expectedServer);
            deadline.Token.ThrowIfCancellationRequested();
            return pipe;
        }
        catch { pipe.Dispose(); throw; }
    }

    /// <summary>Rejects paths, remote endpoints, and names outside the fixed generated format.</summary>
    internal static void ValidateName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (!name.StartsWith(Prefix, StringComparison.Ordinal) || !Guid.TryParseExact(name.AsSpan(Prefix.Length), "N", out _))
            throw new ArgumentException("A generated local control pipe name is required.", nameof(name));
    }

    /// <summary>Closes pending authentication; a successfully transferred stream belongs to its caller.</summary>
    public void Dispose()
    {
        NamedPipeServerStream? pending;
        lock (lifetime)
        {
            disposed = true;
            pending = server;
            server = null;
        }
        pending?.Dispose();
    }

    /// <summary>Bounds connection and handshake together; cancellation never turns into a valid stream.</summary>
    private static CancellationTokenSource Deadline(TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (timeout < TimeSpan.FromMilliseconds(1) || timeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(timeout), "The handshake timeout must be between 1 ms and 1 minute.");
        cancellationToken.ThrowIfCancellationRequested();
        var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        source.CancelAfter(timeout);
        return source;
    }
}
