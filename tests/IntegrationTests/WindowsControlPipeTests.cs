using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using IPGuard.Windows.Control;
using Xunit;

namespace IntegrationTests;

/// <summary>Checks unique local IPC endpoints and real peer verification without elevation or network policy.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsControlPipeTests
{
    /// <summary>Authenticated streams carry duplex data and remain owned by callers after listener disposal.</summary>
    [Fact]
    public async Task ValidPeersExchangeData()
    {
        using var deadline = Deadline();
        using var peer = Process.GetCurrentProcess();
        using var listener = WindowsControlPipe.Create();
        var accepting = listener.AcceptAsync(peer, TimeSpan.FromSeconds(10), deadline.Token);
        await using var client = await WindowsControlPipe.ConnectAsync(listener.Name, peer, TimeSpan.FromSeconds(10), deadline.Token);
        await using var server = await accepting;
        listener.Dispose();
        await client.WriteAsync(new byte[] { 42 }, deadline.Token);
        var data = new byte[1];
        await server.ReadExactlyAsync(data, deadline.Token);
        Assert.Equal(42, data[0]);
        var nativeServer = Assert.IsType<NamedPipeServerStream>(server);
        nativeServer.RunAsClient(() =>
        {
            using var identity = WindowsIdentity.GetCurrent();
            Assert.Equal(TokenImpersonationLevel.Identification, identity.ImpersonationLevel);
        });
        await server.WriteAsync(new byte[] { 43 }, deadline.Token);
        await client.ReadExactlyAsync(data, deadline.Token);
        Assert.Equal(43, data[0]);
        await client.DisposeAsync();
        Assert.Equal(0, await server.ReadAsync(data, deadline.Token));
    }

    /// <summary>The first-instance flag rejects a colliding listener without closing the legitimate endpoint.</summary>
    [Fact]
    public void ExistingEndpointIsNotTakenOver()
    {
        using var listener = WindowsControlPipe.Create();
        Assert.Throws<UnauthorizedAccessException>(() => WindowsControlPipe.Create(listener.Name));
    }

    /// <summary>An already exited expected peer is rejected before any wait for a server that cannot be trusted.</summary>
    [Fact]
    public async Task ExitedPeerCannotStartConnection()
    {
        using var deadline = Deadline();
        using var child = StartChild("exit 0");
        await child.WaitForExitAsync(deadline.Token);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => WindowsControlPipe.ConnectAsync(
            $"IPGuard.Control.{Guid.NewGuid():N}", child, TimeSpan.FromMilliseconds(50), deadline.Token));
    }

    /// <summary>A stalled valid process cannot retain an unauthenticated listener beyond its deadline.</summary>
    [Fact]
    public async Task PartialHandshakeTimesOutAndRetiresListener()
    {
        using var deadline = Deadline();
        using var peer = Process.GetCurrentProcess();
        using var listener = WindowsControlPipe.Create();
        var accepting = listener.AcceptAsync(peer, TimeSpan.FromSeconds(1), deadline.Token);
        using var client = RawClient(listener.Name);
        await client.ConnectAsync(deadline.Token);
        await client.WriteAsync(new byte[] { (byte)'I' }, deadline.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => accepting);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => listener.AcceptAsync(peer, TimeSpan.FromSeconds(1), deadline.Token));
    }

    /// <summary>Cancelling a pending connection closes its listener and does not silently restart authentication.</summary>
    [Fact]
    public async Task CancelledAcceptIsTerminal()
    {
        using var deadline = Deadline();
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        using var peer = Process.GetCurrentProcess();
        using var listener = WindowsControlPipe.Create();
        var accepting = listener.AcceptAsync(peer, TimeSpan.FromSeconds(10), caller.Token);
        caller.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => accepting);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => listener.AcceptAsync(peer, TimeSpan.FromSeconds(1), deadline.Token));
    }

    /// <summary>The client rejects an unsafe real server descriptor before sending any protocol bytes.</summary>
    [Fact]
    public async Task UnsafeServerReceivesNoHandshake()
    {
        using var deadline = Deadline();
        using var peer = Process.GetCurrentProcess();
        var name = $"IPGuard.Control.{Guid.NewGuid():N}";
        using var raw = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var connected = raw.WaitForConnectionAsync(deadline.Token);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => WindowsControlPipe.ConnectAsync(name, peer, TimeSpan.FromSeconds(10), deadline.Token));
        await connected;
        Assert.Equal(0, await raw.ReadAsync(new byte[1], deadline.Token));
    }

    /// <summary>The listener rejects a complete unsupported marker instead of exposing an application stream.</summary>
    [Fact]
    public async Task UnsupportedPeerIsClosed()
    {
        using var deadline = Deadline();
        using var peer = Process.GetCurrentProcess();
        using var listener = WindowsControlPipe.Create();
        var accepting = listener.AcceptAsync(peer, TimeSpan.FromSeconds(10), deadline.Token);
        using var client = RawClient(listener.Name);
        await client.ConnectAsync(deadline.Token);
        await client.WriteAsync(Encoding.ASCII.GetBytes("IPGuard.Control/2\n"), deadline.Token);
        await Assert.ThrowsAsync<InvalidDataException>(() => accepting);
    }

    /// <summary>Both channel roles reject an unexpected live process even within the permitted logon session.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WrongProcessIsRejected(bool wrongServer)
    {
        using var deadline = Deadline();
        using var peer = Process.GetCurrentProcess();
        using var other = StartChild("[Console]::ReadLine() | Out-Null");
        try
        {
            using var listener = WindowsControlPipe.Create();
            var accepting = listener.AcceptAsync(wrongServer ? peer : other, TimeSpan.FromSeconds(10), deadline.Token);
            var connecting = WindowsControlPipe.ConnectAsync(listener.Name, wrongServer ? other : peer, TimeSpan.FromSeconds(10), deadline.Token);
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => wrongServer ? connecting : accepting);
            await Assert.ThrowsAnyAsync<IOException>(() => wrongServer ? accepting : connecting);
        }
        finally { await EndChildAsync(other); }
    }

    /// <summary>A real child process passes server-side PID verification and uses the negotiated stream.</summary>
    [Fact]
    public async Task ExpectedChildCanConnect()
    {
        using var deadline = Deadline();
        using var listener = WindowsControlPipe.Create();
        var script = "$ErrorActionPreference='Stop'; " +
            $"$p=[IO.Pipes.NamedPipeClientStream]::new('.','{listener.Name}',[IO.Pipes.PipeAccessRights]::ReadWrite," +
            "[IO.Pipes.PipeOptions]::Asynchronous,[Security.Principal.TokenImpersonationLevel]::Identification,[IO.HandleInheritability]::None); " +
            "$p.Connect(10000); $hello=[Text.Encoding]::ASCII.GetBytes(\"IPGuard.Control/1`n\"); " +
            "$p.Write($hello,0,$hello.Length); " +
            "foreach ($b in $hello) {if ($p.ReadByte() -ne $b) {exit 2}}; " +
            "$p.WriteByte(42); if ($p.ReadByte() -ne 43) {exit 3}; $p.Dispose(); exit 0";
        using var child = StartChild(script);
        var error = child.StandardError.ReadToEndAsync(deadline.Token);
        try
        {
            await using var stream = await listener.AcceptAsync(child, TimeSpan.FromSeconds(10), deadline.Token);
            var data = new byte[1];
            await stream.ReadExactlyAsync(data, deadline.Token);
            Assert.Equal(42, data[0]);
            await stream.WriteAsync(new byte[] { 43 }, deadline.Token);
            await child.WaitForExitAsync(deadline.Token);
            Assert.Equal(0, child.ExitCode);
            Assert.Equal(string.Empty, await error);
        }
        finally { await EndChildAsync(child); }
    }

    /// <summary>Bounds every native integration test independently of the handshake's own deadline.</summary>
    private static CancellationTokenSource Deadline()
    {
        var source = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        source.CancelAfter(TimeSpan.FromSeconds(20));
        return source;
    }

    /// <summary>Connects with individual data rights and identification-only credentials.</summary>
    private static NamedPipeClientStream RawClient(string name)
        => new(".", name, PipeAccessRights.ReadWrite, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification, HandleInheritability.None);

    /// <summary>Starts a hidden bounded test peer; scripts only use unique test pipes or wait for parent cleanup.</summary>
    private static Process StartChild(string script)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-EncodedCommand");
        start.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
        return Process.Start(start) ?? throw new InvalidOperationException("The IPC test child could not be started.");
    }

    /// <summary>Terminates only the test-owned peer and observes its exit during failure cleanup.</summary>
    private static async Task EndChildAsync(Process child)
    {
        if (!child.HasExited)
        {
            child.Kill(entireProcessTree: true);
            await child.WaitForExitAsync(TestContext.Current.CancellationToken);
        }
    }
}
