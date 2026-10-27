using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using IPGuard.Windows.Filtering;
using Xunit;

namespace IntegrationTests;

/// <summary>Checks real kernel ownership using unique test names, without production mutexes or network policy.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsPolicyOwnershipTests
{
    /// <summary>Another process excludes the owner; normal exit and process death have distinct recovery evidence.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProcessOwnershipAndRecovery(bool crash)
    {
        var name = $@"Global\IPGuard.Tests.Owner.{Guid.NewGuid():N}";
        using var retained = new Mutex(false, name);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        using var child = StartOwner(name, crash);
        var errors = child.StandardError.ReadToEndAsync(deadline.Token);
        try
        {
            Assert.Equal("owned", await child.StandardOutput.ReadLineAsync(deadline.Token));
            Assert.Null(await WindowsPolicyOwner.TryAcquireAsync(() => new TestMutex(name), deadline.Token));
            await child.StandardInput.WriteLineAsync("exit".AsMemory(), deadline.Token);
            await child.WaitForExitAsync(deadline.Token);
            Assert.Equal(crash ? 17 : 0, child.ExitCode);
            Assert.Equal(string.Empty, await errors);

            var owner = Assert.IsType<WindowsPolicyOwner>(await WindowsPolicyOwner.TryAcquireAsync(() => new TestMutex(name), deadline.Token));
            await using (owner)
            {
                Assert.Equal(crash, owner.WasAbandoned);
                Assert.False(owner.Lost.IsCancellationRequested);
            }
            var next = Assert.IsType<WindowsPolicyOwner>(await WindowsPolicyOwner.TryAcquireAsync(() => new TestMutex(name), deadline.Token));
            await using (next) Assert.False(next.WasAbandoned);
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill(entireProcessTree: true);
                await child.WaitForExitAsync(TestContext.Current.CancellationToken);
            }
        }
    }

    /// <summary>A pre-existing unsafe descriptor is rejected without changing its owner or DACL.</summary>
    [Fact]
    public void UnsafeExistingKernelObjectIsNotRepaired()
    {
        var name = $@"Global\IPGuard.Tests.Owner.{Guid.NewGuid():N}";
        using var mutex = new Mutex(false, name);
        var before = mutex.GetAccessControl().GetSecurityDescriptorBinaryForm();
        Assert.Throws<UnauthorizedAccessException>(() => WindowsPolicyMutex.Open(name));
        Assert.Equal(before, mutex.GetAccessControl().GetSecurityDescriptorBinaryForm());
    }

    /// <summary>Protected creation succeeds only with a token allowed to assign and use the Administrators owner.</summary>
    [Fact]
    public void ProtectedCreationRespectsCurrentToken()
    {
        var name = $@"Global\IPGuard.Tests.Owner.{Guid.NewGuid():N}";
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            // MutexAcl preserves ERROR_INVALID_OWNER when a standard token cannot assign Administrators.
            var error = Assert.Throws<IOException>(() => WindowsPolicyMutex.Open(name));
            Assert.Equal(unchecked((int)0x8007051B), error.HResult);
            return;
        }
        using var mutex = WindowsPolicyMutex.Open(name);
        Assert.False(mutex.TryAcquire());
        mutex.Release();
    }

    /// <summary>Starts a hidden child that holds only the unique test mutex until its parent requests exit.</summary>
    private static Process StartOwner(string name, bool crash)
    {
        // The generated name contains only the fixed prefix and a hexadecimal GUID.
        var script = $"$ErrorActionPreference='Stop'; $m=[Threading.Mutex]::new($false,'{name}'); " +
            "if (!$m.WaitOne(10000)) {exit 2}; [Console]::WriteLine('owned'); [Console]::Out.Flush(); " +
            "[Console]::ReadLine() | Out-Null; " +
            (crash ? "[Environment]::Exit(17)" : "$m.ReleaseMutex(); $m.Dispose(); exit 0");
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
        return Process.Start(start) ?? throw new InvalidOperationException("The test mutex owner could not be started.");
    }

    /// <summary>Uses the current user's test object permissions while exercising the real thread-affine mutex API.</summary>
    private sealed class TestMutex : IPolicyMutex
    {
        private readonly Mutex mutex;
        /// <summary>Opens only the unique object supplied by this integration test.</summary>
        internal TestMutex(string name) => mutex = Mutex.OpenExisting(name);
        /// <summary>Attempts immediate acquisition and reports process-death abandonment.</summary>
        public bool? TryAcquire()
        {
            try { return mutex.WaitOne(0) ? false : null; }
            catch (AbandonedMutexException) { return true; }
        }
        /// <summary>Releases on the worker thread that acquired the mutex.</summary>
        public void Release() => mutex.ReleaseMutex();
        /// <summary>Closes this test handle without affecting other owners.</summary>
        public void Dispose() => mutex.Dispose();
    }
}
