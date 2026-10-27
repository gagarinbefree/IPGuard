using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace IPGuard.Windows.Filtering;

/// <summary>Implements protected Windows kernel ownership without modifying network policy.</summary>
internal sealed class WindowsPolicyMutex : IPolicyMutex
{
    private readonly Mutex mutex;

    /// <summary>Retains one validated handle without acquiring it on the opening thread.</summary>
    private WindowsPolicyMutex(Mutex mutex) => this.mutex = mutex;

    /// <summary>Creates or opens and validates the fixed production object only for an enabled administrator.</summary>
    internal static IPolicyMutex OpenProduction()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
            throw new PlatformNotSupportedException("Policy hosting requires Windows x64.");
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Policy hosting requires an enabled administrator token.");
        return Open(@"Global\IPGuard.PolicyOwner.v1");
    }

    /// <summary>Opens a specified name for safe unique-object tests; existing descriptors are validated, never rewritten.</summary>
    internal static IPolicyMutex Open(string name)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows mutex security is required.");
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var handle = MutexAcl.Create(false, name, out _, PolicyMutexSecurity.Create());
        try
        {
            // Creation security is ignored for existing objects; validate the descriptor actually in the kernel.
            PolicyMutexSecurity.Validate(handle.GetAccessControl().GetSecurityDescriptorBinaryForm());
            return new WindowsPolicyMutex(handle);
        }
        catch { handle.Dispose(); throw; }
    }

    /// <summary>Attempts acquisition without waiting, preserving abandonment information.</summary>
    public bool? TryAcquire()
    {
        try { return mutex.WaitOne(0) ? false : null; }
        catch (AbandonedMutexException) { return true; }
    }

    /// <summary>Releases only on the current owning thread.</summary>
    public void Release() => mutex.ReleaseMutex();

    /// <summary>Closes only this process's kernel handle.</summary>
    public void Dispose() => mutex.Dispose();
}
