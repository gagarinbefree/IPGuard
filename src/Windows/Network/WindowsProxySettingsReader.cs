using System.ComponentModel;
using System.Runtime.InteropServices;
using IPGuard.Application.Network;
using IPGuard.Windows.Network.Native;

namespace IPGuard.Windows.Network;

/// <summary>Reads limited Windows proxy configuration without requests, PAC execution, or settings changes.</summary>
public sealed class WindowsProxySettingsReader : IProxySettingsReader
{
    private const uint NoProxyAccess = 1;
    private const uint NamedProxyAccess = 3;
    private readonly IProxyApi api;
    private readonly Func<string, string?> readEnvironment;

    /// <summary>Composes Windows WinHTTP reads with current-process environment variables.</summary>
    public WindowsProxySettingsReader() : this(new NativeProxyApi(), Environment.GetEnvironmentVariable) { }

    /// <summary>Separates native ownership and environment access for controlled tests.</summary>
    internal WindowsProxySettingsReader(IProxyApi api, Func<string, string?> readEnvironment)
    {
        ArgumentNullException.ThrowIfNull(api);
        ArgumentNullException.ThrowIfNull(readEnvironment);
        this.api = api;
        this.readEnvironment = readEnvironment;
    }

    /// <summary>Returns only configured flags and releases all native strings before publishing them.</summary>
    public ProxySettings Read(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        NativeUserProxy user = default;
        NativeDefaultProxy legacy = default;
        Exception? failure = null;
        ProxySettings result;
        try
        {
            uint error = api.ReadUser(out user);
            cancellationToken.ThrowIfCancellationRequested();
            if (error != 0) { throw new Win32Exception(unchecked((int)error), "Cannot read current-user proxy settings."); }
            error = api.ReadDefault(out legacy);
            cancellationToken.ThrowIfCancellationRequested();
            if (error != 0) { throw new Win32Exception(unchecked((int)error), "Cannot read legacy WinHTTP proxy settings."); }
            bool legacyProxy = HasText(legacy.Proxy);
            if (legacy.AccessType is not (NoProxyAccess or NamedProxyAccess) || (legacy.AccessType == NamedProxyAccess) != legacyProxy)
            {
                throw new InvalidDataException("The legacy WinHTTP proxy configuration is unknown or inconsistent.");
            }
            bool processProxy = new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY" }.Any(IsEnvironmentConfigured);
            bool processBypass = IsEnvironmentConfigured("NO_PROXY");
            cancellationToken.ThrowIfCancellationRequested();
            result = new ProxySettings(HasText(user.Proxy), HasText(user.Bypass), user.AutoDetect != 0, HasText(user.AutoConfigUrl),
                legacyProxy, HasText(legacy.Bypass), processProxy, processBypass);
        }
        catch (Exception error) { failure = error; throw; }
        finally
        {
            ReleaseStrings([user.AutoConfigUrl, user.Proxy, user.Bypass, legacy.Proxy, legacy.Bypass], failure);
        }
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    /// <summary>Reads only the first UTF-16 code unit, keeping credentials and addresses out of managed results.</summary>
    private static bool HasText(nint memory) => memory != 0 && Marshal.ReadInt16(memory) != 0;

    /// <summary>Observes configuration without storing or interpreting an environment value as an actual route.</summary>
    private bool IsEnvironmentConfigured(string name) => !string.IsNullOrWhiteSpace(readEnvironment(name));

    /// <summary>Attempts all unique releases, retaining both primary and cleanup failures.</summary>
    private void ReleaseStrings(nint[] strings, Exception? failure)
    {
        var errors = new List<Exception>();
        foreach (nint pointer in strings.Where(pointer => pointer != 0).Distinct())
        {
            try
            {
                uint error = api.Free(pointer);
                if (error != 0) { errors.Add(new Win32Exception(unchecked((int)error), "Cannot release native proxy settings.")); }
            }
            catch (Exception error) { errors.Add(error); }
        }
        if (errors.Count == 0) { return; }
        if (failure is not null) { errors.Insert(0, failure); }
        throw new AggregateException(errors);
    }
}
