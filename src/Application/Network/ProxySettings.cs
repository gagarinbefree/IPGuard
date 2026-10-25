namespace IPGuard.Application.Network;

/// <summary>Records configured proxy mechanisms without storing proxy credentials, addresses, or PAC content.</summary>
/// <remarks>False flags do not establish a direct PowerShell route. Session settings and other users remain unverified.</remarks>
public sealed class ProxySettings
{
    /// <summary>Captures independent user, legacy WinHTTP, and current-process environment observations.</summary>
    public ProxySettings(bool userProxy, bool userBypass, bool autoDetect, bool autoConfigScript,
        bool legacyWinHttpProxy, bool legacyWinHttpBypass, bool processProxy, bool processBypass)
    {
        UserProxy = userProxy;
        UserBypass = userBypass;
        AutoDetect = autoDetect;
        AutoConfigScript = autoConfigScript;
        LegacyWinHttpProxy = legacyWinHttpProxy;
        LegacyWinHttpBypass = legacyWinHttpBypass;
        ProcessProxy = processProxy;
        ProcessBypass = processBypass;
    }

    /// <summary>Gets whether the current user's active-connection configuration names a proxy.</summary>
    public bool UserProxy { get; }

    /// <summary>Gets whether that user configuration includes bypass settings.</summary>
    public bool UserBypass { get; }

    /// <summary>Gets whether user proxy auto-detection is enabled; no discovery request is performed.</summary>
    public bool AutoDetect { get; }

    /// <summary>Gets whether a PAC URL is configured; its content is never downloaded or executed.</summary>
    public bool AutoConfigScript { get; }

    /// <summary>Gets whether the legacy WinHTTP registry configuration names a proxy, independently of sessions.</summary>
    public bool LegacyWinHttpProxy { get; }

    /// <summary>Gets whether that WinHTTP registry configuration includes bypass settings.</summary>
    public bool LegacyWinHttpBypass { get; }

    /// <summary>Gets whether HTTP_PROXY, HTTPS_PROXY, or ALL_PROXY is configured in the current process.</summary>
    public bool ProcessProxy { get; }

    /// <summary>Gets whether NO_PROXY is configured in the current process.</summary>
    public bool ProcessBypass { get; }
}
