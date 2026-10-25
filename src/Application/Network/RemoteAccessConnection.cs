namespace IPGuard.Application.Network;

/// <summary>Describes a provider-reported connection state without establishing traffic coverage.</summary>
public enum RemoteAccessState
{
    /// <summary>The provider returned a state or substate that cannot be interpreted.</summary>
    Unknown,
    /// <summary>The connection is being established or requires further interaction.</summary>
    Connecting,
    /// <summary>The provider reports a connection; its route and public exit remain unverified.</summary>
    Connected,
    /// <summary>The provider reports disconnection without a connection error.</summary>
    Disconnected,
    /// <summary>The connection is waiting for an underlying network interface.</summary>
    Dormant,
    /// <summary>The connection is switching to an available network interface.</summary>
    Reconnecting,
    /// <summary>The provider reported a connection error.</summary>
    Failed
}

/// <summary>Stores one immutable, limited remote-access observation, without entry names or endpoint addresses.</summary>
public sealed class RemoteAccessConnection
{
    /// <summary>Captures provider identity and raw states so unknown mappings remain diagnosable.</summary>
    public RemoteAccessConnection(string? correlationId, bool isVpn, RemoteAccessState state, uint errorCode, uint stateCode, uint substateCode)
    {
        CorrelationId = correlationId;
        IsVpn = isVpn;
        State = state;
        ErrorCode = errorCode;
        StateCode = stateCode;
        SubstateCode = substateCode;
    }

    /// <summary>Gets an optional provider correlation ID; it is not a routing interface identifier.</summary>
    public string? CorrelationId { get; }

    /// <summary>Gets whether the provider explicitly classified this connection as VPN.</summary>
    public bool IsVpn { get; }

    /// <summary>Gets the interpreted state, which never authorizes traffic.</summary>
    public RemoteAccessState State { get; }

    /// <summary>Gets the provider's connection error, independently of API call success.</summary>
    public uint ErrorCode { get; }

    /// <summary>Gets the source-specific raw state retained for diagnostics.</summary>
    public uint StateCode { get; }

    /// <summary>Gets the source-specific raw substate, including unknown values.</summary>
    public uint SubstateCode { get; }
}
