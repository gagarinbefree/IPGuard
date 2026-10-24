namespace IPGuard.Windows.Network.Native;

/// <summary>Separates native routing reads and buffer ownership from deterministic adapter tests.</summary>
internal interface IRoutingApi
{
    /// <summary>Allocates an AF_UNSPEC routing table owned until FreeTable is called.</summary>
    uint ReadTable(out nint table);

    /// <summary>Reads per-family interface metadata using the supplied LUID and index.</summary>
    uint ReadInterface(ref NativeRouteInterface row);

    /// <summary>Frees a complete native table exactly once, without freeing individual rows.</summary>
    void FreeTable(nint table);
}
