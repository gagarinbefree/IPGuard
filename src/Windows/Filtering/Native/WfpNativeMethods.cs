using System.Runtime.InteropServices;

namespace IPGuard.Windows.Filtering.Native;

/// <summary>Declares the user-mode WFP APIs; return codes are checked by the session adapter.</summary>
internal static class WfpNativeMethods
{
    /// <summary>Opens a local BFE session using the caller's credentials.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmEngineOpen0(nint server, uint authentication, nint identity, in NativeSession session, out nint engine);

    /// <summary>Closes a BFE session and releases its transaction resources.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmEngineClose0(nint engine);

    /// <summary>Starts an explicit read-only or write transaction.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmTransactionBegin0(nint engine, uint flags);

    /// <summary>Commits every change staged in the current transaction.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmTransactionCommit0(nint engine);

    /// <summary>Aborts all changes staged in the current transaction.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmTransactionAbort0(nint engine);

    /// <summary>Retrieves a provider whose complete returned tree belongs to BFE.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmProviderGetByKey0(nint engine, in Guid key, out nint provider);

    /// <summary>Adds a provider using default access control.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmProviderAdd0(nint engine, in NativeProvider provider, nint securityDescriptor);

    /// <summary>Retrieves a sublayer whose returned tree belongs to BFE.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmSubLayerGetByKey0(nint engine, in Guid key, out nint subLayer);

    /// <summary>Adds a persistent sublayer under IPGuard's provider.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmSubLayerAdd0(nint engine, in NativeSubLayer subLayer, nint securityDescriptor);

    /// <summary>Retrieves a filter whose returned tree belongs to BFE.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterGetByKey0(nint engine, in Guid key, out nint filter);

    /// <summary>Adds an application-scoped filter and returns its runtime identifier.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterAdd0(nint engine, in NativeFilter filter, nint securityDescriptor, out ulong id);

    /// <summary>Deletes one filter by key without touching unrelated objects.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterDeleteByKey0(nint engine, in Guid key);

    /// <summary>Deletes a sublayer only when no remaining object references it.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmSubLayerDeleteByKey0(nint engine, in Guid key);

    /// <summary>Deletes a provider only when no remaining object references it.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmProviderDeleteByKey0(nint engine, in Guid key);

    /// <summary>Creates a snapshot enumerator; a null template requests all readable filters.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterCreateEnumHandle0(nint engine, nint template, out nint enumeration);

    /// <summary>Reads an API-owned array of filter pointers from the next snapshot page.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterEnum0(nint engine, nint enumeration, uint requested, out nint entries, out uint count);

    /// <summary>Releases a snapshot enumerator independently of its already freed pages.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterDestroyEnumHandle0(nint engine, nint enumeration);

    /// <summary>Resolves a filename into a BFE-allocated application ID without adding a filter.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    internal static extern uint FwpmGetAppIdFromFileName0(string fileName, out nint applicationId);

    /// <summary>Frees the root of a BFE-allocated output tree.</summary>
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern void FwpmFreeMemory0(ref nint memory);
}
