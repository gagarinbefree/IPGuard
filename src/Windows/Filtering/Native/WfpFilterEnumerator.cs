using System.Runtime.InteropServices;
using static IPGuard.Windows.Filtering.Native.WfpNativeError;

namespace IPGuard.Windows.Filtering.Native;

/// <summary>Visits native filter snapshots while their BFE-owned page memory remains valid.</summary>
internal static class WfpFilterEnumerator
{
    internal const uint PageSize = 128;

    /// <summary>Visits all readable filters in a fresh snapshot within the caller's explicit transaction.</summary>
    internal static void Visit(WfpEngineHandle engine, Action<NativeFilter> visit)
    {
        nint enumeration = 0;
        Check(engine.Use(value => WfpNativeMethods.FwpmFilterCreateEnumHandle0(value, 0, out enumeration)), "FwpmFilterCreateEnumHandle0");
        if (enumeration == 0)
        {
            throw new InvalidOperationException("WFP returned a null enumeration handle.");
        }

        WfpCleanup.Run(
            () => VisitPages(engine, enumeration, visit),
            () => Check(engine.Use(value => WfpNativeMethods.FwpmFilterDestroyEnumHandle0(value, enumeration)), "FwpmFilterDestroyEnumHandle0"));
    }

    /// <summary>Frees each returned pointer array once, including when ownership validation throws.</summary>
    private static void VisitPages(WfpEngineHandle engine, nint enumeration, Action<NativeFilter> visit)
    {
        while (true)
        {
            nint entries = 0;
            uint count = 0;
            try
            {
                Check(engine.Use(value => WfpNativeMethods.FwpmFilterEnum0(value, enumeration, PageSize, out entries, out count)), "FwpmFilterEnum0");
                VisitPage(entries, count, visit);
            }
            finally
            {
                if (entries != 0)
                {
                    WfpNativeMethods.FwpmFreeMemory0(ref entries);
                }
            }

            if (count < PageSize)
            {
                return;
            }
        }
    }

    /// <summary>Checks a native pointer array before visiting each filter during the page's lifetime.</summary>
    internal static void VisitPage(nint entries, uint count, Action<NativeFilter> visit)
    {
        if (count > PageSize || (count > 0 && entries == 0))
        {
            throw new InvalidOperationException("WFP returned invalid filter page metadata.");
        }

        for (int index = 0; index < count; index++)
        {
            nint filter = Marshal.ReadIntPtr(entries, index * IntPtr.Size);
            if (filter == 0)
            {
                throw new InvalidOperationException("WFP returned a null filter entry.");
            }

            visit(Marshal.PtrToStructure<NativeFilter>(filter));
        }
    }
}
