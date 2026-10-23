using System.Runtime.InteropServices;

namespace IPGuard.Windows.Filtering.Native;

/// <summary>Stores the two Unicode pointers in FWPM_DISPLAY_DATA0.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeDisplayData
{
    public nint Name;
    public nint Description;
}

/// <summary>Describes an FWP_BYTE_BLOB whose allocation is owned separately.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeBlob
{
    public uint Size;
    public nint Data;
}

/// <summary>Represents the x64 FWP_VALUE0 and FWP_CONDITION_VALUE0 tagged unions.</summary>
[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct NativeValue
{
    [FieldOffset(0)] public uint Type;
    [FieldOffset(8)] public nint Pointer;
}

/// <summary>Stores a filter action and its unused callout/filter-type union.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeAction
{
    public uint Type;
    public Guid Key;
}

/// <summary>Preserves the eight-byte alignment of FWPM_FILTER0's context union.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeContext
{
    public ulong Low;
    public ulong High;
}

/// <summary>Describes one FWPM_FILTER_CONDITION0 predicate.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeCondition
{
    public Guid FieldKey;
    public uint MatchType;
    public NativeValue Value;
}

/// <summary>Matches the Windows SDK's x64 FWPM_FILTER0 layout.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeFilter
{
    public Guid Key;
    public NativeDisplayData DisplayData;
    public uint Flags;
    public nint ProviderKey;
    public NativeBlob ProviderData;
    public Guid LayerKey;
    public Guid SubLayerKey;
    public NativeValue Weight;
    public uint ConditionCount;
    public nint Conditions;
    public NativeAction Action;
    public NativeContext Context;
    public nint Reserved;
    public ulong Id;
    public NativeValue EffectiveWeight;
}

/// <summary>Matches FWPM_PROVIDER0 without associating IPGuard with a Windows Service.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeProvider
{
    public Guid Key;
    public NativeDisplayData DisplayData;
    public uint Flags;
    public NativeBlob ProviderData;
    public nint ServiceName;
}

/// <summary>Matches FWPM_SUBLAYER0 including its provider and arbitration weight.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeSubLayer
{
    public Guid Key;
    public NativeDisplayData DisplayData;
    public uint Flags;
    public nint ProviderKey;
    public NativeBlob ProviderData;
    public ushort Weight;
}

/// <summary>Matches FWPM_SESSION0 for a non-dynamic management session.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeSession
{
    public Guid Key;
    public NativeDisplayData DisplayData;
    public uint Flags;
    public uint TransactionWaitMilliseconds;
    public uint ProcessId;
    public nint Sid;
    public nint UserName;
    public int KernelMode;
}
