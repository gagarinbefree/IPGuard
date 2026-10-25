using System.Runtime.InteropServices;

namespace IPGuard.Windows.Network.Native;

/// <summary>Matches RASCONNW's complete 1388-byte, four-byte-packed buffer without exposing private string fields.</summary>
[StructLayout(LayoutKind.Explicit, Size = 1388, Pack = 4)]
internal struct NativeRemoteConnection
{
    [FieldOffset(0)] public uint Size;
    [FieldOffset(4)] public nint Handle;
    [FieldOffset(1372)] public Guid CorrelationId;
}

/// <summary>Reserves the full RASCONNSTATUSW output, including unexposed endpoint and phone fields.</summary>
[StructLayout(LayoutKind.Explicit, Size = 608, Pack = 4)]
internal struct NativeRemoteStatus
{
    [FieldOffset(0)] public uint Size;
    [FieldOffset(4)] public uint State;
    [FieldOffset(8)] public uint Error;
    [FieldOffset(604)] public uint Substate;
}
