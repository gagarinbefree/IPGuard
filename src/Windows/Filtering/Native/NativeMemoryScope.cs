using System.Runtime.InteropServices;

namespace IPGuard.Windows.Filtering.Native;

/// <summary>Owns temporary HGlobal inputs until a synchronous WFP call returns.</summary>
internal sealed class NativeMemoryScope : IDisposable
{
    private readonly List<nint> _allocations = [];

    /// <summary>Copies a blittable structure into an allocation owned by this scope.</summary>
    internal nint Structure<T>(T value) where T : struct
    {
        nint pointer = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        _allocations.Add(pointer);
        Marshal.StructureToPtr(value, pointer, fDeleteOld: false);
        return pointer;
    }

    /// <summary>Copies bytes into a native blob whose buffer belongs to this scope.</summary>
    internal NativeBlob Blob(ReadOnlySpan<byte> value)
    {
        byte[] bytes = value.ToArray();
        nint pointer = Marshal.AllocHGlobal(bytes.Length);
        _allocations.Add(pointer);
        Marshal.Copy(bytes, 0, pointer, bytes.Length);
        return new NativeBlob { Size = checked((uint)bytes.Length), Data = pointer };
    }

    /// <summary>Allocates a null-terminated UTF-16 string.</summary>
    internal nint Text(string value)
    {
        nint pointer = Marshal.StringToHGlobalUni(value);
        _allocations.Add(pointer);
        return pointer;
    }

    /// <summary>Releases only HGlobal allocations; BFE output memory uses FwpmFreeMemory0.</summary>
    public void Dispose()
    {
        foreach (nint pointer in _allocations)
        {
            Marshal.FreeHGlobal(pointer);
        }

        _allocations.Clear();
    }
}
