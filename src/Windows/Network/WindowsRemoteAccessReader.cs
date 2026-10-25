using System.ComponentModel;
using System.Runtime.InteropServices;
using IPGuard.Application.Network;
using IPGuard.Windows.Network.Native;

namespace IPGuard.Windows.Network;

/// <summary>Reads Windows RAS connections without dialing, disconnecting, or claiming complete VPN coverage.</summary>
public sealed class WindowsRemoteAccessReader : IRemoteAccessReader
{
    private const int MaximumConnections = 1024;
    private const int MaximumAttempts = 4;
    private const int DeviceTypeOffset = 526;
    private const int DeviceTypeCharacters = 17;
    private const uint BufferTooSmall = 603;
    private const uint ConnectedState = 0x2000;
    private const uint DisconnectedState = 0x2001;
    private readonly IRemoteAccessApi api;

    /// <summary>Creates the Windows x64 RAS adapter.</summary>
    public WindowsRemoteAccessReader() : this(new NativeRemoteAccessApi()) { }

    /// <summary>Composes read-only native calls for deterministic enumeration tests.</summary>
    internal WindowsRemoteAccessReader(IRemoteAccessApi api)
    {
        ArgumentNullException.ThrowIfNull(api);
        this.api = api;
    }

    /// <summary>Returns provider observations or throws, bounding buffer growth and retaining raw unknown states.</summary>
    public IReadOnlyList<RemoteAccessConnection> Read(CancellationToken cancellationToken)
    {
        int stride = Marshal.SizeOf<NativeRemoteConnection>();
        uint capacity = checked((uint)stride);
        for (int attempt = 0; attempt < MaximumAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            nint buffer = Marshal.AllocHGlobal(checked((int)capacity));
            IReadOnlyList<RemoteAccessConnection> completed;
            try
            {
                Marshal.Copy(new byte[capacity], 0, buffer, checked((int)capacity));
                Marshal.WriteInt32(buffer, stride);
                uint bytes = capacity;
                uint error = api.Enumerate(buffer, ref bytes, out uint count);
                cancellationToken.ThrowIfCancellationRequested();
                if (error == BufferTooSmall)
                {
                    if (bytes <= capacity || bytes > (uint)(stride * MaximumConnections))
                    {
                        throw new InvalidDataException("RAS requested an invalid or excessive diagnostic buffer.");
                    }
                    capacity = bytes;
                    continue;
                }
                if (error != 0) { throw new Win32Exception(unchecked((int)error), "Cannot enumerate Windows RAS connections."); }
                if (count > MaximumConnections || bytes > capacity || (ulong)count * (uint)stride > bytes)
                {
                    throw new InvalidDataException("RAS returned inconsistent connection counts or buffer sizes.");
                }
                completed = ReadConnections(buffer, count, stride, cancellationToken);
            }
            finally { Marshal.FreeHGlobal(buffer); }
            cancellationToken.ThrowIfCancellationRequested();
            return completed;
        }
        throw new IOException("RAS connections changed too often to produce a bounded diagnostic read.");
    }

    /// <summary>Copies validated enumeration rows and their independently queried statuses into private observations.</summary>
    private IReadOnlyList<RemoteAccessConnection> ReadConnections(nint buffer, uint count, int stride, CancellationToken cancellationToken)
    {
        var connections = new List<RemoteAccessConnection>();
        var handles = new HashSet<nint>();
        for (uint index = 0; index < count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            nint rowPointer = buffer + checked((int)index * stride);
            var row = Marshal.PtrToStructure<NativeRemoteConnection>(rowPointer);
            if (row.Handle == 0 || !handles.Add(row.Handle))
            {
                throw new InvalidDataException("RAS returned a missing or duplicate connection handle.");
            }
            bool vpn = string.Equals(ReadDeviceType(rowPointer), "vpn", StringComparison.OrdinalIgnoreCase);
            var status = new NativeRemoteStatus { Size = checked((uint)Marshal.SizeOf<NativeRemoteStatus>()) };
            uint error = api.ReadStatus(row.Handle, ref status);
            cancellationToken.ThrowIfCancellationRequested();
            if (error != 0) { throw new Win32Exception(unchecked((int)error), "Cannot read Windows RAS connection status."); }
            connections.Add(new RemoteAccessConnection(row.CorrelationId == Guid.Empty ? null : row.CorrelationId.ToString("D"),
                vpn, InterpretState(status), status.Error, status.State, status.Substate));
        }
        return connections.AsReadOnly();
    }

    /// <summary>Reads only the bounded device-type field, excluding names, phone numbers, and endpoint addresses.</summary>
    private static string ReadDeviceType(nint row)
    {
        Span<char> characters = stackalloc char[DeviceTypeCharacters];
        for (int index = 0; index < characters.Length; index++)
        {
            char value = (char)Marshal.ReadInt16(row + DeviceTypeOffset + index * sizeof(char));
            if (value == '\0') { return new string(characters[..index]); }
            characters[index] = value;
        }
        throw new InvalidDataException("RAS returned an unterminated device-type field.");
    }

    /// <summary>Separates call success from connection failure and preserves uncertain IKEv2 states.</summary>
    private static RemoteAccessState InterpretState(NativeRemoteStatus status)
    {
        if (status.Error != 0) { return RemoteAccessState.Failed; }
        if (status.State == ConnectedState)
        {
            return status.Substate switch
            {
                0 or ConnectedState => RemoteAccessState.Connected,
                1 => RemoteAccessState.Dormant,
                2 => RemoteAccessState.Reconnecting,
                _ => RemoteAccessState.Unknown
            };
        }
        if (status.State == DisconnectedState) { return RemoteAccessState.Disconnected; }
        return status.State is <= 24 or (>= 4096 and <= 4100) ? RemoteAccessState.Connecting : RemoteAccessState.Unknown;
    }
}
