using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using IPGuard.Application.Network;
using IPGuard.Windows.Network.Native;

namespace IPGuard.Windows.Network;

/// <summary>Reads local Windows route and interface diagnostics without changing policy or selecting an exit.</summary>
/// <remarks>Coverage is limited to the API caller's local context; other compartments and per-app redirects remain unverified.</remarks>
public sealed class WindowsRoutingTableReader : IRoutingTableReader
{
    private const uint MaximumRows = 65536;
    private readonly IRoutingApi api;

    /// <summary>Creates the Windows x64 read-only IP Helper adapter.</summary>
    public WindowsRoutingTableReader() : this(new NativeRoutingApi()) { }

    /// <summary>Composes native reads and ownership for deterministic tests.</summary>
    internal WindowsRoutingTableReader(IRoutingApi api)
    {
        ArgumentNullException.ThrowIfNull(api);
        this.api = api;
    }

    /// <summary>Copies complete diagnostics, preserving IPv6 scope and failing the entire read on any row or interface error.</summary>
    public IReadOnlyList<NetworkRoute> Read(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        nint table = 0;
        Exception? failure = null;
        var routes = new List<NetworkRoute>();
        try
        {
            uint error = api.ReadTable(out table);
            cancellationToken.ThrowIfCancellationRequested();
            if (error != 0) { throw new Win32Exception(unchecked((int)error), "Cannot read the Windows routing table."); }
            if (table == 0) { throw new InvalidDataException("Windows returned no routing table."); }
            uint count = unchecked((uint)Marshal.ReadInt32(table));
            if (count > MaximumRows) { throw new InvalidDataException("The Windows routing table exceeds the diagnostic row limit."); }

            int offset = checked((int)Marshal.OffsetOf<NativeRouteTable>(nameof(NativeRouteTable.FirstRow)));
            int stride = Marshal.SizeOf<NativeRouteRow>();
            var interfaces = new Dictionary<(ushort Family, ulong Luid, uint Index), NativeRouteInterface>();
            for (uint index = 0; index < count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var row = Marshal.PtrToStructure<NativeRouteRow>(table + checked(offset + (int)index * stride));
                routes.Add(ReadRoute(row, interfaces, cancellationToken));
            }
        }
        catch (Exception error) { failure = error; throw; }
        finally
        {
            if (table != 0)
            {
                try { api.FreeTable(table); }
                catch (Exception cleanupError)
                {
                    if (failure is not null) { throw new AggregateException(failure, cleanupError); }
                    throw;
                }
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        return routes.AsReadOnly();
    }

    /// <summary>Joins one validated route to separately read interface metadata, caching within this read only.</summary>
    private NetworkRoute ReadRoute(NativeRouteRow row,
        Dictionary<(ushort Family, ulong Luid, uint Index), NativeRouteInterface> interfaces, CancellationToken cancellationToken)
    {
        if (row.InterfaceLuid == 0 || row.InterfaceIndex == 0 || row.Prefix.Family != row.NextHop.Family)
        {
            throw new InvalidDataException("The route identity or next-hop family is invalid.");
        }
        var prefix = DecodeAddress(row.Prefix);
        var nextHop = DecodeAddress(row.NextHop);
        if (!IPNetwork.TryParse($"{prefix}/{row.PrefixLength}", out var destination) || !destination.BaseAddress.Equals(prefix))
        {
            throw new InvalidDataException("The route destination is not a canonical IPv4 or IPv6 network prefix.");
        }

        var key = (row.Prefix.Family, row.InterfaceLuid, row.InterfaceIndex);
        if (!interfaces.TryGetValue(key, out var adapter))
        {
            adapter = new NativeRouteInterface { Family = row.Prefix.Family, InterfaceLuid = row.InterfaceLuid, InterfaceIndex = row.InterfaceIndex };
            uint error = api.ReadInterface(ref adapter);
            cancellationToken.ThrowIfCancellationRequested();
            if (error != 0) { throw new Win32Exception(unchecked((int)error), "Cannot read routing interface metadata."); }
            if (adapter.Family != row.Prefix.Family || adapter.InterfaceLuid != row.InterfaceLuid || adapter.InterfaceIndex != row.InterfaceIndex)
            {
                throw new InvalidDataException("Windows returned mismatched routing interface metadata.");
            }
            interfaces.Add(key, adapter);
        }
        try
        {
            return new NetworkRoute(destination, nextHop, row.InterfaceLuid.ToString("x16", CultureInfo.InvariantCulture),
                row.InterfaceIndex, row.Metric, adapter.Metric, adapter.Connected != 0, adapter.DisableDefaultRoutes != 0,
                row.ValidLifetime, row.Loopback != 0);
        }
        catch (ArgumentException error) { throw new InvalidDataException("Windows returned malformed route diagnostics.", error); }
    }

    /// <summary>Reconstructs network-order bytes while retaining IPv6 scope, without returning borrowed native memory.</summary>
    private static IPAddress DecodeAddress(NativeRouteAddress address)
    {
        Span<byte> bytes = stackalloc byte[16];
        if (address.Family == 2)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes, address.Ipv4);
            return new IPAddress(bytes[..4]);
        }
        if (address.Family == 23)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(bytes, address.Ipv6First);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes[8..], address.Ipv6Second);
            return new IPAddress(bytes, address.ScopeId);
        }
        throw new InvalidDataException("Windows returned an unsupported route address family.");
    }
}
