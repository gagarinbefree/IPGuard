using System.Runtime.InteropServices;
using IPGuard.Windows.Filtering.Native;
using static IPGuard.Windows.Filtering.Native.WfpNativeError;

namespace IPGuard.Windows.Filtering;

/// <summary>Manages prototype block and permit objects through real user-mode WFP APIs.</summary>
/// <remarks>Use from one owner without concurrent calls. Writes require appropriate WFP privileges and an isolated VM during development.</remarks>
internal sealed class NativeWfpSession : IWfpSession
{
    private const uint ProviderNotFound = 0x80320005;
    private const uint SubLayerNotFound = 0x80320007;
    private const uint FilterNotFound = 0x80320003;
    private const uint WindowsAuthentication = 10;
    private const uint ReadOnlyTransaction = 1;
    private readonly WfpEngineHandle _engine;

    /// <inheritdoc />
    public bool IsDynamic { get; }

    /// <summary>Opens a session whose filters are removed when its owner disconnects.</summary>
    public static IWfpSession OpenDynamic() => Open(dynamic: true);

    /// <summary>Builds explicit session flags without opening BFE or changing policy.</summary>
    internal static NativeSession CreateSettings(bool dynamic, NativeMemoryScope memory) => new()
    {
        DisplayData = new NativeDisplayData { Name = memory.Text(WfpPolicyIds.DisplayName) },
        Flags = dynamic ? 1u : 0u,
        TransactionWaitMilliseconds = 5_000
    };

    /// <inheritdoc />
    public void AddPermitFor(WfpBlockRule baseline)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        if (!IsDynamic)
        {
            throw new InvalidOperationException("Permits must belong to a dynamic WFP session.");
        }

        using var memory = new NativeMemoryScope();
        Guid key = Guid.NewGuid();
        var filter = WfpNativeFilter.CreatePermit(baseline, key, memory);
        Check(Call(engine => WfpNativeMethods.FwpmFilterAdd0(engine, filter, 0, out _)), "FwpmFilterAdd0");
        if (ReadFilterMatch(key, stored => WfpNativeFilter.MatchesPermit(stored, baseline, key)) != true)
        {
            throw new InvalidOperationException($"WFP permit {key} could not be verified after creation.");
        }
    }

    /// <summary>Takes ownership of an already opened native session.</summary>
    private NativeWfpSession(nint engine, bool dynamic)
    {
        _engine = new WfpEngineHandle(engine, WfpNativeMethods.FwpmEngineClose0);
        IsDynamic = dynamic;
    }

    /// <summary>Opens a non-dynamic session; this operation alone does not create policy objects.</summary>
    public static IWfpSession Open() => Open(dynamic: false);

    /// <summary>Opens a management or permit session using explicitly selected lifetime flags.</summary>
    private static IWfpSession Open(bool dynamic)
    {
        RequireWindowsX64();
        using var memory = new NativeMemoryScope();
        var session = CreateSettings(dynamic, memory);
        Check(WfpNativeMethods.FwpmEngineOpen0(0, WindowsAuthentication, 0, session, out nint engine), "FwpmEngineOpen0");
        return new NativeWfpSession(engine, dynamic);
    }

    /// <summary>Resolves an application ID without creating filters or changing policy.</summary>
    public static byte[] ReadApplicationId(string executablePath)
    {
        RequireWindowsX64();
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        if (!Path.IsPathFullyQualified(executablePath))
        {
            throw new ArgumentException("A full executable path is required.", nameof(executablePath));
        }

        nint pointer = 0;
        try
        {
            Check(WfpNativeMethods.FwpmGetAppIdFromFileName0(executablePath, out pointer), "FwpmGetAppIdFromFileName0");
            var blob = Read<NativeBlob>(pointer);
            if (blob.Size == 0 || blob.Size > 65_536 || blob.Data == 0)
            {
                throw new InvalidOperationException("Windows returned an invalid application ID blob.");
            }

            byte[] applicationId = new byte[checked((int)blob.Size)];
            Marshal.Copy(blob.Data, applicationId, 0, applicationId.Length);
            return applicationId;
        }
        finally
        {
            FreeOutput(ref pointer);
        }
    }

    /// <inheritdoc />
    public byte[] GetApplicationId(string executablePath) => ReadApplicationId(executablePath);

    /// <inheritdoc />
    public void BeginTransaction(bool readOnly) => Check(Call(engine => WfpNativeMethods.FwpmTransactionBegin0(engine, readOnly ? ReadOnlyTransaction : 0u)), "FwpmTransactionBegin0");

    /// <inheritdoc />
    public void CommitTransaction() => Check(Call(WfpNativeMethods.FwpmTransactionCommit0), "FwpmTransactionCommit0");

    /// <inheritdoc />
    public void AbortTransaction() => Check(Call(WfpNativeMethods.FwpmTransactionAbort0), "FwpmTransactionAbort0");

    /// <inheritdoc />
    public void EnsurePolicyOwner()
    {
        using var memory = new NativeMemoryScope();
        if (!CheckProvider())
        {
            var provider = WfpNativePolicyObjects.CreateProvider(memory);
            Check(Call(engine => WfpNativeMethods.FwpmProviderAdd0(engine, provider, 0)), "FwpmProviderAdd0");
        }

        if (!CheckSubLayer())
        {
            var subLayer = WfpNativePolicyObjects.CreateSubLayer(memory);
            Check(Call(engine => WfpNativeMethods.FwpmSubLayerAdd0(engine, subLayer, 0)), "FwpmSubLayerAdd0");
        }

        if (!HasPolicyOwner())
        {
            throw new InvalidOperationException("WFP policy containers could not be verified after creation.");
        }
    }

    /// <inheritdoc />
    public bool HasPolicyOwner() => CheckProvider() && CheckSubLayer();

    /// <inheritdoc />
    public void EnsureBlock(WfpBlockRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (ReadBlock(rule) is bool matches)
        {
            if (!matches)
            {
                throw new InvalidOperationException($"WFP filter {rule.Key} conflicts with the required block; it was not changed.");
            }

            return;
        }

        using var memory = new NativeMemoryScope();
        var filter = WfpNativeFilter.Create(rule, memory);
        Check(Call(engine => WfpNativeMethods.FwpmFilterAdd0(engine, filter, 0, out _)), "FwpmFilterAdd0");
        if (!IsBlockPresent(rule))
        {
            throw new InvalidOperationException($"WFP filter {rule.Key} could not be verified after creation.");
        }
    }

    /// <inheritdoc />
    public bool IsBlockPresent(WfpBlockRule rule) => ReadBlock(rule) == true;

    /// <summary>Verifies an existing provider and rejects same-key collisions or disabled policy.</summary>
    private bool CheckProvider()
    {
        nint pointer = 0;
        uint result = Call(engine => WfpNativeMethods.FwpmProviderGetByKey0(engine, WfpPolicyIds.Provider, out pointer));
        if (result == ProviderNotFound)
        {
            return false;
        }

        Check(result, "FwpmProviderGetByKey0");
        try
        {
            var provider = Read<NativeProvider>(pointer);
            if (!WfpNativePolicyObjects.Matches(provider))
            {
                throw new InvalidOperationException("The existing WFP provider is disabled or has incompatible ownership metadata.");
            }

            return true;
        }
        finally
        {
            FreeOutput(ref pointer);
        }
    }

    /// <summary>Verifies the provider association, persistence, ownership marker, and sublayer weight.</summary>
    private bool CheckSubLayer()
    {
        nint pointer = 0;
        uint result = Call(engine => WfpNativeMethods.FwpmSubLayerGetByKey0(engine, WfpPolicyIds.SubLayer, out pointer));
        if (result == SubLayerNotFound)
        {
            return false;
        }

        Check(result, "FwpmSubLayerGetByKey0");
        try
        {
            var layer = Read<NativeSubLayer>(pointer);
            if (!WfpNativePolicyObjects.Matches(layer))
            {
                throw new InvalidOperationException("The existing WFP sublayer has incompatible ownership metadata.");
            }

            return true;
        }
        finally
        {
            FreeOutput(ref pointer);
        }
    }

    /// <summary>Distinguishes an absent filter from a present but unsafe same-key object.</summary>
    private bool? ReadBlock(WfpBlockRule rule) => ReadFilterMatch(rule.Key, filter => WfpNativeFilter.Matches(filter, rule));

    /// <summary>Reads one filter without confusing absence, a mismatch, and an API failure.</summary>
    private bool? ReadFilterMatch(Guid key, Func<NativeFilter, bool> matches)
    {
        nint pointer = 0;
        uint result = Call(engine => WfpNativeMethods.FwpmFilterGetByKey0(engine, key, out pointer));
        if (result == FilterNotFound)
        {
            return null;
        }

        Check(result, "FwpmFilterGetByKey0");
        try
        {
            return matches(Read<NativeFilter>(pointer));
        }
        finally
        {
            FreeOutput(ref pointer);
        }
    }

    /// <summary>Keeps the native session alive until a synchronous API call has returned.</summary>
    private uint Call(Func<nint, uint> operation) => _engine.Use(operation);

    /// <summary>Rejects a null API output before reading a native structure.</summary>
    private static T Read<T>(nint pointer) where T : struct => pointer != 0
        ? Marshal.PtrToStructure<T>(pointer)
        : throw new InvalidOperationException("WFP returned a null object pointer.");

    /// <summary>Releases a complete API-owned output tree with its matching allocator.</summary>
    private static void FreeOutput(ref nint pointer)
    {
        if (pointer != 0)
        {
            WfpNativeMethods.FwpmFreeMemory0(ref pointer);
        }
    }

    /// <summary>Limits native calls to the ABI tested by the current Windows build.</summary>
    private static void RequireWindowsX64()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            throw new PlatformNotSupportedException("The WFP prototype currently supports Windows x64 only.");
        }
    }

    /// <summary>Closes the session and its dynamic permits; persistent blocks are not removed.</summary>
    public void Dispose() => _engine.Dispose();
}
