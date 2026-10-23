using System.ComponentModel;
using System.Runtime.InteropServices;
using IPGuard.Windows.Filtering.Native;

namespace IPGuard.Windows.Filtering;

/// <summary>Manages prototype baseline objects through real user-mode WFP APIs.</summary>
/// <remarks>Use exclusively within one operation. Writes require appropriate WFP privileges and an isolated VM during development.</remarks>
internal sealed class NativeWfpSession : IWfpSession
{
    private const uint ProviderNotFound = 0x80320005;
    private const uint SubLayerNotFound = 0x80320007;
    private const uint FilterNotFound = 0x80320003;
    private const uint WindowsAuthentication = 10;
    private const uint ReadOnlyTransaction = 1;
    private nint _engine;

    /// <summary>Takes ownership of an already opened native session.</summary>
    private NativeWfpSession(nint engine) => _engine = engine;

    /// <summary>Closes an abandoned session without throwing on the finalizer thread.</summary>
    ~NativeWfpSession() => Release();

    /// <summary>Opens a non-dynamic session; this operation alone does not create policy objects.</summary>
    public static IWfpSession Open()
    {
        RequireWindowsX64();
        using var memory = new NativeMemoryScope();
        var session = new NativeSession
        {
            DisplayData = new NativeDisplayData { Name = memory.Text(WfpPolicyIds.DisplayName) },
            TransactionWaitMilliseconds = 5_000
        };
        Check(WfpNativeMethods.FwpmEngineOpen0(0, WindowsAuthentication, 0, session, out nint engine), "FwpmEngineOpen0");
        return new NativeWfpSession(engine);
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
    private bool? ReadBlock(WfpBlockRule rule)
    {
        nint pointer = 0;
        uint result = Call(engine => WfpNativeMethods.FwpmFilterGetByKey0(engine, rule.Key, out pointer));
        if (result == FilterNotFound)
        {
            return null;
        }

        Check(result, "FwpmFilterGetByKey0");
        try
        {
            return WfpNativeFilter.Matches(Read<NativeFilter>(pointer), rule);
        }
        finally
        {
            FreeOutput(ref pointer);
        }
    }

    /// <summary>Keeps the native session alive until a synchronous API call has returned.</summary>
    private uint Call(Func<nint, uint> operation)
    {
        ObjectDisposedException.ThrowIf(_engine == 0, this);
        try
        {
            return operation(_engine);
        }
        finally
        {
            GC.KeepAlive(this);
        }
    }

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

    /// <summary>Preserves the API name and complete WFP or RPC error code.</summary>
    private static void Check(uint result, string operation)
    {
        if (result != 0)
        {
            throw new Win32Exception(unchecked((int)result), $"{operation} failed (0x{result:X8}).");
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

    /// <summary>Closes this management session; persistent blocks are not removed.</summary>
    public void Dispose()
    {
        uint result = Release();
        GC.SuppressFinalize(this);
        Check(result, "FwpmEngineClose0");
    }

    /// <summary>Atomically relinquishes the handle so repeated disposal cannot close it twice.</summary>
    private uint Release()
    {
        nint engine = Interlocked.Exchange(ref _engine, 0);
        return engine == 0 ? 0 : WfpNativeMethods.FwpmEngineClose0(engine);
    }
}
