using System.ComponentModel;
using IPGuard.Windows.Filtering.Native;
using Xunit;

namespace UnitTests;

/// <summary>Checks native handle lifetime without calling the Windows filter engine.</summary>
public sealed class WfpEngineHandleTests
{
    /// <summary>Operations use the original handle until its owner closes it.</summary>
    [Fact]
    public void Use_ForwardsTheHandleAndResult()
    {
        using var handle = new WfpEngineHandle(123, _ => 0);

        uint result = handle.Use(value =>
        {
            Assert.Equal((nint)123, value);
            return 37;
        });

        Assert.Equal(37u, result);
    }

    /// <summary>Successful disposal closes once and prevents later native operations.</summary>
    [Fact]
    public void Dispose_ClosesOnlyOnce()
    {
        int closed = 0;
        var handle = new WfpEngineHandle(123, value =>
        {
            Assert.Equal((nint)123, value);
            closed++;
            return 0;
        });

        handle.Dispose();
        handle.Dispose();

        Assert.Equal(1, closed);
        Assert.Throws<ObjectDisposedException>(() => handle.Use(_ => 0));
    }

    /// <summary>A native close failure remains visible without reusing a handle of undocumented validity.</summary>
    [Fact]
    public void Dispose_FailedCloseCannotLaterReportSuccessOrReuseTheHandle()
    {
        uint closeResult = 0x80010001;
        var attempts = new List<nint>();
        var handle = new WfpEngineHandle(456, value =>
        {
            attempts.Add(value);
            return closeResult;
        });

        var error = Assert.Throws<Win32Exception>(handle.Dispose);
        Assert.Equal(unchecked((int)closeResult), error.NativeErrorCode);
        Assert.Contains("FwpmEngineClose0", error.Message);
        Assert.Contains("0x80010001", error.Message);
        Assert.Throws<ObjectDisposedException>(() => handle.Use(_ => 0));

        closeResult = 0;
        Assert.Same(error, Assert.Throws<Win32Exception>(handle.Dispose));
        Assert.Equal(new nint[] { 456 }, attempts);
    }

    /// <summary>A null native handle cannot be adopted.</summary>
    [Fact]
    public void Constructor_RejectsNullHandle()
    {
        Assert.Throws<ArgumentException>(() => new WfpEngineHandle(0, _ => 0));
    }
}
