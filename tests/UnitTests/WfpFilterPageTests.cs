using IPGuard.Windows.Filtering.Native;
using Xunit;

namespace UnitTests;

/// <summary>Checks pointer-array traversal using only test-owned native memory.</summary>
public sealed class WfpFilterPageTests
{
    /// <summary>Each native filter is visited in order while its backing page is alive.</summary>
    [Fact]
    public void VisitPage_ReadsEachPointerInOrder()
    {
        using var memory = new NativeMemoryScope();
        Guid first = Guid.NewGuid();
        Guid second = Guid.NewGuid();
        nint firstPointer = memory.Structure(new NativeFilter { Key = first });
        nint secondPointer = memory.Structure(new NativeFilter { Key = second });
        nint entries = memory.Blob([.. BitConverter.GetBytes(firstPointer.ToInt64()), .. BitConverter.GetBytes(secondPointer.ToInt64())]).Data;
        var keys = new List<Guid>();

        WfpFilterEnumerator.VisitPage(entries, 2, filter => keys.Add(filter.Key));

        Assert.Equal([first, second], keys);
    }

    /// <summary>An exhausted enumeration may return an empty page with no allocation.</summary>
    [Fact]
    public void VisitPage_AcceptsAnEmptyPage()
    {
        WfpFilterEnumerator.VisitPage(0, 0, _ => Assert.Fail("An empty page must not invoke its visitor."));
    }

    /// <summary>Invalid API page counts and missing pointer arrays are rejected before dereferencing memory.</summary>
    [Theory]
    [InlineData(1u)]
    [InlineData(129u)]
    public void VisitPage_RejectsInvalidPageMetadata(uint count)
    {
        Assert.Throws<InvalidOperationException>(() => WfpFilterEnumerator.VisitPage(0, count, _ => { }));
    }

    /// <summary>A null filter entry is not silently skipped during ownership preflight.</summary>
    [Fact]
    public void VisitPage_RejectsANullEntry()
    {
        using var memory = new NativeMemoryScope();
        nint entries = memory.Blob(new byte[IntPtr.Size]).Data;

        Assert.Throws<InvalidOperationException>(() => WfpFilterEnumerator.VisitPage(entries, 1, _ => { }));
    }

    /// <summary>A conflict raised by the visitor stops enumeration without masking its cause.</summary>
    [Fact]
    public void VisitPage_PreservesVisitorFailure()
    {
        using var memory = new NativeMemoryScope();
        nint filter = memory.Structure(new NativeFilter());
        nint entries = memory.Blob(BitConverter.GetBytes(filter.ToInt64())).Data;
        var failure = new InvalidOperationException("ownership conflict");

        Assert.Same(failure, Assert.Throws<InvalidOperationException>(() => WfpFilterEnumerator.VisitPage(entries, 1, _ => throw failure)));
    }
}
