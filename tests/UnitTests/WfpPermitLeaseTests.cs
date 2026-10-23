using System.ComponentModel;
using System.Text;
using IPGuard.Windows.Filtering;
using Xunit;

namespace UnitTests;

/// <summary>Checks atomic permit creation and honest closure results without modifying Windows policy.</summary>
public sealed class WfpPermitLeaseTests
{
    /// <summary>Every baseline rule is verified before any permit is added, and the committed session stays open.</summary>
    [Fact]
    public void Open_VerifiesTheWholeBaselineAndKeepsTheSessionAlive()
    {
        var session = new PermitSession();

        using var lease = WfpPermitLease.Open([@"C:\Tools\pwsh.exe"], () => session);

        Assert.False(lease.IsClosed);
        Assert.Equal(4, session.Permits.Count);
        Assert.Equal(4, session.Permits.Select(rule => rule.LayerKey).Distinct().Count());
        Assert.All(session.Permits, rule => Assert.Equal(Encoding.Unicode.GetBytes(@"c:\tools\pwsh.exe"), rule.ApplicationId.ToArray()));
        Assert.Equal(["resolve", "begin", "owner", "block-1", "block-2", "block-3", "block-4", "permit-1", "permit-2", "permit-3", "permit-4", "commit"], session.Events);
    }

    /// <summary>Missing baseline objects prevent any permit and close the unsuccessful session.</summary>
    [Theory]
    [InlineData("owner")]
    [InlineData("block")]
    public void Open_RejectsAnIncompleteBaseline(string missing)
    {
        var session = new PermitSession { OwnerPresent = missing != "owner", MissingBlock = missing == "block" ? 4 : 0 };

        Assert.Throws<InvalidOperationException>(() => WfpPermitLease.Open([@"C:\Tools\pwsh.exe"], () => session));

        Assert.Empty(session.Permits);
        Assert.DoesNotContain(session.Events, entry => entry.StartsWith("permit-", StringComparison.Ordinal));
        Assert.Equal(["abort", "close"], session.Events.TakeLast(2));
    }

    /// <summary>A non-dynamic session cannot create permissions that survive the lease.</summary>
    [Fact]
    public void Open_RejectsAStaticSessionBeforeStartingATransaction()
    {
        var session = new PermitSession { IsDynamic = false };

        Assert.Throws<InvalidOperationException>(() => WfpPermitLease.Open([@"C:\Tools\pwsh.exe"], () => session));

        Assert.Equal(["close"], session.Events);
    }

    /// <summary>Failures in baseline reads, permit adds, or commit roll back and close the dynamic session.</summary>
    [Theory]
    [InlineData("block-2")]
    [InlineData("permit-3")]
    [InlineData("commit")]
    public void Open_FailureDoesNotLeaveAPartialGrant(string failure)
    {
        var session = new PermitSession { FailAt = failure };

        var error = Assert.Throws<Win32Exception>(() => WfpPermitLease.Open([@"C:\Tools\pwsh.exe"], () => session));

        Assert.Contains(failure, error.Message);
        Assert.Empty(session.Permits);
        Assert.Equal(["abort", "close"], session.Events.TakeLast(2));
    }

    /// <summary>Failure before a transaction starts closes the session without aborting a nonexistent transaction.</summary>
    [Theory]
    [InlineData("resolve")]
    [InlineData("begin")]
    public void Open_EarlyFailureClosesWithoutAbort(string failure)
    {
        var session = new PermitSession { FailAt = failure };

        Assert.Throws<Win32Exception>(() => WfpPermitLease.Open([@"C:\Tools\pwsh.exe"], () => session));

        Assert.DoesNotContain("abort", session.Events);
        Assert.Equal("close", session.Events.Last());
    }

    /// <summary>Rollback and session-close failures remain observable alongside the failed operation.</summary>
    [Fact]
    public void Open_PreservesOperationRollbackAndCloseErrors()
    {
        var session = new PermitSession { FailAt = "permit-2", FailAbort = true, FailClose = true };

        var error = Assert.Throws<AggregateException>(() => WfpPermitLease.Open([@"C:\Tools\pwsh.exe"], () => session));

        Assert.Equal(3, error.Flatten().InnerExceptions.Count);
        Assert.Contains(error.Flatten().InnerExceptions, item => item.Message.Contains("permit-2", StringComparison.Ordinal));
        Assert.Contains(error.Flatten().InnerExceptions, item => item.Message.Contains("abort", StringComparison.Ordinal));
        Assert.Contains(error.Flatten().InnerExceptions, item => item.Message.Contains("close", StringComparison.Ordinal));
    }

    /// <summary>Successful disposal revokes the session once without changing baseline objects.</summary>
    [Fact]
    public void Dispose_ClosesOnceAndConfirmsClosure()
    {
        var session = new PermitSession();
        var lease = WfpPermitLease.Open([@"C:\Tools\pwsh.exe"], () => session);

        lease.Dispose();
        lease.Dispose();

        Assert.True(lease.IsClosed);
        Assert.Empty(session.Permits);
        Assert.True(session.OwnerPresent);
        Assert.Equal(1, session.Events.Count(entry => entry == "close"));
    }

    /// <summary>A failed close remains unconfirmed even if later cleanup would appear to succeed.</summary>
    [Fact]
    public void Dispose_FailedCloseRemainsUnconfirmed()
    {
        var session = new PermitSession { FailClose = true };
        var lease = WfpPermitLease.Open([@"C:\Tools\pwsh.exe"], () => session);

        var error = Assert.Throws<Win32Exception>(lease.Dispose);
        Assert.False(lease.IsClosed);
        Assert.Equal(4, session.Permits.Count);

        session.FailClose = false;
        Assert.Same(error, Assert.Throws<Win32Exception>(lease.Dispose));
        Assert.False(lease.IsClosed);
        Assert.Equal(4, session.Permits.Count);
        Assert.Equal(1, session.Events.Count(entry => entry == "close"));
    }

    /// <summary>Invalid scope is rejected before a native session could be opened.</summary>
    [Theory]
    [InlineData("pwsh.exe")]
    [InlineData(@"C:\Tools\curl.exe")]
    [InlineData("")]
    public void Open_InvalidPathsDoNotOpenASession(string path)
    {
        bool opened = false;

        Assert.ThrowsAny<ArgumentException>(() => WfpPermitLease.Open([path], () =>
        {
            opened = true;
            return new PermitSession();
        }));

        Assert.False(opened);
    }

    /// <summary>Case aliases create only one permit for each application and ALE layer.</summary>
    [Fact]
    public void Open_MergesCaseAliases()
    {
        var session = new PermitSession();

        using var lease = WfpPermitLease.Open([@"C:\Tools\pwsh.exe", @"c:\tools\PWSH.EXE"], () => session);

        Assert.Equal(4, session.Permits.Count);
    }

    /// <summary>Windows PowerShell and PowerShell 7 each retain their own four-layer scope.</summary>
    [Fact]
    public void Open_CoversBothPowerShellExecutables()
    {
        var session = new PermitSession();

        using var lease = WfpPermitLease.Open([@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", @"C:\Tools\pwsh.exe"], () => session);

        Assert.Equal(8, session.Permits.Count);
        Assert.Equal(2, session.Permits.Select(rule => Convert.ToHexString(rule.ApplicationId.Span)).Distinct().Count());
    }

    /// <summary>Closing one lease does not claim to revoke another owner's permissions.</summary>
    [Fact]
    public void Dispose_AffectsOnlyTheOwnedSession()
    {
        var first = new PermitSession();
        var second = new PermitSession();
        using var firstLease = WfpPermitLease.Open([@"C:\Tools\pwsh.exe"], () => first);
        using var secondLease = WfpPermitLease.Open([@"C:\Tools\pwsh.exe"], () => second);

        firstLease.Dispose();

        Assert.True(firstLease.IsClosed);
        Assert.Empty(first.Permits);
        Assert.False(secondLease.IsClosed);
        Assert.Equal(4, second.Permits.Count);
    }

    /// <summary>Empty scopes cannot open a session or create unscoped permissions.</summary>
    [Fact]
    public void Open_RejectsAnEmptyScopeBeforeOpening()
    {
        bool opened = false;

        Assert.Throws<ArgumentException>(() => WfpPermitLease.Open([], () =>
        {
            opened = true;
            return new PermitSession();
        }));

        Assert.False(opened);
    }

    /// <summary>Models dynamic session ownership and staged permit changes without native calls.</summary>
    private sealed class PermitSession : IWfpSession
    {
        private readonly List<WfpBlockRule> _pending = [];
        private int _reads;

        /// <inheritdoc />
        public bool IsDynamic { get; init; } = true;

        /// <inheritdoc />
        public bool HasPolicyContainers() => throw new InvalidOperationException("A permit lease must not run VM namespace checks.");

        /// <inheritdoc />
        public IReadOnlyList<WfpBlockRule> GetBlocksForUninstall() => throw new InvalidOperationException("A permit lease must not uninstall policy.");

        /// <inheritdoc />
        public void RemoveBlock(WfpBlockRule rule) => throw new InvalidOperationException("A permit lease must not remove blocks.");

        /// <inheritdoc />
        public void RemovePolicyOwner() => throw new InvalidOperationException("A permit lease must not remove containers.");

        /// <summary>Gets committed permits belonging exclusively to this fake session.</summary>
        public List<WfpBlockRule> Permits { get; } = [];

        /// <summary>Gets transaction and lifetime events.</summary>
        public List<string> Events { get; } = [];

        /// <summary>Gets whether the owned baseline containers exist.</summary>
        public bool OwnerPresent { get; init; } = true;

        /// <summary>Gets the ordinal of a baseline rule that is absent.</summary>
        public int MissingBlock { get; init; }

        /// <summary>Gets the operation that fails before changing state.</summary>
        public string? FailAt { get; init; }

        /// <summary>Gets whether transaction rollback reports an error.</summary>
        public bool FailAbort { get; init; }

        /// <summary>Gets or sets whether session closure reports an error.</summary>
        public bool FailClose { get; set; }

        /// <inheritdoc />
        public byte[] GetApplicationId(string executablePath)
        {
            Record("resolve");
            return Encoding.Unicode.GetBytes(executablePath.ToLowerInvariant());
        }

        /// <inheritdoc />
        public void BeginTransaction(bool readOnly)
        {
            Assert.False(readOnly);
            Record("begin");
        }

        /// <inheritdoc />
        public bool HasPolicyOwner()
        {
            Record("owner");
            return OwnerPresent;
        }

        /// <inheritdoc />
        public bool IsBlockPresent(WfpBlockRule rule)
        {
            Record($"block-{++_reads}");
            return _reads != MissingBlock;
        }

        /// <inheritdoc />
        public void AddPermitFor(WfpBlockRule baseline)
        {
            Record($"permit-{_pending.Count + 1}");
            _pending.Add(baseline);
        }

        /// <inheritdoc />
        public void CommitTransaction()
        {
            Record("commit");
            Permits.AddRange(_pending);
            _pending.Clear();
        }

        /// <inheritdoc />
        public void AbortTransaction()
        {
            Record("abort");
            if (FailAbort)
            {
                throw new Win32Exception(5, "abort failed");
            }
            _pending.Clear();
        }

        /// <inheritdoc />
        public void Dispose()
        {
            Record("close");
            if (FailClose)
            {
                throw new Win32Exception(5, "close failed");
            }
            Permits.Clear();
            _pending.Clear();
        }

        /// <inheritdoc />
        public void EnsurePolicyOwner() => throw new InvalidOperationException("Permit creation must not install baseline objects.");

        /// <inheritdoc />
        public void EnsureBlock(WfpBlockRule rule) => throw new InvalidOperationException("Permit creation must not change baseline blocks.");

        /// <summary>Records an operation and optionally simulates a native failure.</summary>
        private void Record(string operation)
        {
            Events.Add(operation);
            if (FailAt == operation)
            {
                throw new Win32Exception(5, $"{operation} failed");
            }
        }
    }
}
