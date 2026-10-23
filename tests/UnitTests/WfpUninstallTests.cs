using System.ComponentModel;
using IPGuard.Windows.Filtering;
using Xunit;

namespace UnitTests;

/// <summary>Checks atomic removal and conflict handling without opening WFP or resolving files.</summary>
public sealed class WfpUninstallTests
{
    /// <summary>All related objects are validated before deleting blocks, then containers, in one transaction.</summary>
    [Fact]
    public void Uninstall_RemovesTheVerifiedSnapshotWithoutResolvingPaths()
    {
        var session = new RemovalSession();
        Guid foreignKey = Guid.NewGuid();
        session.ForeignFilters.Add(foreignKey);

        new WfpBlockPolicy(() => session).Uninstall();

        Assert.Empty(session.Blocks);
        Assert.False(session.OwnerPresent);
        Assert.Equal([foreignKey], session.ForeignFilters);
        Assert.Equal(["begin", "validate", "delete-1", "delete-2", "delete-3", "delete-4", "containers", "commit", "close"], session.Events);
    }

    /// <summary>Repeated uninstall handles missing filters and containers without recreating them.</summary>
    [Fact]
    public void Uninstall_IsRepeatableWhenObjectsAreAlreadyAbsent()
    {
        var session = new RemovalSession();
        var policy = new WfpBlockPolicy(() => session);
        policy.Uninstall();
        session.Events.Clear();

        policy.Uninstall();

        Assert.Empty(session.Blocks);
        Assert.Equal(["begin", "validate", "containers", "commit", "close"], session.Events);
    }

    /// <summary>Active permissions, unknown schema, and ownership collisions stop removal before any delete.</summary>
    [Theory]
    [InlineData("permit")]
    [InlineData("schema")]
    [InlineData("owner")]
    public void Uninstall_ConflictsPreserveTheBaseline(string conflict)
    {
        var session = new RemovalSession { Conflict = conflict };

        var error = Assert.Throws<InvalidOperationException>(() => new WfpBlockPolicy(() => session).Uninstall());

        Assert.Contains(conflict, error.Message);
        Assert.Equal(4, session.Blocks.Count);
        Assert.True(session.OwnerPresent);
        Assert.Equal(["begin", "validate", "abort", "close"], session.Events);
    }

    /// <summary>Enumeration, deletion, dependency, and commit failures roll back staged removals.</summary>
    [Theory]
    [InlineData("validate")]
    [InlineData("delete-2")]
    [InlineData("containers")]
    [InlineData("commit")]
    public void Uninstall_FailureRollsBackAllChanges(string failure)
    {
        var session = new RemovalSession { FailAt = failure };

        var error = Assert.Throws<Win32Exception>(() => new WfpBlockPolicy(() => session).Uninstall());

        Assert.Contains(failure, error.Message);
        Assert.Equal(4, session.Blocks.Count);
        Assert.True(session.OwnerPresent);
        Assert.Equal(["abort", "close"], session.Events.TakeLast(2));
    }

    /// <summary>A failed transaction start must not abort an unrelated transaction.</summary>
    [Fact]
    public void Uninstall_BeginFailureClosesWithoutAbort()
    {
        var session = new RemovalSession { FailAt = "begin" };

        Assert.Throws<Win32Exception>(() => new WfpBlockPolicy(() => session).Uninstall());

        Assert.Equal(["begin", "close"], session.Events);
        Assert.Equal(4, session.Blocks.Count);
    }

    /// <summary>A dynamic session is rejected before any policy operation.</summary>
    [Fact]
    public void Uninstall_RejectsDynamicSessions()
    {
        var session = new RemovalSession { IsDynamic = true };

        Assert.Throws<InvalidOperationException>(() => new WfpBlockPolicy(() => session).Uninstall());

        Assert.Equal(["close"], session.Events);
    }

    /// <summary>Original, rollback, and close errors remain available together.</summary>
    [Fact]
    public void Uninstall_PreservesAllCleanupErrors()
    {
        var session = new RemovalSession { FailAt = "delete-2", FailAbort = true, FailClose = true };

        var error = Assert.Throws<AggregateException>(() => new WfpBlockPolicy(() => session).Uninstall());

        var failures = error.Flatten().InnerExceptions;
        Assert.Equal(3, failures.Count);
        Assert.Contains(failures, item => item.Message.Contains("delete-2", StringComparison.Ordinal));
        Assert.Contains(failures, item => item.Message.Contains("abort", StringComparison.Ordinal));
        Assert.Contains(failures, item => item.Message.Contains("close", StringComparison.Ordinal));
    }

    /// <summary>A close error after commit is still reported, even though removal has already committed.</summary>
    [Fact]
    public void Uninstall_CloseFailureDoesNotReportSuccess()
    {
        var session = new RemovalSession { FailClose = true };

        Assert.Throws<Win32Exception>(() => new WfpBlockPolicy(() => session).Uninstall());

        Assert.Empty(session.Blocks);
        Assert.False(session.OwnerPresent);
        Assert.DoesNotContain("abort", session.Events);
    }

    /// <summary>Models committed and staged policy separately, without allowing unrelated writes.</summary>
    private sealed class RemovalSession : IWfpSession
    {
        private Dictionary<Guid, WfpBlockRule> _pending = [];
        private bool _pendingOwner;
        private int _deletes;

        /// <summary>Builds an installed four-layer baseline using opaque fixture application bytes.</summary>
        public RemovalSession()
        {
            foreach (Guid layer in WfpPolicyIds.Layers)
            {
                var rule = new WfpBlockRule(Guid.NewGuid(), layer, new byte[] { 1, 2, 3 });
                Blocks.Add(rule.Key, rule);
            }
        }

        /// <inheritdoc />
        public bool IsDynamic { get; init; }

        /// <inheritdoc />
        public bool HasPolicyContainers() => throw new InvalidOperationException("Uninstall validates its removal snapshot.");

        /// <summary>Gets committed baseline filters.</summary>
        public Dictionary<Guid, WfpBlockRule> Blocks { get; } = [];

        /// <summary>Gets unrelated filters that removal must preserve.</summary>
        public List<Guid> ForeignFilters { get; } = [];

        /// <summary>Gets observable transaction and cleanup operations.</summary>
        public List<string> Events { get; } = [];

        /// <summary>Gets whether committed baseline containers remain.</summary>
        public bool OwnerPresent { get; private set; } = true;

        /// <summary>Gets an ownership or permission conflict discovered during preflight.</summary>
        public string? Conflict { get; init; }

        /// <summary>Gets the operation that reports an OS failure.</summary>
        public string? FailAt { get; init; }

        /// <summary>Gets whether rollback fails.</summary>
        public bool FailAbort { get; init; }

        /// <summary>Gets whether session closure fails.</summary>
        public bool FailClose { get; init; }

        /// <inheritdoc />
        public void BeginTransaction(bool readOnly)
        {
            Assert.False(readOnly);
            Record("begin");
            _pending = new(Blocks);
            _pendingOwner = OwnerPresent;
            _deletes = 0;
        }

        /// <inheritdoc />
        public IReadOnlyList<WfpBlockRule> GetBlocksForUninstall()
        {
            Record("validate");
            if (Conflict is not null)
            {
                throw new InvalidOperationException(Conflict);
            }
            return _pending.Values.ToArray();
        }

        /// <inheritdoc />
        public void RemoveBlock(WfpBlockRule rule)
        {
            Record($"delete-{++_deletes}");
            _pending.Remove(rule.Key);
        }

        /// <inheritdoc />
        public void RemovePolicyOwner()
        {
            Record("containers");
            Assert.Empty(_pending);
            _pendingOwner = false;
        }

        /// <inheritdoc />
        public void CommitTransaction()
        {
            Record("commit");
            Blocks.Clear();
            foreach (var pair in _pending)
            {
                Blocks.Add(pair.Key, pair.Value);
            }
            OwnerPresent = _pendingOwner;
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
            _pending.Clear();
        }

        /// <inheritdoc />
        public byte[] GetApplicationId(string executablePath) => throw new InvalidOperationException("Uninstall must not depend on existing executable files.");

        /// <inheritdoc />
        public void EnsurePolicyOwner() => throw new InvalidOperationException("Uninstall must not create containers.");

        /// <inheritdoc />
        public bool HasPolicyOwner() => throw new InvalidOperationException("Uninstall validates containers through its snapshot.");

        /// <inheritdoc />
        public void EnsureBlock(WfpBlockRule rule) => throw new InvalidOperationException("Uninstall must not install blocks.");

        /// <inheritdoc />
        public bool IsBlockPresent(WfpBlockRule rule) => throw new InvalidOperationException("Uninstall uses a validated snapshot.");

        /// <inheritdoc />
        public void AddPermitFor(WfpBlockRule baseline) => throw new InvalidOperationException("Uninstall must not create permits.");

        /// <summary>Records a requested operation before optionally reporting a native error.</summary>
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
