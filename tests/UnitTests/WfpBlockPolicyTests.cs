using System.ComponentModel;
using System.Text;
using IPGuard.Windows.Filtering;
using Xunit;

namespace UnitTests;

/// <summary>Checks atomic baseline changes and honest diagnostics without accessing WFP.</summary>
public sealed class WfpBlockPolicyTests
{
    /// <summary>Every registered application covers both address families and connection directions.</summary>
    [Fact]
    public void Install_CoversAllFourAleLayers()
    {
        var session = new RecordingSession();
        new WfpBlockPolicy(() => session).Install([@"C:\Tools\pwsh.exe"]);

        Assert.Equal(new HashSet<Guid>
        {
            new("c38d57d1-05a7-4c33-904f-7fbceee60e82"),
            new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"),
            new("e1cd9fe7-f4b5-4273-96c0-592e487b8650"),
            new("a3b42c97-9f04-4672-b87e-cee9c483257f")
        }, session.Stored.Values.Select(rule => rule.LayerKey).ToHashSet());
        Assert.Equal(4, session.Stored.Count);
        Assert.Equal(["resolve", "begin-write", "owner", "add-1", "add-2", "add-3", "add-4", "commit", "dispose"], session.Events);
    }

    /// <summary>Case differences in configured paths do not create duplicate filters.</summary>
    [Fact]
    public void Install_DeduplicatesPathsAndUsesStableKeys()
    {
        var session = new RecordingSession();
        var policy = new WfpBlockPolicy(() => session);
        policy.Install([@"C:\Tools\pwsh.exe", @"c:\TOOLS\PWSH.EXE"]);
        var keys = session.Stored.Keys.ToHashSet();
        session.Events.Clear();

        policy.Install([@"C:\Tools\pwsh.exe"]);

        Assert.Equal(keys, session.Stored.Keys.ToHashSet());
        Assert.Equal(4, session.Stored.Count);
        Assert.Single(session.Events, entry => entry == "resolve");
    }

    /// <summary>Invalid inputs never open a session or alter policy.</summary>
    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("pwsh.exe")]
    [InlineData(@"C:\Tools\curl.exe")]
    [InlineData(@"C:\Tools\")]
    public void Install_RejectsInvalidExecutablePaths(string path)
    {
        bool opened = false;
        var policy = new WfpBlockPolicy(() => { opened = true; return new RecordingSession(); });

        Assert.ThrowsAny<ArgumentException>(() => policy.Install([path]));
        Assert.False(opened);
    }

    /// <summary>Resolving an identity must succeed before starting a write transaction.</summary>
    [Fact]
    public void Install_IdentityFailureDoesNotStartTransaction()
    {
        var session = new RecordingSession { FailAt = "resolve" };

        Assert.Throws<Win32Exception>(() => new WfpBlockPolicy(() => session).Install([@"C:\Tools\pwsh.exe"]));

        Assert.Equal(["resolve", "dispose"], session.Events);
        Assert.Empty(session.Stored);
    }

    /// <summary>An owner, filter, or commit failure rolls back every staged change.</summary>
    [Theory]
    [InlineData("owner")]
    [InlineData("add-2")]
    [InlineData("commit")]
    public void Install_FailureRollsBack(string failure)
    {
        var session = new RecordingSession { FailAt = failure };

        Assert.Throws<Win32Exception>(() => new WfpBlockPolicy(() => session).Install([@"C:\Tools\pwsh.exe"]));

        Assert.Empty(session.Stored);
        Assert.Contains("abort", session.Events);
        Assert.Equal("dispose", session.Events[^1]);
    }

    /// <summary>Failure to start a transaction must not abort an unrelated transaction.</summary>
    [Fact]
    public void Install_BeginFailureDoesNotAbort()
    {
        var session = new RecordingSession { FailAt = "begin-write" };

        Assert.Throws<Win32Exception>(() => new WfpBlockPolicy(() => session).Install([@"C:\Tools\pwsh.exe"]));

        Assert.DoesNotContain("abort", session.Events);
    }

    /// <summary>Both the original failure and rollback failure remain available to diagnostics.</summary>
    [Fact]
    public void Install_ReportsRollbackFailure()
    {
        var session = new RecordingSession { FailAt = "add-2", FailAbort = true };

        var error = Assert.Throws<AggregateException>(() => new WfpBlockPolicy(() => session).Install([@"C:\Tools\pwsh.exe"]));

        Assert.Equal(2, error.InnerExceptions.Count);
        Assert.Contains("add-2", error.InnerExceptions[0].Message);
        Assert.Contains("abort", error.InnerExceptions[1].Message);
    }

    /// <summary>A successful read reports object presence and performs no write operations.</summary>
    [Fact]
    public void Inspect_UsesReadOnlyTransaction()
    {
        var session = new RecordingSession();
        var policy = new WfpBlockPolicy(() => session);
        policy.Install([@"C:\Tools\pwsh.exe"]);
        session.Events.Clear();

        var inspection = policy.Inspect([@"C:\Tools\pwsh.exe"]);

        Assert.Equal(WfpBaselineState.Present, inspection.State);
        Assert.Equal(4, inspection.MatchingRules);
        Assert.Equal(4, inspection.ExpectedRules);
        Assert.Null(inspection.Error);
        Assert.Equal(["resolve", "begin-read", "check-owner", "read-1", "read-2", "read-3", "read-4", "commit", "dispose"], session.Events);
    }

    /// <summary>Missing, disabled, or incompatible filters cannot count as a complete baseline.</summary>
    [Fact]
    public void Inspect_MissingRuleIsIncomplete()
    {
        var session = new RecordingSession();
        var policy = new WfpBlockPolicy(() => session);
        policy.Install([@"C:\Tools\pwsh.exe"]);
        session.Stored.Remove(session.Stored.Keys.First());

        var inspection = policy.Inspect([@"C:\Tools\pwsh.exe"]);

        Assert.Equal(WfpBaselineState.Incomplete, inspection.State);
        Assert.Equal(3, inspection.MatchingRules);
    }

    /// <summary>Partial reads and failed snapshot commits never produce a successful result.</summary>
    [Theory]
    [InlineData("read-2")]
    [InlineData("commit")]
    public void Inspect_FailureIsUnknown(string failure)
    {
        var session = new RecordingSession();
        var policy = new WfpBlockPolicy(() => session);
        policy.Install([@"C:\Tools\pwsh.exe"]);
        session.FailAt = failure;

        var inspection = policy.Inspect([@"C:\Tools\pwsh.exe"]);

        Assert.Equal(WfpBaselineState.Unknown, inspection.State);
        Assert.Equal(0, inspection.MatchingRules);
        Assert.Contains(failure, inspection.Error);
        Assert.Contains("abort", session.Events);
    }

    /// <summary>A missing or incompatible policy owner invalidates otherwise matching filters.</summary>
    [Fact]
    public void Inspect_RequiresOwnedContainers()
    {
        var session = new RecordingSession();
        var policy = new WfpBlockPolicy(() => session);
        policy.Install([@"C:\Tools\pwsh.exe"]);
        session.OwnerPresent = false;

        Assert.Equal(WfpBaselineState.Incomplete, policy.Inspect([@"C:\Tools\pwsh.exe"]).State);
    }

    /// <summary>Baseline installation must not accidentally use a short-lived dynamic session.</summary>
    [Fact]
    public void Install_RejectsADynamicSessionBeforeAnyPolicyOperation()
    {
        var session = new RecordingSession { IsDynamic = true };

        Assert.Throws<InvalidOperationException>(() => new WfpBlockPolicy(() => session).Install([@"C:\Tools\pwsh.exe"]));

        Assert.Equal(["dispose"], session.Events);
        Assert.Empty(session.Stored);
    }

    /// <summary>Models staged changes and injects operating-system failures without native calls.</summary>
    private sealed class RecordingSession : IWfpSession
    {
        private Dictionary<Guid, WfpBlockRule> _pending = [];
        private bool _pendingOwner;
        private int _adds;
        private int _reads;

        /// <inheritdoc />
        public bool IsDynamic { get; init; }

        /// <inheritdoc />
        public IReadOnlyList<WfpBlockRule> GetBlocksForUninstall() => throw new InvalidOperationException("This fixture does not uninstall policy.");

        /// <inheritdoc />
        public void RemoveBlock(WfpBlockRule rule) => throw new InvalidOperationException("Baseline installation must not remove blocks.");

        /// <inheritdoc />
        public void RemovePolicyOwner() => throw new InvalidOperationException("Baseline installation must not remove containers.");

        /// <inheritdoc />
        public void AddPermitFor(WfpBlockRule baseline) => throw new InvalidOperationException("Baseline operations must not add permits.");

        /// <summary>Gets committed filters that survive an aborted transaction.</summary>
        public Dictionary<Guid, WfpBlockRule> Stored { get; } = [];

        /// <summary>Gets observable transaction and resource-lifetime events.</summary>
        public List<string> Events { get; } = [];

        /// <summary>Gets or sets the operation that reports an access error.</summary>
        public string? FailAt { get; set; }

        /// <summary>Gets or sets whether rollback itself fails.</summary>
        public bool FailAbort { get; init; }

        /// <summary>Gets or sets whether matching policy containers exist.</summary>
        public bool OwnerPresent { get; set; }

        /// <inheritdoc />
        public byte[] GetApplicationId(string executablePath)
        {
            Record("resolve");
            return Encoding.Unicode.GetBytes(executablePath.ToLowerInvariant());
        }

        /// <inheritdoc />
        public void BeginTransaction(bool readOnly)
        {
            Record(readOnly ? "begin-read" : "begin-write");
            _pending = new(Stored);
            _pendingOwner = OwnerPresent;
            _adds = 0;
            _reads = 0;
        }

        /// <inheritdoc />
        public void EnsurePolicyOwner()
        {
            Record("owner");
            _pendingOwner = true;
        }

        /// <inheritdoc />
        public bool HasPolicyOwner()
        {
            Record("check-owner");
            return _pendingOwner;
        }

        /// <inheritdoc />
        public void EnsureBlock(WfpBlockRule rule)
        {
            Record($"add-{++_adds}");
            _pending[rule.Key] = rule;
        }

        /// <inheritdoc />
        public bool IsBlockPresent(WfpBlockRule rule)
        {
            Record($"read-{++_reads}");
            return _pending.ContainsKey(rule.Key);
        }

        /// <inheritdoc />
        public void CommitTransaction()
        {
            Record("commit");
            Stored.Clear();
            foreach (var entry in _pending)
            {
                Stored.Add(entry.Key, entry.Value);
            }
            OwnerPresent = _pendingOwner;
        }

        /// <inheritdoc />
        public void AbortTransaction()
        {
            Record("abort");
            _pending.Clear();
            if (FailAbort)
            {
                throw new Win32Exception(5, "abort failed");
            }
        }

        /// <inheritdoc />
        public void Dispose() => Record("dispose");

        /// <summary>Records a requested operation before optionally simulating an OS failure.</summary>
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
