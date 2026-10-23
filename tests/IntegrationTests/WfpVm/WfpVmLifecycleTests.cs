using System.ComponentModel;
using System.Text;
using IPGuard.Windows.Filtering;
using Xunit;

namespace IntegrationTests.WfpVm;

/// <summary>Checks the VM scenario with in-memory sessions, without native WFP operations.</summary>
public sealed class WfpVmLifecycleTests
{
    /// <summary>The successful object round trip closes permits before removing the verified baseline.</summary>
    [Fact]
    public void Run_CompletesTheObjectRoundTrip()
    {
        var state = new PolicyState();
        var evidence = new List<string>();

        CreateScenario(state, evidence).Run(@"C:\VmResults\powershell.exe");

        Assert.Empty(state.Blocks);
        Assert.False(state.Provider);
        Assert.False(state.SubLayer);
        Assert.False(state.Permit);
        Assert.Equal(4, state.CreatedPermits);
        Assert.Equal(2, state.Removals);
        Assert.True(state.Events.IndexOf("permit-close") < state.Events.IndexOf("remove"));
        Assert.Contains(evidence, item => item.Contains("complete", StringComparison.Ordinal));
    }

    /// <summary>A partial or full pre-existing installation is rejected without writes or cleanup.</summary>
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void Run_RefusesAnyExistingContainer(bool provider, bool subLayer)
    {
        var state = new PolicyState { Provider = provider, SubLayer = subLayer };

        Assert.Throws<InvalidOperationException>(() => CreateScenario(state, []).Run(@"C:\VmResults\powershell.exe"));

        Assert.Equal(provider, state.Provider);
        Assert.Equal(subLayer, state.SubLayer);
        Assert.Empty(state.Events);
    }

    /// <summary>Unconfirmed permit closure stops the scenario without removing persistent protection.</summary>
    [Fact]
    public void Run_CloseFailureRetainsTheBaseline()
    {
        var state = new PolicyState { FailPermitClose = true };

        Assert.Throws<Win32Exception>(() => CreateScenario(state, []).Run(@"C:\VmResults\powershell.exe"));

        Assert.Equal(4, state.Blocks.Count);
        Assert.True(state.Provider);
        Assert.True(state.SubLayer);
        Assert.True(state.Permit);
        Assert.DoesNotContain("remove", state.Events);
    }

    /// <summary>A removal failure is a failed scenario, with the failed transaction rolled back.</summary>
    [Fact]
    public void Run_RemovalFailureDoesNotClaimSuccess()
    {
        var state = new PolicyState { FailRemoval = true };
        var evidence = new List<string>();

        Assert.Throws<Win32Exception>(() => CreateScenario(state, evidence).Run(@"C:\VmResults\powershell.exe"));

        Assert.Equal(4, state.Blocks.Count);
        Assert.True(state.Provider);
        Assert.DoesNotContain(evidence, item => item.Contains("complete", StringComparison.Ordinal));
    }

    /// <summary>Creates a scenario whose sessions share only in-memory committed policy state.</summary>
    private static WfpVmLifecycle CreateScenario(PolicyState state, List<string> evidence) =>
        new(() => new FakeSession(state, false), () => new FakeSession(state, true), evidence.Add);

    /// <summary>Stores fake committed objects and observable test events.</summary>
    private sealed class PolicyState
    {
        /// <summary>Gets or sets the provider's presence independently of the sublayer.</summary>
        internal bool Provider { get; set; }

        /// <summary>Gets or sets the sublayer's presence independently of the provider.</summary>
        internal bool SubLayer { get; set; }

        /// <summary>Gets or sets whether committed permits still exist.</summary>
        internal bool Permit { get; set; }

        /// <summary>Gets or sets how many permit filters were created.</summary>
        internal int CreatedPermits { get; set; }

        /// <summary>Gets or sets the number of removal requests.</summary>
        internal int Removals { get; set; }

        /// <summary>Gets committed baseline filters.</summary>
        internal Dictionary<Guid, WfpBlockRule> Blocks { get; } = [];

        /// <summary>Gets mutation events in execution order.</summary>
        internal List<string> Events { get; } = [];

        /// <summary>Gets whether dynamic session closure reports an error.</summary>
        internal bool FailPermitClose { get; init; }

        /// <summary>Gets whether container deletion reports an error.</summary>
        internal bool FailRemoval { get; init; }
    }

    /// <summary>Implements the existing native boundary using staged dictionaries and no operating-system calls.</summary>
    private sealed class FakeSession : IWfpSession
    {
        private readonly PolicyState _state;
        private Dictionary<Guid, WfpBlockRule> _pending = [];
        private bool _provider;
        private bool _subLayer;
        private bool _readOnly;
        private int _permits;

        /// <summary>Creates a separately owned management or dynamic session.</summary>
        internal FakeSession(PolicyState state, bool dynamic)
        {
            _state = state;
            IsDynamic = dynamic;
        }

        /// <inheritdoc />
        public bool IsDynamic { get; }

        /// <inheritdoc />
        public byte[] GetApplicationId(string executablePath) => Encoding.Unicode.GetBytes(executablePath.ToLowerInvariant());

        /// <inheritdoc />
        public void BeginTransaction(bool readOnly)
        {
            _readOnly = readOnly;
            _pending = new(_state.Blocks);
            _provider = _state.Provider;
            _subLayer = _state.SubLayer;
        }

        /// <inheritdoc />
        public bool HasPolicyContainers() => _provider || _subLayer;

        /// <inheritdoc />
        public bool HasPolicyOwner() => _provider && _subLayer;

        /// <inheritdoc />
        public void EnsurePolicyOwner()
        {
            _state.Events.Add("install");
            _provider = true;
            _subLayer = true;
        }

        /// <inheritdoc />
        public void EnsureBlock(WfpBlockRule rule) => _pending[rule.Key] = rule;

        /// <inheritdoc />
        public bool IsBlockPresent(WfpBlockRule rule) => _pending.ContainsKey(rule.Key);

        /// <inheritdoc />
        public void AddPermitFor(WfpBlockRule baseline) => _permits++;

        /// <inheritdoc />
        public IReadOnlyList<WfpBlockRule> GetBlocksForUninstall()
        {
            if (_state.Permit)
            {
                throw new InvalidOperationException("Active permits prevent uninstall.");
            }
            return _pending.Values.ToArray();
        }

        /// <inheritdoc />
        public void RemoveBlock(WfpBlockRule rule) => _pending.Remove(rule.Key);

        /// <inheritdoc />
        public void RemovePolicyOwner()
        {
            _state.Events.Add("remove");
            if (_state.FailRemoval)
            {
                throw new Win32Exception(5, "remove failed");
            }
            _provider = false;
            _subLayer = false;
            _state.Removals++;
        }

        /// <inheritdoc />
        public void CommitTransaction()
        {
            if (_readOnly)
            {
                return;
            }
            _state.Blocks.Clear();
            foreach (var pair in _pending)
            {
                _state.Blocks.Add(pair.Key, pair.Value);
            }
            _state.Provider = _provider;
            _state.SubLayer = _subLayer;
            if (IsDynamic)
            {
                _state.Permit = _permits > 0;
                _state.CreatedPermits += _permits;
            }
        }

        /// <inheritdoc />
        public void AbortTransaction() => _pending.Clear();

        /// <inheritdoc />
        public void Dispose()
        {
            if (IsDynamic)
            {
                _state.Events.Add("permit-close");
                if (_state.FailPermitClose)
                {
                    throw new Win32Exception(5, "permit-close failed");
                }
                _state.Permit = false;
            }
        }
    }
}
