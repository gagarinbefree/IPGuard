using Xunit;

namespace IntegrationTests.WfpVm;

/// <summary>Prevents VM policy tests from running alongside other tests in the same process.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class WfpVmCollection
{
    /// <summary>Names the collection sharing the native policy namespace.</summary>
    public const string Name = "WFP VM policy";
}
