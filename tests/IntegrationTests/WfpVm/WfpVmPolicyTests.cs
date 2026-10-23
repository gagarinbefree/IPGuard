using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using IPGuard.Windows.Filtering;
using Microsoft.Win32;
using Xunit;

namespace IntegrationTests.WfpVm;

/// <summary>Runs real WFP object operations only after explicit isolated-VM authorization.</summary>
[Collection(WfpVmCollection.Name)]
public sealed class WfpVmPolicyTests
{
    private readonly ITestOutputHelper _output;

    /// <summary>Receives the xUnit evidence sink without opening any native session.</summary>
    public WfpVmPolicyTests(ITestOutputHelper output) => _output = output;

    /// <summary>Checks stored object lifecycle using a private PowerShell copy; it does not test packet enforcement.</summary>
    [Fact]
    [Trait("Category", "WfpVm")]
    public void PolicyObjects_CompleteRoundTrip() => WfpVmGate.RunCurrent(RunNativeScenario);

    /// <summary>Serializes real VM runs, preserves evidence, and never targets the system PowerShell executable.</summary>
    private void RunNativeScenario()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The native VM scenario requires Windows.");
        }

        using var mutex = new Mutex(false, $"Global\\IPGuard.WfpVm.{WfpPolicyIds.Provider:N}");
        bool acquired = false;
        try
        {
            try
            {
                acquired = mutex.WaitOne(0);
            }
            catch (AbandonedMutexException error)
            {
                acquired = true;
                throw new InvalidOperationException("A previous VM test was abandoned. Restore the checkpoint before another run.", error);
            }
            if (!acquired)
            {
                throw new InvalidOperationException("Another WFP VM test owns this policy namespace.");
            }

            string root = Environment.GetEnvironmentVariable(WfpVmGate.ResultsVariable)
                ?? throw new InvalidOperationException("The authorized VM results directory is missing.");
            string directory = Path.Combine(root, "objects-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            string source = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            string target = Path.Combine(directory, "powershell.exe");
            File.Copy(source, target, overwrite: false);
            string journal = Path.Combine(directory, "journal.jsonl");
            using var versionKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            Record(journal, JsonSerializer.Serialize(new
            {
                utc = DateTimeOffset.UtcNow,
                phase = "environment",
                machine = Environment.MachineName,
                snapshot = Environment.GetEnvironmentVariable(WfpVmGate.SnapshotVariable),
                os = RuntimeInformation.OSDescription,
                edition = versionKey?.GetValue("EditionID")?.ToString() ?? "unknown",
                runtime = RuntimeInformation.FrameworkDescription,
                architecture = RuntimeInformation.ProcessArchitecture.ToString(),
                version = typeof(WfpBlockPolicy).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
                source,
                target,
                executableSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(target))),
                provider = WfpPolicyIds.Provider,
                subLayer = WfpPolicyIds.SubLayer,
                scope = "Object lifecycle only; no packet enforcement assertions."
            }));

            var scenario = new WfpVmLifecycle(NativeWfpSession.Open, NativeWfpSession.OpenDynamic, line =>
            {
                Record(journal, line);
                WfpVmEvidence.RecordFilters(snapshot => Record(journal, snapshot));
            });
            try
            {
                scenario.Run(target);
            }
            catch (Exception error)
            {
                try
                {
                    Record(journal, JsonSerializer.Serialize(new { utc = DateTimeOffset.UtcNow, phase = "failed", error = error.ToString(), recovery = "Export evidence and restore the VM checkpoint." }));
                }
                catch (Exception journalError)
                {
                    throw new AggregateException("The VM scenario failed and its failure journal could not be written.", error, journalError);
                }
                throw;
            }
        }
        finally
        {
            if (acquired)
            {
                mutex.ReleaseMutex();
            }
        }
    }

    /// <summary>Persists each event in the VM artifacts and the TRX test output.</summary>
    private void Record(string journal, string line)
    {
        File.AppendAllText(journal, line + Environment.NewLine);
        _output.WriteLine(line);
    }
}
