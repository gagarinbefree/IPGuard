using System.Net;
using System.Security.Cryptography;
using System.Text;
using IPGuard.Application.GeoIp;
using IPGuard.Infrastructure.GeoIp;
using Xunit;

namespace IntegrationTests;

/// <summary>Checks real staged MMDB validation and filesystem publication using only synthetic data.</summary>
public sealed class GeoIpDatabaseUpdaterTests
{
    private static readonly TimeSpan MaximumAge = TimeSpan.FromDays(45);

    /// <summary>A missing database is installed with its original build timestamp and exact validated identity.</summary>
    [Fact]
    public async Task UpdateAsync_FirstInstall_PublishesValidatedFile()
    {
        using var files = new TestFiles();
        var updater = files.Updater(files.Bytes);

        GeoIpUpdateResult result = await updater.UpdateAsync(TestContext.Current.CancellationToken);

        Assert.True(result.Changed);
        Assert.Equal(files.BuiltAt, result.Info.BuiltAt);
        Assert.Equal(files.BuiltAt + MaximumAge, result.Info.ValidUntil);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(files.Bytes)), result.Info.Sha256);
        Assert.Equal(files.Bytes, File.ReadAllBytes(files.Active));
        files.AssertNoStagingFiles();
    }

    /// <summary>A newer validated file replaces the active path while already loaded snapshots remain immutable.</summary>
    [Fact]
    public async Task UpdateAsync_NewerBuild_ReplacesFileWithoutChangingLiveSnapshot()
    {
        using var files = new TestFiles();
        File.WriteAllBytes(files.Active, files.Bytes);
        using var previous = MmdbCountryDatabase.Open(files.Active, MaximumAge);
        byte[] candidate = files.WithBuildOffset(1);

        GeoIpUpdateResult result = await files.Updater(candidate).UpdateAsync(TestContext.Current.CancellationToken);

        Assert.True(result.Changed);
        Assert.Equal(files.BuiltAt.AddDays(1), result.Info.BuiltAt);
        Assert.Equal(files.BuiltAt, previous.Info.BuiltAt);
        Assert.Equal("US", previous.Lookup(IPAddress.Parse("149.101.100.1"), files.Now).Evidence.CountryCode);
        Assert.Equal(candidate, File.ReadAllBytes(files.Active));
        files.AssertNoStagingFiles();
    }

    /// <summary>Identical bytes return unchanged without rewriting or refreshing the active file.</summary>
    [Fact]
    public async Task UpdateAsync_IdenticalBuild_DoesNotRefreshFile()
    {
        using var files = new TestFiles();
        File.WriteAllBytes(files.Active, files.Bytes);
        File.SetLastWriteTimeUtc(files.Active, DateTime.UtcNow.AddDays(-10));
        DateTime oldTimestamp = File.GetLastWriteTimeUtc(files.Active);

        GeoIpUpdateResult result = await files.Updater(files.Bytes).UpdateAsync(TestContext.Current.CancellationToken);

        Assert.False(result.Changed);
        Assert.Equal(oldTimestamp, File.GetLastWriteTimeUtc(files.Active));
        Assert.Equal(files.BuiltAt + MaximumAge, result.Info.ValidUntil);
        files.AssertNoStagingFiles();
    }

    /// <summary>Rollback, same-date conflicts, malformed bytes, and a different product leave the active file untouched.</summary>
    [Theory]
    [InlineData("older")]
    [InlineData("conflict")]
    [InlineData("corrupt")]
    [InlineData("empty")]
    [InlineData("product")]
    public async Task UpdateAsync_InvalidCandidate_PreservesActiveFile(string invalid)
    {
        using var files = new TestFiles();
        File.WriteAllBytes(files.Active, files.Bytes);
        byte[] candidate = invalid switch
        {
            "older" => files.WithBuildOffset(-1),
            "conflict" => files.WithDifferentContent(),
            "corrupt" => [1, 2, 3],
            "empty" => [],
            _ => files.Bytes
        };
        var updater = files.Updater(candidate, product: invalid == "product" ? "DBIP-Country-Lite" : "GeoIP2-Country");

        await Assert.ThrowsAsync<InvalidDataException>(() => updater.UpdateAsync(TestContext.Current.CancellationToken));

        Assert.Equal(files.Bytes, File.ReadAllBytes(files.Active));
        files.AssertNoStagingFiles();
    }

    /// <summary>Expired or future metadata cannot initialize an absent active database.</summary>
    [Theory]
    [InlineData(-50)]
    [InlineData(3)]
    public async Task UpdateAsync_InvalidFreshness_DoesNotPublish(int offset)
    {
        using var files = new TestFiles();

        await Assert.ThrowsAsync<InvalidDataException>(() => files.Updater(files.WithBuildOffset(offset))
            .UpdateAsync(TestContext.Current.CancellationToken));

        Assert.False(File.Exists(files.Active));
        files.AssertNoStagingFiles();
    }

    /// <summary>Partial writes followed by cancellation or transport failure never replace a complete database.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UpdateAsync_InterruptedDownload_RemovesOnlyStagedBytes(bool cancel)
    {
        using var files = new TestFiles();
        File.WriteAllBytes(files.Active, files.Bytes);
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var error = new IOException("Interrupted provider transfer");
        var download = new FakeDownload(async (destination, _, token) =>
        {
            await destination.WriteAsync(files.Bytes.AsMemory(0, 100), token);
            if (cancel)
            {
                caller.Cancel();
                token.ThrowIfCancellationRequested();
            }
            throw error;
        });
        var updater = new GeoIpDatabaseUpdater(files.Active, download, MaximumAge, () => files.Now);

        if (cancel)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => updater.UpdateAsync(caller.Token));
        }
        else
        {
            Assert.Same(error, await Assert.ThrowsAsync<IOException>(() => updater.UpdateAsync(caller.Token)));
        }

        Assert.Equal(files.Bytes, File.ReadAllBytes(files.Active));
        files.AssertNoStagingFiles();
    }

    /// <summary>Freshness is checked again at publication and a backward clock cannot make evidence younger.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UpdateAsync_TimeChangesDuringDownload_DoesNotPublish(bool rollback)
    {
        using var files = new TestFiles();
        int reads = 0;
        Func<DateTimeOffset> clock = () => ++reads == 1 ? files.Now : rollback ? files.Now.AddSeconds(-1) : files.BuiltAt + MaximumAge;

        await Assert.ThrowsAsync<InvalidDataException>(() => files.Updater(files.Bytes, clock)
            .UpdateAsync(TestContext.Current.CancellationToken));

        Assert.False(File.Exists(files.Active));
        files.AssertNoStagingFiles();
    }

    /// <summary>Cancellation at the final clock check stops publication; no incomplete success is reported.</summary>
    [Fact]
    public async Task UpdateAsync_CancelBeforeRename_PreservesActiveFile()
    {
        using var files = new TestFiles();
        File.WriteAllBytes(files.Active, files.Bytes);
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        int reads = 0;
        Func<DateTimeOffset> clock = () =>
        {
            if (++reads > 1) caller.Cancel();
            return files.Now;
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => files.Updater(files.WithBuildOffset(1), clock).UpdateAsync(caller.Token));

        Assert.Equal(files.Bytes, File.ReadAllBytes(files.Active));
        files.AssertNoStagingFiles();
    }

    /// <summary>A target opened without delete sharing makes rename fail without truncating the current database.</summary>
    [Fact]
    public async Task UpdateAsync_ActiveFileLocked_PreservesCompleteDatabase()
    {
        using var files = new TestFiles();
        File.WriteAllBytes(files.Active, files.Bytes);
        using (var held = new FileStream(files.Active, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            Exception? error = await Record.ExceptionAsync(() => files.Updater(files.WithBuildOffset(1))
                .UpdateAsync(TestContext.Current.CancellationToken));
            Assert.True(error is IOException or UnauthorizedAccessException, $"Expected a filesystem refusal, received {error}");
            Assert.Equal(files.Bytes, File.ReadAllBytes(files.Active));
        }
        files.AssertNoStagingFiles();
    }

    /// <summary>A persistent lock file serializes separate updater instances before they download anything.</summary>
    [Fact]
    public async Task UpdateAsync_ConcurrentWriter_IsRejected()
    {
        using var files = new TestFiles();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var download = new FakeDownload(async (destination, _, token) =>
        {
            entered.SetResult();
            await resume.Task.WaitAsync(token);
            await destination.WriteAsync(files.Bytes, token);
        });
        Task<GeoIpUpdateResult> first = new GeoIpDatabaseUpdater(files.Active, download, MaximumAge, () => files.Now)
            .UpdateAsync(TestContext.Current.CancellationToken);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            await Assert.ThrowsAsync<IOException>(() => files.Updater(files.Bytes).UpdateAsync(TestContext.Current.CancellationToken));
        }
        finally
        {
            resume.TrySetResult();
            await first;
        }
        files.AssertNoStagingFiles();
    }

    /// <summary>A corrupt baseline cannot silently discard the rollback floor or trigger a provider request.</summary>
    [Fact]
    public async Task UpdateAsync_CorruptActiveFile_RequiresExplicitRecovery()
    {
        using var files = new TestFiles();
        File.WriteAllText(files.Active, "corrupt baseline");
        var download = new FakeDownload((_, _, _) => throw new InvalidOperationException("Must not download"));

        await Assert.ThrowsAsync<InvalidDataException>(() => new GeoIpDatabaseUpdater(files.Active, download, MaximumAge, () => files.Now)
            .UpdateAsync(TestContext.Current.CancellationToken));

        Assert.Equal("corrupt baseline", File.ReadAllText(files.Active));
        files.AssertNoStagingFiles();
    }

    /// <summary>A writer ignoring the update lock cannot be silently overwritten after changing the baseline.</summary>
    [Fact]
    public async Task UpdateAsync_ActiveFileChangedDuringDownload_DetectsConflict()
    {
        using var files = new TestFiles();
        File.WriteAllBytes(files.Active, files.Bytes);
        byte[] changed = files.WithBuildOffset(1);
        var download = new FakeDownload(async (destination, _, token) =>
        {
            File.WriteAllBytes(files.Active, changed);
            await destination.WriteAsync(files.WithBuildOffset(2), token);
        });

        await Assert.ThrowsAsync<InvalidDataException>(() => new GeoIpDatabaseUpdater(files.Active, download, MaximumAge, () => files.Now)
            .UpdateAsync(TestContext.Current.CancellationToken));

        Assert.Equal(changed, File.ReadAllBytes(files.Active));
        files.AssertNoStagingFiles();
    }

    /// <summary>A cancelled call creates neither a lock file nor a staged file.</summary>
    [Fact]
    public async Task UpdateAsync_PreCancelled_DoesNotTouchDirectory()
    {
        using var files = new TestFiles();
        using var caller = new CancellationTokenSource();
        caller.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => files.Updater(files.Bytes).UpdateAsync(caller.Token));

        Assert.Empty(Directory.GetFiles(files.DirectoryPath));
    }

    /// <summary>Cleanup does not remove abandoned stages or unrelated files owned by another operation.</summary>
    [Fact]
    public async Task UpdateAsync_UnrelatedFile_IsPreserved()
    {
        using var files = new TestFiles();
        string abandoned = Path.Combine(files.DirectoryPath, ".country.mmdb.previous.download");
        File.WriteAllText(abandoned, "leave this file alone");

        await files.Updater(files.Bytes).UpdateAsync(TestContext.Current.CancellationToken);

        Assert.Equal("leave this file alone", File.ReadAllText(abandoned));
    }

    /// <summary>Provides complete synthetic bytes while preserving the real updater's disk operations.</summary>
    private sealed class FakeDownload : IGeoIpDatabaseDownload
    {
        private readonly Func<Stream, DateTimeOffset, CancellationToken, Task> download;

        /// <summary>Captures a controlled transfer and its expected product identity.</summary>
        internal FakeDownload(Func<Stream, DateTimeOffset, CancellationToken, Task> download, string product = "GeoIP2-Country")
        {
            this.download = download;
            DatabaseType = product;
        }

        /// <summary>Gets the product expected from this synthetic provider.</summary>
        public string DatabaseType { get; }

        /// <summary>Writes the configured bytes or simulates an interrupted transfer.</summary>
        public Task DownloadAsync(Stream destination, DateTimeOffset now, CancellationToken cancellationToken) =>
            download(destination, now, cancellationToken);
    }

    /// <summary>Owns only a unique temporary directory containing synthetic database files.</summary>
    private sealed class TestFiles : IDisposable
    {
        /// <summary>Loads the pinned synthetic fixture and creates an empty private test directory.</summary>
        internal TestFiles()
        {
            DirectoryPath = Path.Combine(Path.GetTempPath(), $"ipguard-update-{Guid.NewGuid():N}");
            Directory.CreateDirectory(DirectoryPath);
            string fixture = Path.Combine(AppContext.BaseDirectory, "GeoIp", "GeoIP2-Country-Test.mmdb");
            Bytes = File.ReadAllBytes(fixture);
            using var database = MmdbCountryDatabase.Open(fixture, MaximumAge);
            BuiltAt = database.Info.BuiltAt;
        }

        /// <summary>Gets the uniquely owned test directory.</summary>
        internal string DirectoryPath { get; }

        /// <summary>Gets the active database path; no production paths are used.</summary>
        internal string Active => Path.Combine(DirectoryPath, "country.mmdb");

        /// <summary>Gets the original licensed synthetic bytes.</summary>
        internal byte[] Bytes { get; }

        /// <summary>Gets the build epoch actually decoded from the fixture.</summary>
        internal DateTimeOffset BuiltAt { get; }

        /// <summary>Gets a fixed fresh test time compatible with the fixture.</summary>
        internal DateTimeOffset Now => BuiltAt.AddDays(2);

        /// <summary>Composes the real updater with a synthetic provider.</summary>
        internal GeoIpDatabaseUpdater Updater(byte[] bytes, Func<DateTimeOffset>? clock = null, string product = "GeoIP2-Country") =>
            new(Active, new FakeDownload((destination, _, token) => destination.WriteAsync(bytes, token).AsTask(), product), MaximumAge, clock ?? (() => Now));

        /// <summary>Adjusts only the pinned fixture's encoded build_epoch to exercise freshness and rollback.</summary>
        internal byte[] WithBuildOffset(int days)
        {
            byte[] result = Bytes.ToArray();
            int position = result.AsSpan().LastIndexOf(Encoding.ASCII.GetBytes("build_epoch")) + "build_epoch".Length;
            byte control = result[position++];
            Assert.Equal(0, control >> 5);
            Assert.Equal(2, result[position++]); // MMDB extended type 9 is uint64.
            int width = control & 31;
            Assert.InRange(width, 1, 8);
            ulong epoch = checked((ulong)BuiltAt.AddDays(days).ToUnixTimeSeconds());
            for (int index = width - 1; index >= 0; index--)
            {
                result[position + index] = (byte)epoch;
                epoch >>= 8;
            }
            Assert.Equal(0UL, epoch);
            return result;
        }

        /// <summary>Changes a country display name without changing metadata or the validity of MMDB encoding.</summary>
        internal byte[] WithDifferentContent()
        {
            byte[] result = Bytes.ToArray();
            int position = result.AsSpan().IndexOf(Encoding.UTF8.GetBytes("United States"));
            Assert.True(position >= 0);
            result[position] = (byte)'u';
            return result;
        }

        /// <summary>Ensures the updater removed its own stage while allowing the persistent coordination lock.</summary>
        internal void AssertNoStagingFiles() => Assert.All(Directory.GetFiles(DirectoryPath),
            file => Assert.Contains(Path.GetFileName(file), new[] { "country.mmdb", "country.mmdb.update.lock" }));

        /// <summary>Deletes individually created files and then the empty directory, without recursive traversal.</summary>
        public void Dispose()
        {
            foreach (string file in Directory.GetFiles(DirectoryPath)) File.Delete(file);
            Directory.Delete(DirectoryPath);
        }
    }
}
