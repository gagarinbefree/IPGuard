using IPGuard.Application.GeoIp;

namespace IPGuard.Infrastructure.GeoIp;

/// <summary>Validates a staged local database and publishes it without truncating the active file.</summary>
public sealed class GeoIpDatabaseUpdater
{
    private readonly string path;
    private readonly IGeoIpDatabaseDownload download;
    private readonly string expectedProduct;
    private readonly TimeSpan maximumAge;
    private readonly Func<DateTimeOffset> utcNow;

    /// <summary>Uses an existing trusted local directory, a provider download, and build-based maximum age.</summary>
    public GeoIpDatabaseUpdater(string path, IGeoIpDatabaseDownload download, TimeSpan maximumAge,
        Func<DateTimeOffset>? utcNow = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(download);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maximumAge, TimeSpan.Zero);
        this.path = Path.GetFullPath(path);
        this.download = download;
        expectedProduct = download.DatabaseType;
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedProduct);
        this.maximumAge = maximumAge;
        this.utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Serializes cooperating writers, rejects rollback, and commits with a same-directory rename.</summary>
    public async Task<GeoIpUpdateResult> UpdateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        DateTimeOffset startedAt = utcNow();
        string directory = Path.GetDirectoryName(path)!;
        RejectLinkedDirectories(directory);
        string lockPath = path + ".update.lock";
        RejectLinkedFile(lockPath);
        // Keep the lock file after closing it: deleting it would allow writers to lock different file identities.
        using var ownership = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        GeoIpDatabaseInfo? previous = ReadCurrentInfo();
        string stagedPath = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.download");
        Exception? failure = null;
        bool created = false;
        try
        {
            await using (var staged = new FileStream(stagedPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
                64 * 1024, FileOptions.Asynchronous))
            {
                created = true;
                await WriteCandidateAsync(staged, startedAt, cancellationToken).ConfigureAwait(false);
            }
            GeoIpDatabaseInfo candidate;
            using (var database = MmdbCountryDatabase.Open(stagedPath, maximumAge))
            {
                candidate = database.Info;
            }

            if (candidate.DatabaseType != expectedProduct)
            {
                throw new InvalidDataException("The downloaded database product does not match the configured provider.");
            }
            if (previous is not null && (candidate.BuiltAt < previous.BuiltAt
                || (candidate.BuiltAt == previous.BuiltAt && candidate.Sha256 != previous.Sha256)))
            {
                throw new InvalidDataException("The GeoIP candidate rolls back the build date or conflicts with the same build.");
            }
            if (ReadCurrentInfo()?.Sha256 != previous?.Sha256)
            {
                throw new InvalidDataException("The active GeoIP file changed outside the update lock.");
            }

            DateTimeOffset now = utcNow();
            if (now < startedAt || now < candidate.BuiltAt || now >= candidate.ValidUntil)
            {
                throw new InvalidDataException("The clock moved backward or the GeoIP candidate is not currently fresh.");
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (candidate.Sha256 == previous?.Sha256)
            {
                return new GeoIpUpdateResult(false, candidate);
            }

            // Same-directory rename is the commit point. Never fall back to deleting, copying, or truncating the target.
            File.Move(stagedPath, path, overwrite: true);
            return new GeoIpUpdateResult(true, candidate);
        }
        catch (Exception error)
        {
            failure = error;
            cancellationToken.ThrowIfCancellationRequested();
            throw;
        }
        finally
        {
            try
            {
                if (created)
                {
                    File.Delete(stagedPath);
                }
            }
            catch (Exception cleanupError)
            {
                if (failure is not null)
                {
                    throw new AggregateException("Updating GeoIP and removing its staged file failed.", failure, cleanupError);
                }
                throw;
            }
        }
    }

    /// <summary>Writes only a new private stage, checks its size, and flushes its bytes before validation.</summary>
    private async Task WriteCandidateAsync(FileStream staged, DateTimeOffset startedAt, CancellationToken cancellationToken)
    {
        await download.DownloadAsync(staged, startedAt, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (staged.Length is <= 0 or > GeoIpFileLimits.MaximumDatabaseBytes)
        {
            throw new InvalidDataException("The downloaded MMDB must contain between 1 byte and 64 MiB.");
        }
        await staged.FlushAsync(cancellationToken).ConfigureAwait(false);
        staged.Flush(flushToDisk: true);
    }

    /// <summary>Reads the rollback floor from the active file; corruption requires explicit recovery.</summary>
    private GeoIpDatabaseInfo? ReadCurrentInfo()
    {
        RejectLinkedFile(path);
        try
        {
            using var current = MmdbCountryDatabase.Open(path, maximumAge);
            return current.Info;
        }
        catch (FileNotFoundException)
        {
            // File.Exists also returns false on access errors; only an actually absent file has no rollback floor.
            return null;
        }
    }

    /// <summary>Refuses linked directory components; the caller must still provide a directory protected from other writers.</summary>
    private static void RejectLinkedDirectories(string path)
    {
        for (DirectoryInfo? directory = new(path); directory is not null; directory = directory.Parent)
        {
            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("GeoIP updates require a trusted directory without linked components.");
            }
        }
    }

    /// <summary>Rejects linked active or coordination files, including dangling links.</summary>
    private static void RejectLinkedFile(string path)
    {
        var file = new FileInfo(path);
        if (file.LinkTarget is not null || (file.Exists && (file.Attributes & FileAttributes.ReparsePoint) != 0))
        {
            throw new InvalidDataException("GeoIP update files must not be links or reparse points.");
        }
    }
}
