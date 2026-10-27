namespace IPGuard.Application.Network;

/// <summary>Exposes cached diagnostic state and refresh requests to an application coordinator.</summary>
/// <remarks>The composing host owns this reader's lifetime and scheduling.</remarks>
public interface INetworkDiagnosticsReader
{
    /// <summary>Returns only generation-bound, unexpired observations without performing OS or network I/O.</summary>
    NetworkDiagnosticsObservation? Capture();

    /// <summary>Retires previous observations before requesting background collection.</summary>
    void Refresh();

    /// <summary>Gets the latest attempt's outcome, independently of current observation availability.</summary>
    NetworkDiagnosticsStatus? LastStatus { get; }

    /// <summary>Gets unavailable outcome details, which are diagnostic history rather than usable evidence.</summary>
    NetworkDiagnosticsResult? LastFailure { get; }

    /// <summary>Gets operational or consumer callback failures requiring a conservative application decision.</summary>
    Exception? LastError { get; }
}
