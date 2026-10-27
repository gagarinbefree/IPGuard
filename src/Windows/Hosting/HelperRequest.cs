using System.Globalization;
using IPGuard.Windows.Control;

namespace IPGuard.Windows.Hosting;

/// <summary>Defines the only supported privileged entry arguments, without policy paths or operations.</summary>
public sealed class HelperRequest
{
    /// <summary>Captures a validated local endpoint and GUI process identifier.</summary>
    private HelperRequest(string pipeName, int parentId) { PipeName = pipeName; ParentId = parentId; }
    /// <summary>Gets the generated endpoint owned by the expected GUI.</summary>
    public string PipeName { get; }
    /// <summary>Gets the GUI process to retain and authenticate before serving commands.</summary>
    public int ParentId { get; }
    /// <summary>Rejects missing, duplicate, extra, remote, or policy-bearing arguments.</summary>
    public static HelperRequest Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Count != 5 || args[0] != "--helper" || args[1] != "--pipe" || args[3] != "--parent" ||
            !int.TryParse(args[4], NumberStyles.None, CultureInfo.InvariantCulture, out var parent) || parent <= 0)
            throw new ArgumentException("Expected --helper --pipe <generated-name> --parent <positive-pid>.", nameof(args));
        WindowsControlPipe.ValidateName(args[2]);
        return new(args[2], parent);
    }
}
