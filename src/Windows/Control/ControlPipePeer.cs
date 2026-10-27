using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace IPGuard.Windows.Control;

/// <summary>Compares kernel-reported pipe process identifiers with a caller-retained live process.</summary>
internal static class ControlPipePeer
{
    /// <summary>Retains the process handle before waiting and rejects a peer that has already exited.</summary>
    internal static void RequireLive(Process expected)
    {
        if (expected.HasExited) throw new UnauthorizedAccessException("The expected control process has exited.");
        _ = expected.Handle;
        if (expected.HasExited) throw new UnauthorizedAccessException("The expected control process has exited.");
    }

    /// <summary>Rejects an unexpected client process without consuming any client data.</summary>
    internal static void VerifyClient(NamedPipeServerStream pipe, Process expected)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var id)) throw new Win32Exception(Marshal.GetLastWin32Error());
        Verify(expected, id);
    }

    /// <summary>Rejects an unexpected server process before sending the version marker.</summary>
    internal static void VerifyServer(NamedPipeClientStream pipe, Process expected)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var id)) throw new Win32Exception(Marshal.GetLastWin32Error());
        Verify(expected, id);
    }

    /// <summary>Requires a retained process handle and rejects exit or a different identifier.</summary>
    private static void Verify(Process expected, uint actual)
    {
        RequireLive(expected);
        if (actual != (uint)expected.Id)
            throw new UnauthorizedAccessException("The control pipe peer is not the expected live process.");
    }

    /// <summary>Reads the client PID recorded by Windows for this pipe connection.</summary>
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);

    /// <summary>Reads the server PID recorded by Windows for this pipe connection.</summary>
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
}
