// Exception type shared by every fallible call in the binding.

namespace Itb;

/// <summary>
/// Raised when libitb returns a non-OK status. <see cref="Status"/>
/// carries the structural code; <see cref="Exception.Message"/>
/// appends the <c>ITB_LastError</c> diagnostic captured immediately
/// after the failing call (process-global last-write-wins — the
/// message may belong to a different call under concurrent FFI use;
/// the status code is always attributable).
/// </summary>
public sealed class ItbException : Exception
{
    /// <summary>The libitb status code for the failing call.</summary>
    public Status Status { get; }

    public ItbException(Status status, string? message = null)
        : base(Format(status, message))
    {
        Status = status;
    }

    private static string Format(Status status, string? message)
    {
        return string.IsNullOrEmpty(message)
            ? $"itb: status={(int)status} ({status})"
            : $"itb: status={(int)status} ({status}): {message}";
    }

    /// <summary>Builds an <see cref="ItbException"/> from a raw return
    /// code, pulling the <c>ITB_LastError</c> diagnostic at
    /// construction time.</summary>
    internal static ItbException FromRc(int rc)
    {
        return new ItbException((Status)rc, NativeMethods.ReadLastError());
    }

    /// <summary>Throws when <paramref name="rc"/> is non-OK; otherwise
    /// returns.</summary>
    internal static void Check(int rc)
    {
        if (rc != (int)Status.Ok)
        {
            throw FromRc(rc);
        }
    }
}
