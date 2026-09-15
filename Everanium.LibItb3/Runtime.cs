// Process-wide Go runtime knobs plus the library version string.

namespace Everanium.Itb3;

/// <summary>Static accessors for the libitb3 process-wide Go runtime
/// knobs and the library version.</summary>
public static class Runtime
{
    /// <summary>The binding's own version.</summary>
    public const string BindingVersion = "0.5.1";

    /// <summary>Sets the Go runtime's soft heap limit in bytes and
    /// returns the previous limit. A negative value queries without
    /// changing.</summary>
    public static long SetMemoryLimit(long bytes) => NativeMethods.ITB_SetMemoryLimit(bytes);

    /// <summary>Sets the Go GC trigger percentage and returns the
    /// previous value. A negative value queries without
    /// changing.</summary>
    public static int SetGCPercent(int pct) => NativeMethods.ITB_SetGCPercent(pct);

    /// <summary>Returns the libitb3 library version string.</summary>
    public static string Version() => NativeMethods.VersionString();
}
