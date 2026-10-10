// Process-wide Go runtime knobs, runtime diagnostics, and the library
// version string.

namespace Everanium.Itb3;

/// <summary>Static accessors for the libitb3 process-wide Go runtime
/// knobs, its runtime diagnostics, and the library version.</summary>
public static unsafe class Runtime
{
    /// <summary>The binding's own version.</summary>
    public const string BindingVersion = "0.5.5";

    /// <summary>Sets the Go runtime's soft heap limit in bytes and
    /// returns the previous limit. A negative value queries without
    /// changing.</summary>
    public static long SetMemoryLimit(long bytes) => NativeMethods.ITB_SetMemoryLimit(bytes);

    /// <summary>Sets the Go GC trigger percentage and returns the
    /// previous value. A negative value queries without
    /// changing.</summary>
    public static int SetGCPercent(int pct) => NativeMethods.ITB_SetGCPercent(pct);

    /// <summary>Sets the Go runtime's GOMAXPROCS and returns the
    /// previous value. Zero or a negative value queries without
    /// changing.</summary>
    public static int SetGOMAXPROCS(int n) => NativeMethods.ITB_SetGOMAXPROCS(n);

    /// <summary>
    /// Writes the Go runtime's heap profile (pprof format) to
    /// <paramref name="path"/> after one forced garbage collection. An
    /// empty path falls back to the <c>ITB_MEMPROFILE</c> environment
    /// variable inside libitb3; a path that is still empty, or a
    /// file-system failure, throws with
    /// <see cref="Status.BadInput"/>.
    /// </summary>
    public static void WriteHeapProfile(string path)
    {
        ItbException.Check(NativeMethods.ITB_WriteHeapProfile(path));
    }

    /// <summary>The number of <see cref="long"/> slots
    /// <see cref="PoolStats"/> fills.</summary>
    public static int PoolStatsLen()
    {
        int n = NativeMethods.ITB_PoolStatsLen();
        return n > 0 ? n : 0;
    }

    /// <summary>
    /// One snapshot of the library's pool hit / miss counters. Every
    /// counter is a monotonically increasing total since library load,
    /// so a per-window figure is the difference of two snapshots.
    ///
    /// Slot layout, with <c>T</c> the tier count in slot 0: hash-array
    /// tier <c>i</c> holds starter width, checkouts, constructor
    /// misses, regrow replacements and bytes allocated at slots
    /// <c>1 + 5*i .. 1 + 5*i + 4</c>; the scratch byte pool's get /
    /// new / regrow / regrow-bytes follow at <c>1 + 5*T</c>, and the
    /// parallax chunk pool's at <c>1 + 5*T + 4</c>. The buffer is
    /// sized from <see cref="PoolStatsLen"/>, never from a constant —
    /// the tier ladder is a library-side policy that grows.
    /// </summary>
    public static long[] PoolStats()
    {
        var buf = new long[PoolStatsLen()];
        nuint written;
        int rc;
        fixed (long* p = buf)
        {
            rc = NativeMethods.ITB_PoolStats(p, (nuint)buf.Length, out written);
        }
        ItbException.Check(rc);
        int n = checked((int)written);
        return n == buf.Length ? buf : buf[..n];
    }

    /// <summary>Returns the libitb3 library version string.</summary>
    public static string Version() => NativeMethods.VersionString();

    /// <summary>Returns the fill cipher the auto DRBG tier selected on
    /// this host (<c>"aes-256-ctr"</c> or <c>"chacha20"</c>): the tier
    /// a Pipeline uses when its <c>drbg</c> option is empty, resolved
    /// per host and recorded in no blob.</summary>
    public static string DrbgAutoTier() => NativeMethods.DrbgAutoTierString();
}
