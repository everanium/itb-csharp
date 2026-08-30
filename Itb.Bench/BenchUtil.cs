// Shared timing + reporting helpers for the C# binding
// micro-benchmarks. Wall-clock via Stopwatch; output is a
// fixed-width table:
//
//   bench             size     mb_per_sec
//   message           1 MiB    <n>
//   ...
//
// Bench configuration is driven by environment variables so a
// side-by-side comparison with the root Go bench harness is
// straightforward:
//
//   ITB_NONCE_BITS     nonce width (default 512)
//   ITB_KEY_BITS       key bits (default 1024)
//   ITB_WITH_PARALLAX  parallax layer on/off (default false)
//   ITB_WITH_WRAPPER   wrapper layer on/off (default false)
//   ITB_INNER_HASH     opaque hash name (default: profile's)
//   ITB_PROFILE        profile name override
//   ITB_BENCH_MIN_SEC  per-case wall-clock budget (default 5.0)

using System.Diagnostics;
using System.Globalization;

namespace Itb.Bench;

internal static class BenchUtil
{
    /// <summary>Iteration floor per case.</summary>
    private const int MinIters = 3;

    /// <summary>Payload sizes exercised by both shapes.</summary>
    internal static readonly int[] Sizes = [1 << 20, 16 << 20, 64 << 20];

    internal static double MinSeconds()
    {
        var raw = Environment.GetEnvironmentVariable("ITB_BENCH_MIN_SEC");
        if (!string.IsNullOrEmpty(raw)
            && double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var v)
            && v > 0.0)
        {
            return v;
        }
        return 5.0;
    }

    /// <summary>Reads the bench-shape env vars and builds an
    /// <see cref="Opts"/>. Defaults match root Go BENCH3.md so
    /// numbers are directly comparable.</summary>
    internal static Opts BuildOpts()
    {
        var opts = new Opts()
            .WithNonceBits(EnvLong("ITB_NONCE_BITS", 512))
            .WithKeyBits(EnvLong("ITB_KEY_BITS", 1024))
            .WithParallax(EnvBool("ITB_WITH_PARALLAX"))
            .WithWrapper(EnvBool("ITB_WITH_WRAPPER"));
        var innerHash = Environment.GetEnvironmentVariable("ITB_INNER_HASH");
        if (!string.IsNullOrEmpty(innerHash))
        {
            opts = opts.WithInnerHash(innerHash);
        }
        var macName = Environment.GetEnvironmentVariable("ITB_MAC_NAME");
        if (!string.IsNullOrEmpty(macName))
        {
            opts = opts.WithMacName(macName);
        }
        return opts;
    }

    internal static string ProfileName(string fallback)
    {
        var env = Environment.GetEnvironmentVariable("ITB_PROFILE");
        return string.IsNullOrEmpty(env) ? fallback : env;
    }

    internal static void Header()
    {
        Console.WriteLine($"{"bench",-17} {"size",-8} mb_per_sec");
    }

    private static string SizeLabel(int size)
    {
        return size >= (1 << 20) ? $"{size >> 20} MiB" : $"{size >> 10} KiB";
    }

    /// <summary>Runs <paramref name="run"/> until the wall-clock
    /// budget is spent (with an iteration floor + one untimed
    /// warm-up), then prints one table row.</summary>
    internal static void Case(string name, int size, Action run)
    {
        run(); // warm-up
        double budget = MinSeconds();
        var clock = Stopwatch.StartNew();
        long iters = 0;
        while (clock.Elapsed.TotalSeconds < budget || iters < MinIters)
        {
            run();
            iters++;
        }
        double elapsed = clock.Elapsed.TotalSeconds;
        double mb = (double)size * iters / (1024.0 * 1024.0);
        Console.WriteLine(FormattableString.Invariant(
            $"{name,-17} {SizeLabel(size),-8} {mb / elapsed:F1}"));
    }

    private static long EnvLong(string name, long fallback)
    {
        var raw = Environment.GetEnvironmentVariable(name);
        return !string.IsNullOrEmpty(raw) && long.TryParse(raw, out var v) ? v : fallback;
    }

    private static bool EnvBool(string name)
    {
        var raw = Environment.GetEnvironmentVariable(name);
        return raw is "true" or "1";
    }
}
