// Shared scaffolding for the C# Easy Mode benchmark harness.
//
// The harness mirrors the Go ``testing.B`` benchmark style on the
// itb_ext_test.go / itb3_ext_test.go side: each bench case runs a
// short warm-up batch to reach steady state, then a measured batch
// whose total wall-clock time is divided by the iteration count to
// produce the canonical ``ns/op`` throughput line. The output line
// also carries an MB/s figure derived from the configured payload
// size, matching the Go reporter's ``-benchmem``-less default.
//
// Environment variables (mirrored from itb's bitbyte_test.go +
// extended for Easy Mode):
//
// * ITB_NONCE_BITS  — process-wide nonce width override; valid
//   values 128 / 256 / 512. Maps to Library.NonceBits before any
//   Encryptor is constructed. Default 128.
// * ITB_LOCKSEED    — when set to a non-empty / non-"0" value, every
//   Easy Mode encryptor in this run calls Encryptor.SetLockSeed(1)
//   AND Library.LockSoup is set to 1 at start. Mixed-primitive cases
//   attach a dedicated lockSeed primitive at construction (via primL)
//   under this flag; otherwise primL is null. Default off.
// * ITB_BENCH_FILTER — substring filter on bench-case names; only
//   cases whose name contains the substring run.
// * ITB_BENCH_MIN_SEC — minimum measured wall-clock seconds per case
//   (default 5.0). The runner doubles iteration count until the
//   measured batch reaches the threshold, mirroring Go's
//   ``-benchtime=Ns``. The 5-second default absorbs the cold-cache /
//   warm-up transient that distorts shorter measurement windows on
//   the 16 MiB encrypt / decrypt path.
//
// Worker count defaults to Library.MaxWorkers = 0 (auto-detect),
// matching the Go bench default.

using System.Diagnostics;
using System.Security.Cryptography;

namespace Itb.Bench;

/// <summary>
/// Per-iter callable; accepts an iteration count and runs the per-iter
/// body that many times. The harness measures wall-clock time outside
/// the callable.
/// </summary>
internal delegate void BenchFn(long iters);

/// <summary>
/// One bench case: name + per-iter callable + payload byte count
/// (used to compute the MB/s column).
/// </summary>
internal sealed class BenchCase
{
    public string Name { get; }
    public BenchFn Run { get; }
    public long PayloadBytes { get; }

    public BenchCase(string name, BenchFn run, long payloadBytes)
    {
        Name = name;
        Run = run;
        PayloadBytes = payloadBytes;
    }
}

/// <summary>
/// Bench-harness primitives shared by <see cref="BenchSingle"/> and
/// <see cref="BenchTriple"/>: env-var readers, payload generator,
/// convergence loop, and the Go-bench-style report formatter.
/// </summary>
internal static class Common
{
    /// <summary>Default 16 MiB CSPRNG-filled payload, matching the Go
    /// bench / Python bench / Rust bench surface.</summary>
    public const int Payload16MB = 16 << 20;

    /// <summary>Bench MAC slot. <b>Hard-coded</b> to
    /// <c>"hmac-blake3"</c> — never <c>"kmac256"</c>. KMAC-256 adds
    /// ~44% overhead on encrypt_auth via cSHAKE-256 / Keccak; HMAC-BLAKE3
    /// adds ~9%. KMAC-256 in benches would shift the encrypt_auth row
    /// 4-5× higher than expected.</summary>
    public const string MacName = "hmac-blake3";

    /// <summary>Dedicated lockSeed primitive used by mixed-primitive
    /// bench cases when <c>ITB_LOCKSEED</c> is set. When the env var is
    /// unset, the mixed cases pass <c>null</c> for primL — DO NOT pass
    /// a real primitive name unconditionally (that would auto-couple
    /// BitSoup + LockSoup at the Easy Mode level and the no-LockSeed
    /// arm would mis-measure as ~50 MB/s instead of the real
    /// ~110-130 MB/s plain-Mixed cost).</summary>
    public const string MixedLock = "blake3";

    /// <summary>Canonical ITB key width pinned across every bench case
    /// (1024 bits = 128 bytes).</summary>
    public const int KeyBits = 1024;

    /// <summary>
    /// Reads <c>ITB_NONCE_BITS</c> from the environment with the same
    /// 128 / 256 / 512 validation as bitbyte_test.go's TestMain. Falls
    /// back to <paramref name="defaultBits"/> on missing / invalid
    /// input (with a stderr diagnostic for the invalid case).
    /// </summary>
    public static int EnvNonceBits(int defaultBits = 128)
    {
        var v = Environment.GetEnvironmentVariable("ITB_NONCE_BITS");
        if (string.IsNullOrEmpty(v))
        {
            return defaultBits;
        }
        switch (v)
        {
            case "128": return 128;
            case "256": return 256;
            case "512": return 512;
            default:
                Console.Error.WriteLine(
                    $"ITB_NONCE_BITS=\"{v}\" invalid (expected 128/256/512); using {defaultBits}");
                return defaultBits;
        }
    }

    /// <summary>
    /// <c>true</c> when <c>ITB_LOCKSEED</c> is set to a non-empty /
    /// non-<c>0</c> value. The bench harness uses the result to (a)
    /// flip <see cref="Library.LockSoup"/> to <c>1</c> at start, (b)
    /// call <see cref="Encryptor.SetLockSeed"/> on every single-primitive
    /// encryptor, and (c) pass <see cref="MixedLock"/> as the dedicated
    /// lockSeed primitive into the mixed-primitive constructors (else
    /// <c>null</c>).
    /// </summary>
    public static bool EnvLockSeed()
    {
        var v = Environment.GetEnvironmentVariable("ITB_LOCKSEED");
        if (string.IsNullOrEmpty(v))
        {
            return false;
        }
        return v != "0";
    }

    /// <summary>
    /// Optional substring filter for bench-case names, read from
    /// <c>ITB_BENCH_FILTER</c>. Cases whose name does not contain the
    /// filter substring are skipped; used to scope a run down to a
    /// single primitive or operation during development. Matching is
    /// case-insensitive.
    /// </summary>
    public static string? EnvBenchFilter()
    {
        var v = Environment.GetEnvironmentVariable("ITB_BENCH_FILTER");
        return string.IsNullOrEmpty(v) ? null : v;
    }

    /// <summary>
    /// Minimum wall-clock seconds the measured iter loop should take,
    /// read from <c>ITB_BENCH_MIN_SEC</c> (default <c>5.0</c>). The
    /// runner keeps doubling iteration count until the measured run
    /// reaches this threshold, mirroring Go's <c>-benchtime=Ns</c>
    /// semantics. The 5-second default is wide enough to absorb the
    /// cold-cache / warm-up transient that distorts shorter measurement
    /// windows on the 16 MiB encrypt / decrypt path.
    /// </summary>
    public static double EnvMinSeconds()
    {
        var v = Environment.GetEnvironmentVariable("ITB_BENCH_MIN_SEC");
        if (string.IsNullOrEmpty(v))
        {
            return 5.0;
        }
        if (double.TryParse(v, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var f) && f > 0)
        {
            return f;
        }
        Console.Error.WriteLine(
            $"ITB_BENCH_MIN_SEC=\"{v}\" invalid (expected positive float); using 5.0");
        return 5.0;
    }

    /// <summary>
    /// Returns <paramref name="n"/> CSPRNG-filled bytes via
    /// <see cref="RandomNumberGenerator.Fill(Span{byte})"/>. Mirrors
    /// the <c>TestRng.Bytes</c> helper used by the Phase-5 test suite —
    /// no new NuGet dependency is introduced.
    /// </summary>
    public static byte[] RandomBytes(int n)
    {
        if (n <= 0)
        {
            return Array.Empty<byte>();
        }
        var buf = new byte[n];
        RandomNumberGenerator.Fill(buf);
        return buf;
    }

    /// <summary>
    /// Run a benchmark case to convergence and emit a single
    /// Go-bench-style report line.
    ///
    /// Convergence policy: warm up with one iteration, then double the
    /// iteration count until the measured wall-clock duration meets
    /// <paramref name="minSeconds"/>. The final <c>ns/op</c> figure is
    /// the measured duration of that final batch divided by its
    /// iteration count.
    /// </summary>
    private static void Measure(BenchCase bench, double minSeconds)
    {
        // Warm-up — one iteration to hit cache / cold-start transients
        // before the measured loop.
        bench.Run(1);

        long minNs = (long)(minSeconds * 1e9);
        long iters = 1;
        long elapsed;
        while (true)
        {
            var t0 = Stopwatch.GetTimestamp();
            bench.Run(iters);
            elapsed = ElapsedNanoseconds(t0);
            if (elapsed >= minNs)
            {
                break;
            }
            // Double up; cap growth so a very fast op doesn't escalate
            // past 1 << 24 iters for one batch.
            if (iters >= (1L << 24))
            {
                break;
            }
            iters *= 2;
        }

        double nsPerOp = (double)elapsed / iters;
        double mbPerS = nsPerOp > 0
            ? (bench.PayloadBytes / (nsPerOp / 1e9)) / (1L << 20)
            : 0.0;
        // Mirrors `BenchmarkX-8     N    ns/op    MB/s` Go format,
        // column-aligned for human reading.
        Console.WriteLine(
            string.Format(
                System.Globalization.CultureInfo.InvariantCulture,
                "{0,-60}\t{1,10}\t{2,14:F1} ns/op\t{3,9:F2} MB/s",
                bench.Name, iters, nsPerOp, mbPerS));
        Console.Out.Flush();
    }

    private static long ElapsedNanoseconds(long startTimestamp)
    {
        var ticks = Stopwatch.GetTimestamp() - startTimestamp;
        // Stopwatch.Frequency is ticks per second; convert to ns.
        return (long)((double)ticks / Stopwatch.Frequency * 1e9);
    }

    /// <summary>
    /// Run every case in <paramref name="cases"/> and print one
    /// Go-bench-style line per case to stdout. Honours
    /// <c>ITB_BENCH_FILTER</c> for substring scoping (case-insensitive)
    /// and <c>ITB_BENCH_MIN_SEC</c> for the per-case wall-clock
    /// budget.
    /// </summary>
    public static void RunAll(IReadOnlyList<BenchCase> cases)
    {
        var flt = EnvBenchFilter();
        var minSeconds = EnvMinSeconds();

        var allNames = cases.Select(c => c.Name).ToArray();
        var selected = flt is null
            ? cases.ToList()
            : cases.Where(c =>
                c.Name.Contains(flt, StringComparison.OrdinalIgnoreCase)).ToList();
        if (selected.Count == 0)
        {
            Console.Error.WriteLine(
                $"no bench cases match filter \"{flt}\"; available: [{string.Join(", ", allNames)}]");
            return;
        }

        Console.WriteLine(
            string.Format(
                System.Globalization.CultureInfo.InvariantCulture,
                "# benchmarks={0} payload_bytes={1} min_seconds={2}",
                selected.Count, selected[0].PayloadBytes, minSeconds));
        Console.Out.Flush();
        foreach (var bench in selected)
        {
            Measure(bench, minSeconds);
        }
    }

    /// <summary>
    /// Apply the <c>ITB_LOCKSEED</c> per-encryptor flag. Calling
    /// <see cref="Encryptor.SetLockSeed"/> with mode 1 auto-couples
    /// BitSoup + LockSoup on the Single Ouroboros encryptor; the
    /// auto-couple is intentional behaviour of the underlying easy
    /// package, not a binding-side workaround.
    /// </summary>
    public static void ApplyLockSeedIfRequested(Encryptor enc)
    {
        if (EnvLockSeed())
        {
            enc.SetLockSeed(1);
        }
    }
}
