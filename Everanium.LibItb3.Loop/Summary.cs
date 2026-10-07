// The final summary in both renderings, and the two measurements it
// folds in that are not per-worker counters: the process resident
// set and the shared library's pool counters.

using System.Globalization;
using System.Text;

namespace Everanium.Itb3.Loop;

internal static class Summary
{
    /// <summary>Parses one "Vm...:   1234 kB" line of
    /// /proc/self/status into bytes; zero on any parse failure.</summary>
    private static long StatusKb(string line)
    {
        int colon = line.IndexOf(':');
        if (colon < 0)
        {
            return 0;
        }
        string[] parts = line[(colon + 1)..]
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0
            || !long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out long kb))
        {
            return 0;
        }
        return kb * 1024;
    }

    /// <summary>The process's current resident set and its high-water
    /// mark in bytes, from /proc/self/status (VmRSS and VmHWM, reported
    /// in kB). Both are zero on a platform without that file; the
    /// figures are informational and never enter the verdict.</summary>
    internal static (long Current, long Peak) ReadRss()
    {
        string[] lines;
        try
        {
            lines = File.ReadAllLines("/proc/self/status");
        }
        catch (Exception)
        {
            return (0, 0);
        }
        long current = 0;
        long peak = 0;
        foreach (string line in lines)
        {
            if (line.StartsWith("VmRSS:", StringComparison.Ordinal))
            {
                current = StatusKb(line);
            }
            else if (line.StartsWith("VmHWM:", StringComparison.Ordinal))
            {
                peak = StatusKb(line);
            }
        }
        return (current, peak);
    }

    /// <summary>
    /// Pool counters. The shared library keeps process-wide monotonic
    /// totals at every pool checkout of its cipher core: per hash-array
    /// tier the starter width, checkouts, constructor misses, regrow
    /// replacements and bytes allocated; for the scratch byte pool and
    /// the parallax chunk pool the checkouts, constructor misses,
    /// regrows and regrow bytes. Two snapshots bracketing the main loop
    /// are differenced into per-run hit / miss figures that tell
    /// whether a pool keeps its items warm between calls or evicts them
    /// across GC cycles. The slot layout is read from the library: slot
    /// 0 carries the tier count T, tier i occupies the five slots at
    /// 1 + 5*i, and the two byte pools occupy the eight slots at
    /// 1 + 5*T; the vector is sized by the binding from the library's
    /// own length query, never from a constant. Empty when the library
    /// is unavailable.
    /// </summary>
    internal static long[] PoolSnapshot()
    {
        try
        {
            return Everanium.Itb3.Runtime.PoolStats();
        }
        catch (Exception)
        {
            return [];
        }
    }

    /// <summary>One starter tier of the hash-array pool,
    /// differenced.</summary>
    private sealed class Tier
    {
        internal long Index;
        internal long Starter;
        internal long Get;
        internal long Fresh;
        internal long Regrow;
        internal long NewBytes;
    }

    /// <summary>One single-size byte pool, differenced.</summary>
    private sealed class BytePool
    {
        internal long Get;
        internal long Fresh;
        internal long Regrow;
        internal long RegrowBytes;
    }

    private sealed class PoolDelta
    {
        internal readonly List<Tier> Tiers = [];
        internal BytePool Buf = new();
        internal BytePool Chunk = new();
    }

    private static PoolDelta PoolDiff(long[] steady, long[] warmup)
    {
        var d = new PoolDelta();
        if (steady.Length < 9 || warmup.Length != steady.Length)
        {
            return d;
        }
        long tiers = steady[0];
        if (tiers < 0 || 1 + 5 * tiers + 8 > steady.Length)
        {
            return d;
        }
        for (long i = 0; i < tiers; i++)
        {
            int b = (int)(1 + 5 * i);
            if (steady[b] == 0)
            {
                continue;
            }
            d.Tiers.Add(new Tier
            {
                Index = i,
                Starter = steady[b],
                Get = steady[b + 1] - warmup[b + 1],
                Fresh = steady[b + 2] - warmup[b + 2],
                Regrow = steady[b + 3] - warmup[b + 3],
                NewBytes = steady[b + 4] - warmup[b + 4],
            });
        }
        int t = (int)(1 + 5 * tiers);
        d.Buf = new BytePool
        {
            Get = steady[t] - warmup[t],
            Fresh = steady[t + 1] - warmup[t + 1],
            Regrow = steady[t + 2] - warmup[t + 2],
            RegrowBytes = steady[t + 3] - warmup[t + 3],
        };
        d.Chunk = new BytePool
        {
            Get = steady[t + 4] - warmup[t + 4],
            Fresh = steady[t + 5] - warmup[t + 5],
            Regrow = steady[t + 6] - warmup[t + 6],
            RegrowBytes = steady[t + 7] - warmup[t + 7],
        };
        return d;
    }

    /// <summary>Misses over checkouts as a percentage; zero when
    /// nothing was checked out.</summary>
    private static double MissPercent(long miss, long get) =>
        get <= 0 ? 0.0 : 100.0 * miss / get;

    /// <summary>Renders s as a JSON string literal with the escapes
    /// JSON requires.</summary>
    private static string JsonString(string s)
    {
        var sb = new StringBuilder(s.Length + 2);
        sb.Append('"');
        foreach (char ch in s)
        {
            switch (ch)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (ch < 0x20)
                    {
                        sb.Append("\\u").Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(ch);
                    }
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }

    /// <summary>The effective GC percentage as the runtime reports it:
    /// the query form of the setter (a set-and-restore round trip
    /// inside the library) so the field is the same whether the value
    /// came from the flag, the environment, or the runtime
    /// default.</summary>
    private static int EffectiveGogc(int flag)
    {
        if (flag > 0)
        {
            return flag;
        }
        try
        {
            return Everanium.Itb3.Runtime.SetGCPercent(-1);
        }
        catch (Exception)
        {
            return 0;
        }
    }

    private static string F(double v, int decimals) =>
        v.ToString("F" + decimals.ToString(CultureInfo.InvariantCulture), CultureInfo.InvariantCulture);

    private static string D(long v) => v.ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// Output contract. Both renderings are shared with the Go harness
    /// and every other binding's loop utility field for field: the same
    /// lines in the same order, the same keys in the same order, floats
    /// with a fixed number of decimals so the JSON is byte-identical
    /// across implementations. The Go harness alone adds its
    /// runtime-internal lines after rss: and its runtime-internal keys
    /// after parallax_chunk_pool; nothing here reproduces them because
    /// nothing they read is reachable through the C ABI. Returns the
    /// exit code.
    /// </summary>
    internal static int Final(RunState r, long elapsedNs)
    {
        var cfg = r.Cfg;
        long workers = cfg.Workers;
        long totalIters = 0;
        long totalEnc = 0;
        long totalDec = 0;
        long nanosEnc = 0;
        long nanosDec = 0;
        var perWorker = new List<long>(cfg.Workers);
        var errors = new List<string>();
        foreach (var c in r.Workers)
        {
            long n = Interlocked.Read(ref c.Iters);
            perWorker.Add(n);
            totalIters += n;
            totalEnc += Interlocked.Read(ref c.BytesEnc);
            totalDec += Interlocked.Read(ref c.BytesDec);
            nanosEnc += Interlocked.Read(ref c.NanosEnc);
            nanosDec += Interlocked.Read(ref c.NanosDec);
            lock (c.ErrorLock)
            {
                if (c.Error is not null)
                {
                    errors.Add(c.Error);
                }
            }
        }

        // Throughput. Per-direction throughput divides the sum of every
        // worker's wall time in that direction by the worker count —
        // the equivalent single-stream wall time under N-way
        // concurrency — so each direction reports the aggregate rate it
        // sustained rather than collapsing to combined/2 (every
        // iteration moves equal encrypt and decrypt bytes, so a
        // total-elapsed denominator would give both directions the same
        // figure). The combined rate keeps total elapsed as the
        // one-glance overall figure.
        long avgEnc = nanosEnc > 0 ? nanosEnc / workers : 0;
        long avgDec = nanosDec > 0 ? nanosDec / workers : 0;

        long rssDelta = r.RssFinal - r.RssWarmup;
        double rssGrowth = r.RssWarmup > 0 ? 100.0 * rssDelta / r.RssWarmup : 0.0;

        var pd = PoolDiff(r.PoolSteady, r.PoolWarmup);
        bool pass = errors.Count == 0;
        long rekeys = Interlocked.Read(ref r.Rekeys);
        long cycles = Interlocked.Read(ref r.BlobCycles);
        int gomaxprocs;
        try
        {
            gomaxprocs = Everanium.Itb3.Runtime.SetGOMAXPROCS(0);
        }
        catch (Exception)
        {
            gomaxprocs = 0;
        }
        string streamProfile = r.Pipes.Stream is not null ? r.StreamProfile : "";
        string msgProfile = r.Pipes.Msg is not null ? r.MsgProfile : "";

        if (cfg.JsonOutput)
        {
            var j = new StringBuilder();
            j.Append("{\"duration_seconds\":").Append(F(elapsedNs / 1e9, 3));
            j.Append(",\"iterations\":").Append(D(totalIters));
            j.Append(",\"per_worker_iterations\":[")
                .Append(string.Join(",", perWorker.Select(D))).Append(']');
            j.Append(",\"bytes_encrypted\":").Append(D(totalEnc));
            j.Append(",\"bytes_decrypted\":").Append(D(totalDec));
            j.Append(",\"encrypt_mb_per_sec\":").Append(F(Size.MbPerSec(totalEnc, avgEnc), 1));
            j.Append(",\"decrypt_mb_per_sec\":").Append(F(Size.MbPerSec(totalDec, avgDec), 1));
            j.Append(",\"combined_mb_per_sec\":")
                .Append(F(Size.MbPerSec(totalEnc + totalDec, elapsedNs), 1));
            j.Append(",\"rekeys\":").Append(D(rekeys));
            j.Append(",\"blob_cycles\":").Append(D(cycles));
            j.Append(",\"worker_errors\":[")
                .Append(string.Join(",", errors.Select(JsonString))).Append(']');
            j.Append(",\"verdict\":\"").Append(pass ? "PASS" : "FAIL").Append('"');
            j.Append(",\"shape\":\"").Append(cfg.Shape.Name()).Append('"');
            j.Append(",\"stream_profile\":").Append(JsonString(streamProfile));
            j.Append(",\"message_profile\":").Append(JsonString(msgProfile));
            j.Append(",\"hash\":").Append(JsonString(cfg.Hash));
            j.Append(",\"mac\":").Append(JsonString(cfg.Mac));
            j.Append(",\"payload_bytes\":").Append(D(cfg.Payload));
            j.Append(",\"payload_mode\":\"").Append(cfg.PayloadMode.Name()).Append('"');
            j.Append(",\"seed\":").Append(cfg.Seed.ToString(CultureInfo.InvariantCulture));
            j.Append(",\"key_bits\":").Append(D(cfg.KeyBits));
            j.Append(",\"nonce_bits\":").Append(D(cfg.NonceBits));
            j.Append(",\"blob_mode\":").Append(D(cfg.BlobMode));
            j.Append(",\"drbg\":").Append(JsonString(cfg.Drbg));
            j.Append(",\"drbg_auto_tier\":").Append(JsonString(Everanium.Itb3.Runtime.DrbgAutoTier()));
            j.Append(",\"chunk_size_bytes\":").Append(D(cfg.ChunkSize));
            j.Append(",\"barrier_fill\":").Append(D(cfg.BarrierFill));
            j.Append(",\"parallax\":\"").Append(Program.OnOff(cfg.Parallax)).Append('"');
            j.Append(",\"wrapper\":\"").Append(Program.OnOff(cfg.Wrapper)).Append('"');
            j.Append(",\"goroutines_requested\":").Append(D(cfg.WorkersRequested));
            j.Append(",\"goroutines\":").Append(D(cfg.Workers));
            j.Append(",\"concurrency\":\"").Append(Program.Concurrency).Append('"');
            j.Append(",\"gogc\":\"").Append(D(EffectiveGogc(cfg.Gogc))).Append('"');
            j.Append(",\"memlimit_bytes\":").Append(D(cfg.Memlimit));
            j.Append(",\"gomaxprocs\":").Append(D(gomaxprocs));
            j.Append(",\"microbatch_tiers\":")
                .Append(JsonString(Program.PolicyLabel("ITB_MICROBATCH_TIERS")));
            j.Append(",\"hashpool_starters\":")
                .Append(JsonString(Program.PolicyLabel("ITB_HASHPOOL_STARTERS")));
            j.Append(",\"rss_warmup_bytes\":").Append(D(r.RssWarmup));
            j.Append(",\"rss_peak_bytes\":").Append(D(r.RssPeak));
            j.Append(",\"rss_final_bytes\":").Append(D(r.RssFinal));
            j.Append(",\"rss_growth_percent\":").Append(F(rssGrowth, 2));
            j.Append(",\"hash_pool_tiers\":[");
            j.Append(string.Join(",", pd.Tiers.Select(t =>
                "{\"tier\":" + D(t.Index)
                + ",\"starter\":" + D(t.Starter)
                + ",\"get\":" + D(t.Get)
                + ",\"new\":" + D(t.Fresh)
                + ",\"regrow\":" + D(t.Regrow)
                + ",\"new_bytes\":" + D(t.NewBytes)
                + ",\"miss_percent\":" + F(MissPercent(t.Fresh + t.Regrow, t.Get), 2)
                + "}")));
            j.Append(']');
            j.Append(",\"buf_pool\":{\"get\":").Append(D(pd.Buf.Get))
                .Append(",\"new\":").Append(D(pd.Buf.Fresh))
                .Append(",\"regrow\":").Append(D(pd.Buf.Regrow))
                .Append(",\"regrow_bytes\":").Append(D(pd.Buf.RegrowBytes))
                .Append(",\"miss_percent\":").Append(F(MissPercent(pd.Buf.Regrow, pd.Buf.Get), 2))
                .Append('}');
            j.Append(",\"parallax_chunk_pool\":{\"get\":").Append(D(pd.Chunk.Get))
                .Append(",\"new\":").Append(D(pd.Chunk.Fresh))
                .Append(",\"regrow\":").Append(D(pd.Chunk.Regrow))
                .Append(",\"regrow_bytes\":").Append(D(pd.Chunk.RegrowBytes))
                .Append(",\"miss_percent\":").Append(F(MissPercent(pd.Chunk.Regrow, pd.Chunk.Get), 2))
                .Append('}');
            j.Append('}');
            Console.WriteLine(j.ToString());
            return pass ? 0 : 1;
        }

        Program.LogLine("=== FINAL ===");
        Program.LogLine("  duration: " + Size.HumanDuration(Size.RoundTo(elapsedNs, 1_000_000)));
        Program.LogLine(
            "  iterations: " + string.Join(" + ", perWorker.Select(D)) + " = " + D(totalIters) + " total");
        Program.LogLine(
            "  throughput: encrypt " + Size.HumanRate(totalEnc, avgEnc)
            + ", decrypt " + Size.HumanRate(totalDec, avgDec)
            + ", combined " + Size.HumanRate(totalEnc + totalDec, elapsedNs));
        Program.LogLine(
            "  bytes: " + Size.HumanBytes(totalEnc) + " encrypted, "
            + Size.HumanBytes(totalDec) + " decrypted");
        Program.LogLine("  data integrity: " + D(totalIters) + "/" + D(totalIters) + " PASS");
        Program.LogLine(
            "  concurrency: " + Program.Concurrency + ", workers " + D(cfg.Workers)
            + " (requested " + D(cfg.WorkersRequested) + ")");
        Program.LogLine(
            "  rss: warmup " + Size.HumanBytes(r.RssWarmup)
            + ", peak " + Size.HumanBytes(r.RssPeak)
            + ", final " + Size.HumanBytes(r.RssFinal)
            + " (delta " + Size.HumanBytesSigned(rssDelta)
            + ", " + F(rssGrowth, 1) + "% growth)");
        foreach (var t in pd.Tiers)
        {
            Program.LogLine(
                "  hash pool tier " + D(t.Index) + " (starter " + D(t.Starter) + "): get " + D(t.Get)
                + ", miss " + D(t.Fresh + t.Regrow)
                + " (new " + D(t.Fresh) + " + regrow " + D(t.Regrow) + ")"
                + ", miss " + F(MissPercent(t.Fresh + t.Regrow, t.Get), 2) + "%"
                + ", " + Size.HumanBytes(t.NewBytes) + " allocated");
        }
        Program.LogLine(
            "  buf pool: get " + D(pd.Buf.Get) + ", regrow " + D(pd.Buf.Regrow)
            + " (of which fresh " + D(pd.Buf.Fresh) + ")"
            + ", miss " + F(MissPercent(pd.Buf.Regrow, pd.Buf.Get), 2) + "%"
            + ", " + Size.HumanBytes(pd.Buf.RegrowBytes) + " regrown");
        Program.LogLine(
            "  parallax chunk pool: get " + D(pd.Chunk.Get) + ", regrow " + D(pd.Chunk.Regrow)
            + " (of which fresh " + D(pd.Chunk.Fresh) + ")"
            + ", miss " + F(MissPercent(pd.Chunk.Regrow, pd.Chunk.Get), 2) + "%"
            + ", " + Size.HumanBytes(pd.Chunk.RegrowBytes) + " regrown");
        if (rekeys > 0)
        {
            Program.LogLine("  rekeys: " + D(rekeys));
        }
        if (cycles > 0)
        {
            Program.LogLine("  blob cycles: " + D(cycles));
        }
        foreach (string e in errors)
        {
            Program.LogLine("  ERROR: " + e);
        }
        if (pass)
        {
            Program.LogLine("  verdict: PASS");
            return 0;
        }
        Program.LogLine("  verdict: FAIL (errors=" + D(errors.Count) + ")");
        return 1;
    }
}
