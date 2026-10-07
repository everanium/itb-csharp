// Long-run stress harness. The loop utility holds one Pipeline handle
// per exercised cipher surface for minutes, hammers it with concurrent
// encrypt → decrypt → compare round-trips from N worker threads,
// rotates the outer masters and reopens the handle from its session
// blob on a schedule, and reports whether the process survived with
// every byte intact. It is the C# binding's counterpart of the Go
// harness under tools/loop: the same flags, the same round structure,
// the same summary in both renderings.
//
// The default shape is full production: the Streaming AEAD profile
// with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner
// hash, 1024-bit keys, and the compile-in 512-bit nonce width, driven
// through a stream session by three workers for five minutes on 16 MiB
// plaintexts. Every worker owns a distinct CSPRNG-generated plaintext
// held for the whole run, so any cross-call state leakage inside the
// Pipeline surfaces as a data mismatch between workers rather than
// cancelling out.
//
// A failure is one of two things. A cipher, rekey or load call that
// returns a non-OK status is a worker error: the run stops, the summary
// lists it, the verdict is FAIL and the exit code 1. A round-trip that
// returns without error but with different bytes is a data mismatch:
// the process terminates on the spot with exit code 3, printing the
// worker, the iteration and the first differing offset, and no summary
// — the state that produced the wrong bytes is the evidence. A crash
// inside the shared library or the host runtime has no exit code of its
// own here; surfacing it is what the utility is for. This binding runs
// a Go c-shared runtime and CoreCLR in one process, two runtimes that
// each drive threads through signals, which is the interaction the
// long run is meant to expose.
//
// Usage:
//
//   ./bin/Release/net10.0/Everanium.LibItb3.Loop --duration 5m --goroutines 3 \
//          --shape stream --hash areion512 --mac hmac-blake3 \
//          --payload-size 16MB --memlimit auto --parallax on --wrapper on
//
// Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
// then the partial summary prints.

using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Everanium.Itb3.Loop;

/// <summary>The resolved command line.</summary>
internal sealed class Config
{
    internal long DurationNs;
    internal long Iterations;
    internal int WorkersRequested;
    internal int Workers;
    internal Shape Shape;
    internal string Hash = "";
    internal string Mac = "";
    internal long Payload;
    internal long Memlimit;
    internal bool MemlimitAuto;
    internal int Gogc;
    internal bool Parallax;
    internal bool Wrapper;
    internal string Profile = "";
    internal long KeyBits;
    internal long NonceBits;
    internal long BlobMode;
    internal long ChunkSize;
    internal long BarrierFill;
    internal string Drbg = "";
    internal int Gomaxprocs;
    internal long RekeyEvery;
    internal long BlobCycleEvery;
    internal PayloadMode PayloadMode;
    internal ulong Seed;
    internal bool JsonOutput;
    internal string Memprofile = "";
}

/// <summary>The Pipeline handles and their retained blobs, behind the
/// lock that keeps iterations clear of handle mutation.</summary>
internal sealed class Pipes
{
    internal Pipeline? Stream;
    internal Pipeline? Msg;

    /// <summary>The blob Init handed out, replaced by every rekey; the
    /// input of the next blob reopen.</summary>
    internal byte[] StreamBlob = [];
    internal byte[] MsgBlob = [];
}

/// <summary>One worker's counters, read by the summary after every
/// worker has returned, and the error it stopped on.</summary>
internal sealed class Counters
{
    internal long Iters;
    internal long BytesEnc;
    internal long BytesDec;
    internal long NanosEnc;
    internal long NanosDec;
    internal readonly object ErrorLock = new();
    internal string? Error;

    internal void AddEncrypt(long ns) => Interlocked.Add(ref NanosEnc, ns);

    internal void AddDecrypt(long ns) => Interlocked.Add(ref NanosDec, ns);

    internal void AddIteration(long encBytes, long decBytes)
    {
        Interlocked.Increment(ref Iters);
        Interlocked.Add(ref BytesEnc, encBytes);
        Interlocked.Add(ref BytesDec, decBytes);
    }
}

/// <summary>One worker's private state, owned by its thread: its
/// plaintext, its reusable pump accumulators, its generator.</summary>
internal sealed class WorkerState
{
    internal int Id;
    internal byte[] Plaintext = [];
    internal PayloadMode PayloadMode;
    internal bool Seeded;
    internal ulong Rng;
    internal MemoryStream Wire = new();
    internal MemoryStream Plain = new();
    internal byte[] Scratch = [];
}

/// <summary>The state every worker shares.</summary>
internal sealed class RunState
{
    internal Config Cfg = new();
    internal string StreamProfile = "";
    internal string MsgProfile = "";

    /// <summary>Handle mutation. Iterations hold the read side for
    /// their whole encrypt → decrypt → compare; rekey and blob reopen
    /// take the write side, so no cipher call is in flight while a
    /// handle's keying changes or the handle itself is swapped, and no
    /// encrypt is separated from its decrypt by either.</summary>
    internal readonly ReaderWriterLockSlim PipesLock =
        new(LockRecursionPolicy.NoRecursion);

    internal Pipes Pipes = new();
    internal long Rekeys;
    internal long BlobCycles;
    internal Counters[] Workers = [];

    /// <summary>Warmup barrier: workers arrive at WarmupDone after
    /// iteration 0 and at Release once main has taken the
    /// baselines.</summary>
    internal Barrier WarmupDone = new(1);
    internal Barrier Release = new(1);

    /// <summary>Set by the duration timer, by a signal, or by a failing
    /// worker; checked by every worker before it starts an
    /// iteration.</summary>
    internal volatile bool Stop;

    internal readonly object DoneLock = new();
    internal int Active;
    internal long FinishTimestamp;

    internal long RssWarmup;
    internal long RssPeak;
    internal long RssFinal;
    internal long[] PoolWarmup = [];
    internal long[] PoolSteady = [];
}

internal static class Program
{
    /// <summary>--goroutines ceiling; the harness targets modest hosts
    /// and each worker pins payload-sized buffers for the whole
    /// run.</summary>
    internal const int MaxWorkers = 10;

    /// <summary>The concurrency mode this binding implements, as the
    /// summary reports it (shared-handle / independent-handles /
    /// single).</summary>
    internal const string Concurrency = "shared-handle";

    /// <summary>Largest slice fed to a stream session per write; the
    /// drain after every write uses the same bound.</summary>
    internal const int PumpSlice = 1 << 20;

    /// <summary>Profiles the shape-based pair is built against when
    /// --profile is empty.</summary>
    private const string DefaultStreamProfile = "streaming-aead-triple-mac-v1";
    private const string DefaultMessageProfile = "singlemsg-triple-mac-v1";

    /// <summary>The keystream-capable primitive supplied for a layer a
    /// profile leaves unnamed: PRF-grade, so sound outside the barrier,
    /// and the closest relative of the AES-based inner primitive whose
    /// profiles need the fill.</summary>
    private const string KeystreamFillCipher = "aescmac";

    /// <summary>The parallax segment size a filled palette runs with —
    /// the library's own default; a schedule rejects zero.</summary>
    private const long KeystreamFillSegment = 4093;

    private static readonly double NsPerTick = 1e9 / Stopwatch.Frequency;

    /// <summary>Nanoseconds elapsed since a
    /// <see cref="Stopwatch.GetTimestamp"/> reading.</summary>
    internal static long ElapsedNs(long since) =>
        (long)((Stopwatch.GetTimestamp() - since) * NsPerTick);

    /// <summary>Prints one prefixed status line to stdout.</summary>
    internal static void LogLine(string line) => Console.WriteLine("[loop] " + line);

    internal static string OnOff(bool b) => b ? "on" : "off";

    /// <summary>Renders an encoder policy env value for the summary: the
    /// raw string when set, "default" when the shipped ladder
    /// applies.</summary>
    internal static string PolicyLabel(string name)
    {
        string? v = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrWhiteSpace(v) ? "default" : v.TrimStart();
    }

    // --------------------------------------------------------------
    // Flags
    // --------------------------------------------------------------

    /// <summary>The raw flag values before validation.</summary>
    private sealed class RawFlags
    {
        internal long BarrierFill;
        internal long BlobCycleEvery;
        internal long BlobMode = 1;
        internal string ChunkSize = "0";
        internal string Drbg = "";
        internal string Duration = "5m";
        internal long Gogc;
        internal long Gomaxprocs;
        internal long Goroutines = 3;
        internal string Hash = "areion512";
        internal long Iterations;
        internal bool JsonOutput;
        internal long KeyBits;
        internal string Mac = "hmac-blake3";
        internal string Memlimit = "auto";
        internal string Memprofile = "";
        internal long NonceBits;
        internal string Parallax = "on";
        internal string PayloadMode = "fixed";
        internal string PayloadSize = "16MB";
        internal string Profile = "";
        internal long RekeyEvery;
        internal ulong Seed;
        internal string Shape = "stream";
        internal string Wrapper = "on";
    }

    /// <summary>One command-line flag: its name, the type label the
    /// usage prints, its help text, whether it takes a value, the
    /// default-value suffix the usage appends, and the store that
    /// parses a value into the raw flags. Values are validated after
    /// the whole line is parsed. The table is in alphabetical order —
    /// the order the usage prints.</summary>
    private sealed record Flag(
        string Name,
        string TypeLabel,
        string Help,
        bool IsBool,
        string DefaultSuffix,
        Func<RawFlags, string, bool> Store);

    private static string DefaultOf(long v) =>
        v != 0 ? " (default " + v.ToString(CultureInfo.InvariantCulture) + ")" : "";

    private static string DefaultOf(string v) => v.Length > 0 ? " (default \"" + v + "\")" : "";

    private static bool StoreInt(string value, out long v) =>
        long.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out v);

    private static readonly Flag[] Flags = BuildFlags();

    private static Flag[] BuildFlags()
    {
        var d = new RawFlags();
        return
        [
            new Flag("barrier-fill", "int",
                "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)",
                false, DefaultOf(d.BarrierFill),
                (f, s) => StoreInt(s, out f.BarrierFill)),
            new Flag("blob-cycle-every", "int",
                "reopen each pipeline from its session blob every N iterations per worker; 0 = never",
                false, "",
                (f, s) => StoreInt(s, out f.BlobCycleEvery)),
            new Flag("blob-mode", "int",
                "container floor sizing mode: 1 (per-region, default) | 2 (per-container)",
                false, DefaultOf(d.BlobMode),
                (f, s) => StoreInt(s, out f.BlobMode)),
            new Flag("chunk-size", "string",
                "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape",
                false, DefaultOf(d.ChunkSize),
                (f, s) => { f.ChunkSize = s; return true; }),
            new Flag("drbg", "string",
                "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)",
                false, DefaultOf(d.Drbg),
                (f, s) => { f.Drbg = s; return true; }),
            new Flag("duration", "duration",
                "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0",
                false, DefaultOf(d.Duration),
                (f, s) => { f.Duration = s; return true; }),
            new Flag("gogc", "int",
                "GC trigger percentage; 0 = leave the runtime default",
                false, DefaultOf(d.Gogc),
                (f, s) => StoreInt(s, out f.Gogc)),
            new Flag("gomaxprocs", "int",
                "Go runtime GOMAXPROCS override; 0 = inherit from the environment",
                false, DefaultOf(d.Gomaxprocs),
                (f, s) => StoreInt(s, out f.Gomaxprocs)),
            new Flag("goroutines", "int",
                "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1",
                false, DefaultOf(d.Goroutines),
                (f, s) => StoreInt(s, out f.Goroutines)),
            new Flag("hash", "string",
                "inner ITB hash primitive name",
                false, DefaultOf(d.Hash),
                (f, s) => { f.Hash = s; return true; }),
            new Flag("iterations", "int",
                "fixed per-worker iteration count; 0 = duration-based",
                false, "",
                (f, s) => StoreInt(s, out f.Iterations)),
            new Flag("json-output", "",
                "print the final summary as one compact JSON object instead of log lines",
                true, "",
                (f, s) =>
                {
                    if (s == "true") { f.JsonOutput = true; return true; }
                    if (s == "false") { f.JsonOutput = false; return true; }
                    return false;
                }),
            new Flag("key-bits", "int",
                "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)",
                false, DefaultOf(d.KeyBits),
                (f, s) => StoreInt(s, out f.KeyBits)),
            new Flag("mac", "string",
                "MAC primitive name",
                false, DefaultOf(d.Mac),
                (f, s) => { f.Mac = s; return true; }),
            new Flag("memlimit", "string",
                "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)",
                false, DefaultOf(d.Memlimit),
                (f, s) => { f.Memlimit = s; return true; }),
            new Flag("memprofile", "string",
                "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none",
                false, DefaultOf(d.Memprofile),
                (f, s) => { f.Memprofile = s; return true; }),
            new Flag("nonce-bits", "int",
                "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)",
                false, DefaultOf(d.NonceBits),
                (f, s) => StoreInt(s, out f.NonceBits)),
            new Flag("parallax", "string",
                "parallax layer: on | off",
                false, DefaultOf(d.Parallax),
                (f, s) => { f.Parallax = s; return true; }),
            new Flag("payload-mode", "string",
                "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii",
                false, DefaultOf(d.PayloadMode),
                (f, s) => { f.PayloadMode = s; return true; }),
            new Flag("payload-size", "string",
                "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)",
                false, DefaultOf(d.PayloadSize),
                (f, s) => { f.PayloadSize = s; return true; }),
            new Flag("profile", "string",
                "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair",
                false, DefaultOf(d.Profile),
                (f, s) => { f.Profile = s; return true; }),
            new Flag("rekey-every", "int",
                "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never",
                false, "",
                (f, s) => StoreInt(s, out f.RekeyEvery)),
            new Flag("seed", "uint",
                "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts",
                false, "",
                (f, s) => ulong.TryParse(
                    s, NumberStyles.None, CultureInfo.InvariantCulture, out f.Seed)),
            new Flag("shape", "string",
                "cipher surface to exercise: stream | message | stream_one_shot | both",
                false, DefaultOf(d.Shape),
                (f, s) => { f.Shape = s; return true; }),
            new Flag("wrapper", "string",
                "wrapper layer: on | off",
                false, DefaultOf(d.Wrapper),
                (f, s) => { f.Wrapper = s; return true; }),
        ];
    }

    private static void Usage()
    {
        Console.Error.WriteLine("Usage of loop:");
        foreach (var fl in Flags)
        {
            Console.Error.WriteLine(
                fl.TypeLabel.Length == 0 ? "  -" + fl.Name : "  -" + fl.Name + " " + fl.TypeLabel);
            Console.Error.WriteLine("    \t" + fl.Help + fl.DefaultSuffix);
        }
    }

    /// <summary>Parses argv into the raw flag values. Accepts -name
    /// value, --name value, -name=value and --name=value; a boolean
    /// flag takes no value unless given as -name=true / -name=false.
    /// True for -h / --help (usage printed); null after printing the
    /// error.</summary>
    private static bool? ParseArgv(string[] args, RawFlags f)
    {
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg.Length <= 1 || arg[0] != '-')
            {
                Console.Error.WriteLine($"loop: unexpected positional arguments: [{arg}]");
                return null;
            }
            string name = arg.StartsWith("--", StringComparison.Ordinal) ? arg[2..] : arg[1..];
            if (name is "h" or "help")
            {
                Usage();
                return true;
            }
            string? inline = null;
            int eq = name.IndexOf('=');
            if (eq >= 0)
            {
                inline = name[(eq + 1)..];
                name = name[..eq];
            }
            Flag? fl = null;
            foreach (var candidate in Flags)
            {
                if (candidate.Name == name)
                {
                    fl = candidate;
                    break;
                }
            }
            if (fl is null)
            {
                Console.Error.WriteLine($"loop: flag provided but not defined: -{name}");
                Usage();
                return null;
            }
            string value;
            if (inline is not null)
            {
                value = inline;
            }
            else if (fl.IsBool)
            {
                value = "true";
            }
            else
            {
                i++;
                if (i >= args.Length)
                {
                    Console.Error.WriteLine($"loop: flag needs an argument: -{fl.Name}");
                    return null;
                }
                value = args[i];
            }
            if (!fl.Store(f, value))
            {
                Console.Error.WriteLine($"loop: invalid value \"{value}\" for flag -{fl.Name}");
                return null;
            }
        }
        return false;
    }

    /// <summary>Whether name is in the shipped hash registry the
    /// binding returns.</summary>
    private static bool HashRegistered(string name)
    {
        try
        {
            return Array.IndexOf(Pipeline.HashNames(), name) >= 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Resolves a registered profile to the shape family its
    /// record's mode exposes by reading the record through the
    /// binding's lookup: a mode beginning with "streaming" exposes the
    /// stream surfaces, one beginning with "singlemsg" the message
    /// surface, "blob-only" none. Prints the validation message and
    /// returns null on rejection.</summary>
    private static Shape? ProfileSurface(string name)
    {
        Profile p;
        try
        {
            p = Pipeline.Lookup(name);
        }
        catch (Exception)
        {
            Console.Error.WriteLine(
                $"loop: --profile \"{name}\" is not a registered triple profile");
            return null;
        }
        if (p.Mode.StartsWith("streaming", StringComparison.Ordinal))
        {
            return Shape.Stream;
        }
        if (p.Mode.StartsWith("singlemsg", StringComparison.Ordinal))
        {
            return Shape.Message;
        }
        Console.Error.WriteLine(
            $"loop: --profile \"{name}\" carries no cipher surface (blob-only mode)");
        return null;
    }

    /// <summary>Applies a --profile's surface to the requested shape: a
    /// message-surface profile forces message; a stream-surface profile
    /// keeps stream or stream_one_shot as requested and turns message
    /// or both into stream.</summary>
    private static Shape NarrowShape(Shape requested, Shape surface)
    {
        if (surface == Shape.Message)
        {
            return Shape.Message;
        }
        return requested == Shape.StreamOneShot ? Shape.StreamOneShot : Shape.Stream;
    }

    /// <summary>Builds the resolved config from argv. Returns (null,
    /// 0) for help and (null, 2) after printing "loop: &lt;message&gt;"
    /// for the first failing rule.</summary>
    private static (Config? Cfg, int Code) ParseFlags(string[] args)
    {
        var inv = CultureInfo.InvariantCulture;
        var f = new RawFlags();
        bool? help = ParseArgv(args, f);
        if (help is null)
        {
            return (null, 2);
        }
        if (help.Value)
        {
            return (null, 0);
        }
        long? durationNs = Size.ParseDuration(f.Duration);
        if (durationNs is null or <= 0)
        {
            Console.Error.WriteLine($"loop: --duration must be positive, got {f.Duration}");
            return (null, 2);
        }
        if (f.Iterations < 0)
        {
            Console.Error.WriteLine(
                $"loop: --iterations must be >= 0, got {f.Iterations.ToString(inv)}");
            return (null, 2);
        }
        if (f.Goroutines < 1 || f.Goroutines > MaxWorkers)
        {
            Console.Error.WriteLine(
                $"loop: --goroutines must be in 1..{MaxWorkers.ToString(inv)}, "
                + $"got {f.Goroutines.ToString(inv)}");
            return (null, 2);
        }
        // Concurrency mode. This binding runs shared-handle: CLR threads
        // call into one Pipeline handle concurrently. The handle is a
        // SafeHandle over an opaque Go-side registry key, every entry it
        // is passed to is re-entrant after construction, and nothing in
        // the binding's Pipeline type is thread-affine, so --goroutines
        // is the thread count verbatim, never clamped.
        int workers = (int)f.Goroutines;
        Shape? shape = Worker.ParseShape(f.Shape);
        if (shape is null)
        {
            Console.Error.WriteLine(
                "loop: --shape must be stream | message | stream_one_shot | both, "
                + $"got \"{f.Shape}\"");
            return (null, 2);
        }
        if (!HashRegistered(f.Hash))
        {
            Console.Error.WriteLine(
                $"loop: --hash \"{f.Hash}\" is not a registered hash primitive");
            return (null, 2);
        }
        // --mac is validated by Init: the C ABI enumerates no MAC names.
        long? payload = Size.ParseSize(f.PayloadSize);
        if (payload is null)
        {
            Console.Error.WriteLine($"loop: --payload-size: invalid size \"{f.PayloadSize}\"");
            return (null, 2);
        }
        if (payload < 1)
        {
            Console.Error.WriteLine("loop: --payload-size must be at least 1 byte");
            return (null, 2);
        }
        bool memlimitAuto = f.Memlimit == "auto";
        long memlimit;
        if (memlimitAuto)
        {
            memlimit = workers <= 3 ? 1L << 30 : 256L << 20;
        }
        else
        {
            long? parsed = Size.ParseSize(f.Memlimit);
            if (parsed is null)
            {
                Console.Error.WriteLine($"loop: --memlimit: invalid size \"{f.Memlimit}\"");
                return (null, 2);
            }
            memlimit = parsed.Value;
        }
        if (f.Gogc < 0)
        {
            Console.Error.WriteLine($"loop: --gogc must be >= 0, got {f.Gogc.ToString(inv)}");
            return (null, 2);
        }
        bool parallax;
        switch (f.Parallax)
        {
            case "on": parallax = true; break;
            case "off": parallax = false; break;
            default:
                Console.Error.WriteLine($"loop: --parallax must be on | off, got \"{f.Parallax}\"");
                return (null, 2);
        }
        bool wrapper;
        switch (f.Wrapper)
        {
            case "on": wrapper = true; break;
            case "off": wrapper = false; break;
            default:
                Console.Error.WriteLine($"loop: --wrapper must be on | off, got \"{f.Wrapper}\"");
                return (null, 2);
        }
        if (f.Profile.Length > 0)
        {
            Shape? surface = ProfileSurface(f.Profile);
            if (surface is null)
            {
                return (null, 2);
            }
            shape = NarrowShape(shape.Value, surface.Value);
        }
        if (f.KeyBits is not (0 or 512 or 1024 or 2048))
        {
            Console.Error.WriteLine(
                "loop: --key-bits must be 512 | 1024 | 2048 (or 0 = profile default), "
                + $"got {f.KeyBits.ToString(inv)}");
            return (null, 2);
        }
        if (f.NonceBits is not (0 or 128 or 256 or 512))
        {
            Console.Error.WriteLine(
                "loop: --nonce-bits must be 128 | 256 | 512 (or 0 = profile default), "
                + $"got {f.NonceBits.ToString(inv)}");
            return (null, 2);
        }
        if (f.BlobMode is not (1 or 2))
        {
            Console.Error.WriteLine(
                "loop: --blob-mode must be 1 (per-region) | 2 (per-container), "
                + $"got {f.BlobMode.ToString(inv)}");
            return (null, 2);
        }
        if (f.BarrierFill is not (0 or 1 or 2 or 4 or 8 or 16 or 32))
        {
            Console.Error.WriteLine(
                "loop: --barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), "
                + $"got {f.BarrierFill.ToString(inv)}");
            return (null, 2);
        }
        // --drbg is validated by Init: the C ABI enumerates no DRBG names.
        long? chunkSize = Size.ParseSize(f.ChunkSize);
        if (chunkSize is null)
        {
            Console.Error.WriteLine($"loop: --chunk-size: invalid size \"{f.ChunkSize}\"");
            return (null, 2);
        }
        if (f.Gomaxprocs < 0)
        {
            Console.Error.WriteLine(
                $"loop: --gomaxprocs must be > 0 when specified, got {f.Gomaxprocs.ToString(inv)}");
            return (null, 2);
        }
        if (f.RekeyEvery < 0)
        {
            Console.Error.WriteLine(
                $"loop: --rekey-every must be >= 0, got {f.RekeyEvery.ToString(inv)}");
            return (null, 2);
        }
        if (f.BlobCycleEvery < 0)
        {
            Console.Error.WriteLine(
                $"loop: --blob-cycle-every must be >= 0, got {f.BlobCycleEvery.ToString(inv)}");
            return (null, 2);
        }
        PayloadMode? payloadMode = Payload.Parse(f.PayloadMode);
        if (payloadMode is null)
        {
            Console.Error.WriteLine(
                "loop: --payload-mode must be fixed | rotating | pattern-zero | pattern-ff | "
                + $"pattern-ascii, got \"{f.PayloadMode}\"");
            return (null, 2);
        }
        return (new Config
        {
            DurationNs = durationNs.Value,
            Iterations = f.Iterations,
            WorkersRequested = workers,
            Workers = workers,
            Shape = shape.Value,
            Hash = f.Hash,
            Mac = f.Mac,
            Payload = payload.Value,
            Memlimit = memlimit,
            MemlimitAuto = memlimitAuto,
            Gogc = (int)f.Gogc,
            Parallax = parallax,
            Wrapper = wrapper,
            Profile = f.Profile,
            KeyBits = f.KeyBits,
            NonceBits = f.NonceBits,
            BlobMode = f.BlobMode,
            ChunkSize = chunkSize.Value,
            BarrierFill = f.BarrierFill,
            Drbg = f.Drbg,
            Gomaxprocs = (int)f.Gomaxprocs,
            RekeyEvery = f.RekeyEvery,
            BlobCycleEvery = f.BlobCycleEvery,
            PayloadMode = payloadMode.Value,
            Seed = f.Seed,
            JsonOutput = f.JsonOutput,
            Memprofile = f.Memprofile,
        }, 0);
    }

    // --------------------------------------------------------------
    // Signals
    // --------------------------------------------------------------

    private static volatile bool _signalSeen;
    private static readonly List<PosixSignalRegistration> SignalRegistrations = [];

    /// <summary>
    /// Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
    /// while it waits for the workers; it turns the flag into the stop
    /// request every worker checks before starting an iteration, so a
    /// signal interrupts nothing mid-call — the in-flight encrypt /
    /// decrypt / compare completes, the worker returns, and the partial
    /// summary prints with the verdict the completed iterations earned.
    /// .NET-specific: the registration cancels the runtime's own
    /// default termination for both signals, and the registration
    /// objects are held for the life of the process because disposing
    /// one restores that default.
    /// </summary>
    private static void InstallSignals()
    {
        foreach (var sig in new[] { PosixSignal.SIGINT, PosixSignal.SIGTERM })
        {
            SignalRegistrations.Add(PosixSignalRegistration.Create(sig, ctx =>
            {
                ctx.Cancel = true;
                _signalSeen = true;
            }));
        }
    }

    // --------------------------------------------------------------
    // Pipelines
    // --------------------------------------------------------------

    /// <summary>
    /// Supplies the keystream-capable primitive for every layer the
    /// profile record leaves unnamed and the run engages: a missing
    /// parallax palette becomes three copies of the fill cipher (with
    /// the library's default segment size when the record carries
    /// none), a missing outer cipher becomes the fill cipher. These are
    /// opts overrides that fold into the resolved record the blob
    /// carries — a derived profile is never registered, so no name the
    /// receiver did not agree to reaches the wire. The second element
    /// is true when anything was filled; null after printing the
    /// validation message.
    /// </summary>
    private static (Opts Opts, bool Filled)? FillKeystreamLayers(
        string name, Opts opts, bool wantParallax, bool wantWrapper)
    {
        Profile p;
        try
        {
            p = Pipeline.Lookup(name);
        }
        catch (Exception)
        {
            Console.Error.WriteLine(
                $"loop: --profile \"{name}\" is not a registered triple profile");
            return null;
        }
        bool filled = false;
        if (wantParallax && p.Palette.Length == 0)
        {
            opts = opts.WithParallaxPalette(
                KeystreamFillCipher, KeystreamFillCipher, KeystreamFillCipher);
            if (p.Segment == 0)
            {
                // A recipe that never carried a palette never carried a
                // segment size either, and the schedule rejects zero.
                opts = opts.WithParallaxSegmentSize(KeystreamFillSegment);
            }
            filled = true;
        }
        if (wantWrapper && p.Outer.Length == 0)
        {
            opts = opts.WithOuterCipher(KeystreamFillCipher);
            filled = true;
        }
        return (opts, filled);
    }

    /// <summary>
    /// Constructs one Pipeline against profile with every flag-carried
    /// override in the opts string (zero values included — the shared
    /// library treats zero as "profile default"), then obtains the Init
    /// blob once through Save: the binding's init entry does not hand
    /// the blob back, and the bytes are the ones Init produced. Later
    /// blob reopens use the retained blob; Save is never called again.
    /// </summary>
    private static (Pipeline Pipe, byte[] Blob)? BuildPipeline(Config cfg, string profile)
    {
        var opts = new Opts()
            .WithInnerHash(cfg.Hash)
            .WithMacName(cfg.Mac)
            .WithParallax(cfg.Parallax)
            .WithWrapper(cfg.Wrapper)
            .WithKeyBits(cfg.KeyBits)
            .WithNonceBits(cfg.NonceBits)
            .WithBarrierFill(cfg.BarrierFill)
            .WithDrbg(cfg.Drbg)
            .WithChunkSize(cfg.ChunkSize);
        if (cfg.Profile.Length > 0)
        {
            var filled = FillKeystreamLayers(cfg.Profile, opts, cfg.Parallax, cfg.Wrapper);
            if (filled is null)
            {
                return null;
            }
            opts = filled.Value.Opts;
            if (filled.Value.Filled)
            {
                Console.Error.WriteLine(
                    $"loop: {cfg.Profile} leaves the requested keystream layers unnamed; "
                    + $"{KeystreamFillCipher} supplied for them");
            }
        }
        Pipeline pipe;
        try
        {
            pipe = Pipeline.Init(profile, opts);
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"loop: Init({profile}): {Worker.Detail(e)}");
            return null;
        }
        byte[] blob;
        try
        {
            blob = pipe.Save();
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"loop: Save({profile}): {Worker.Detail(e)}");
            pipe.Dispose();
            return null;
        }
        if (cfg.BlobMode == 2)
        {
            // The sizing mode is not an Opts knob: the Init blob is
            // edited and the pipeline reopened from it, so the retained
            // blob (the one blob-cycle reopens from) carries the edited
            // mode.
            pipe.Dispose();
            try
            {
                blob = SetInnerBlobMode(blob, 2);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"loop: rewrite blob mode: {e.Message}");
                return null;
            }
            try
            {
                pipe = Pipeline.Load(blob);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"loop: reload Mode 2 blob: {Worker.Detail(e)}");
                return null;
            }
        }
        LogPipelineInitialised(profile, blob);
        return (pipe, blob);
    }

    /// <summary>Prints the construction line with the recipe read back
    /// from the blob the Pipeline handed out, not echoed from the
    /// flags: every construction override is proven to have reached the
    /// library by the value the receiver would see. Record values that
    /// are empty (a No MAC profile's MAC, a mixed profile's single
    /// hash) print as "-".</summary>
    private static void LogPipelineInitialised(string profile, byte[] blob)
    {
        var inv = CultureInfo.InvariantCulture;
        Profile rec;
        try
        {
            rec = Pipeline.Inspect(blob);
        }
        catch (Exception e)
        {
            LogLine(
                $"pipeline initialised: profile={profile} blob={blob.Length.ToString(inv)} bytes "
                + $"(inspect: {Worker.Detail(e)})");
            return;
        }
        static string Dash(string s) => s.Length == 0 ? "-" : s;
        LogLine(
            $"pipeline initialised: profile={profile} blob={blob.Length.ToString(inv)} bytes "
            + $"hash={Dash(rec.Hash)} key-bits={rec.KeyBits.ToString(inv)} "
            + $"nonce-bits={(rec.NonceBits ?? 0).ToString(inv)} "
            + $"barrier-fill={(rec.BarrierFill ?? 0).ToString(inv)} "
            + $"chunk-size={rec.Chunk.ToString(inv)} mac={Dash(rec.Mac)} "
            + $"parallax={OnOff(rec.Parallax)} wrapper={OnOff(rec.Wrapper)}"
            + (rec.ContainerMode == 2 ? " container-mode=2" : "")
            + (rec.Drbg.Length > 0 ? $" drbg={rec.Drbg}" : ""));
    }

    /// <summary>Returns a copy of a wrap-layer session blob whose inner
    /// blob ("ib") carries the given container floor sizing mode
    /// (1 = per-region, 2 = per-container). The wrap layer's profile
    /// record carries its own "mode" (a string), so only the inner
    /// blob's integer field is set; no key is added, integers keep
    /// their literals, and strings are written without escaping the
    /// base64 alphabet.</summary>
    private static byte[] SetInnerBlobMode(byte[] blob, int mode)
    {
        var root = JsonNode.Parse(blob) as JsonObject
            ?? throw new FormatException("session blob is not a JSON object");
        if (root["ib"] is not JsonObject ib || !ib.ContainsKey("mode"))
        {
            throw new FormatException("inner blob mode field not found");
        }
        ib["mode"] = mode;
        using var buf = new MemoryStream();
        using (var w = new Utf8JsonWriter(buf, new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        }))
        {
            root.WriteTo(w);
        }
        return buf.ToArray();
    }

    // --------------------------------------------------------------
    // Run
    // --------------------------------------------------------------

    private static int Run(string[] args)
    {
        var inv = CultureInfo.InvariantCulture;
        var (cfg, code) = ParseFlags(args);
        if (cfg is null)
        {
            return code;
        }

        // Runtime shaping. A long run under allocation churn grows the
        // Go heap inside the shared library without bound unless a soft
        // limit paces the collector, so a limit is always in force: an
        // explicit --memlimit is set as given, and auto caps the heap
        // only when the runtime reports no limit at all (a limit already
        // installed from the environment is left standing). The GC
        // percentage and GOMAXPROCS are set only when their flag is
        // non-zero — a zero flag skips the setter rather than calling it
        // with zero, because zero is a real value to the GC-percent
        // setter, and a call would clobber whatever the environment
        // installed. All of it lands before any Pipeline exists so the
        // baselines are taken under the shaped runtime.
        if (cfg.MemlimitAuto)
        {
            if (Everanium.Itb3.Runtime.SetMemoryLimit(-1) == long.MaxValue)
            {
                Everanium.Itb3.Runtime.SetMemoryLimit(cfg.Memlimit);
            }
        }
        else
        {
            Everanium.Itb3.Runtime.SetMemoryLimit(cfg.Memlimit);
        }
        cfg.Memlimit = Everanium.Itb3.Runtime.SetMemoryLimit(-1);
        if (cfg.Gogc > 0)
        {
            Everanium.Itb3.Runtime.SetGCPercent(cfg.Gogc);
        }
        if (cfg.Gomaxprocs > 0)
        {
            Everanium.Itb3.Runtime.SetGOMAXPROCS(cfg.Gomaxprocs);
        }

        LogLine(
            $"start: duration={Size.HumanDuration(cfg.DurationNs)} "
            + $"iterations={cfg.Iterations.ToString(inv)} "
            + $"goroutines={cfg.WorkersRequested.ToString(inv)} "
            + $"workers={cfg.Workers.ToString(inv)} concurrency={Concurrency} "
            + $"shape={cfg.Shape.Name()} hash={cfg.Hash} mac={cfg.Mac} "
            + $"payload={Size.HumanBytes(cfg.Payload)} "
            + $"memlimit={Size.HumanBytes(cfg.Memlimit)} "
            + $"parallax={OnOff(cfg.Parallax)} wrapper={OnOff(cfg.Wrapper)}");
        LogLine(
            $"overrides: profile=\"{cfg.Profile}\" key-bits={cfg.KeyBits.ToString(inv)} "
            + $"nonce-bits={cfg.NonceBits.ToString(inv)} "
            + $"chunk-size={Size.HumanBytes(cfg.ChunkSize)} "
            + $"barrier-fill={cfg.BarrierFill.ToString(inv)} "
            + $"gomaxprocs={cfg.Gomaxprocs.ToString(inv)} "
            + $"rekey-every={cfg.RekeyEvery.ToString(inv)} "
            + $"blob-cycle-every={cfg.BlobCycleEvery.ToString(inv)} "
            + $"payload-mode={cfg.PayloadMode.Name()} seed={cfg.Seed.ToString(inv)} "
            + $"json-output={(cfg.JsonOutput ? "true" : "false")}"
            + (cfg.BlobMode != 1 ? $" blob-mode={cfg.BlobMode.ToString(inv)}" : "")
            + (cfg.Drbg.Length > 0 ? $" drbg={cfg.Drbg}" : ""));
        LogLine(
            $"policy: microbatch-tiers={PolicyLabel("ITB_MICROBATCH_TIERS")} "
            + $"hashpool-starters={PolicyLabel("ITB_HASHPOOL_STARTERS")}");

        // Pipeline construction — one shared handle per exercised shape.
        // stream and stream_one_shot share the streaming handle.
        string streamProfile = cfg.Profile.Length == 0 ? DefaultStreamProfile : cfg.Profile;
        string msgProfile = cfg.Profile.Length == 0 ? DefaultMessageProfile : cfg.Profile;
        var pipes = new Pipes();
        if (cfg.Shape is Shape.Stream or Shape.StreamOneShot or Shape.Both)
        {
            var built = BuildPipeline(cfg, streamProfile);
            if (built is null)
            {
                return 1;
            }
            pipes.Stream = built.Value.Pipe;
            pipes.StreamBlob = built.Value.Blob;
        }
        if (cfg.Shape is Shape.Message or Shape.Both)
        {
            var built = BuildPipeline(cfg, msgProfile);
            if (built is null)
            {
                return 1;
            }
            pipes.Msg = built.Value.Pipe;
            pipes.MsgBlob = built.Value.Blob;
        }

        // Allocation posture. Per-worker plaintexts are allocated once
        // and held for the whole run (rotating mode refills them in
        // place per iteration); the pump accumulators and the drain
        // scratch live inside each worker and are reused across
        // iterations; the message and one-shot outputs are allocated by
        // the binding per call and reclaimed per iteration. Under the
        // default fixed CSPRNG mode every worker's buffer is distinct,
        // so cross-worker data crossover is detectable; pattern modes
        // trade that property for content edge-case coverage.
        var states = new List<WorkerState>(cfg.Workers);
        for (int id = 0; id < cfg.Workers; id++)
        {
            var w = new WorkerState
            {
                Id = id,
                Plaintext = new byte[cfg.Payload],
                PayloadMode = cfg.PayloadMode,
                Seeded = cfg.Seed != 0,
                Rng = Payload.SeedWorker(cfg.Seed, id),
                Scratch = new byte[PumpSlice],
            };
            if (!Payload.Fill(cfg.PayloadMode, w.Seeded, ref w.Rng, w.Plaintext))
            {
                Console.Error.WriteLine("loop: payload fill: csprng");
                return 1;
            }
            states.Add(w);
        }

        InstallSignals();
        var r = new RunState
        {
            Cfg = cfg,
            StreamProfile = streamProfile,
            MsgProfile = msgProfile,
            Pipes = pipes,
            Workers = Enumerable.Range(0, cfg.Workers).Select(_ => new Counters()).ToArray(),
            WarmupDone = new Barrier(cfg.Workers + 1),
            Release = new Barrier(cfg.Workers + 1),
            Active = cfg.Workers,
        };

        // Warmup barrier. Every worker runs one iteration and waits; the
        // clock starts only once all of them have paid their first-call
        // costs (pool warm-up, lazy kernel dispatch, page faults on the
        // payload buffers, and on this runtime the tiered JIT's first
        // pass over the iteration body), and the RSS and pool baselines
        // taken here describe a process that has already run the whole
        // cipher path once per worker.
        long warmupStart = Stopwatch.GetTimestamp();
        var threads = new List<Thread>(cfg.Workers);
        foreach (var w in states)
        {
            var thread = new Thread(() => Worker.Run(r, w))
            {
                IsBackground = false,
                Name = "loop-worker-" + w.Id.ToString(inv),
            };
            threads.Add(thread);
            thread.Start();
        }
        r.WarmupDone.SignalAndWait();
        (long rssWarmup, _) = Summary.ReadRss();
        long[] poolWarmup = Summary.PoolSnapshot();
        LogLine(
            $"warmup: {cfg.Workers.ToString(inv)} workers x 1 iter completed in "
            + $"{Size.HumanDuration(Size.RoundTo(ElapsedNs(warmupStart), 100_000_000))} "
            + $"(baseline rss={Size.HumanBytes(rssWarmup)})");

        // Open the gate; the duration is a deadline the waiter below
        // enforces in duration mode.
        long start = Stopwatch.GetTimestamp();
        r.Release.SignalAndWait();

        // Wait for every worker, polling every 100 ms so the deadline
        // and a signal are both noticed promptly.
        long finish = start;
        lock (r.DoneLock)
        {
            while (r.Active > 0)
            {
                if (_signalSeen || (cfg.Iterations == 0 && ElapsedNs(start) >= cfg.DurationNs))
                {
                    r.Stop = true;
                }
                Monitor.Wait(r.DoneLock, 100);
            }
            if (r.FinishTimestamp != 0)
            {
                finish = r.FinishTimestamp;
            }
        }
        long elapsedNs = (long)((finish - start) * NsPerTick);
        (long rssFinal, long rssPeak) = Summary.ReadRss();
        long[] poolSteady = Summary.PoolSnapshot();
        foreach (var thread in threads)
        {
            thread.Join();
        }
        r.RssWarmup = rssWarmup;
        r.RssPeak = rssPeak;
        r.RssFinal = rssFinal;
        r.PoolWarmup = poolWarmup;
        r.PoolSteady = poolSteady;

        if (cfg.Memprofile.Length > 0)
        {
            try
            {
                Everanium.Itb3.Runtime.WriteHeapProfile(cfg.Memprofile);
                LogLine($"memprofile: heap profile written to {cfg.Memprofile}");
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"loop: memprofile: {Worker.Detail(e)}");
            }
        }

        int exit = Summary.Final(r, elapsedNs);
        r.Pipes.Stream?.Dispose();
        r.Pipes.Msg?.Dispose();
        return exit;
    }

    [DllImport("libc", EntryPoint = "signal")]
    private static extern IntPtr SysSignal(int sig, IntPtr handler);

    private const int Sigpipe = 13;

    private static int Main(string[] args)
    {
        // .NET-specific. The runtime ignores SIGPIPE and the console
        // stream drops a write to a closed pipe without a word, so a
        // consumer that stops reading leaves the process printing into
        // nothing and exiting 0 with its verdict undelivered. With the
        // default disposition back the first such write ends the
        // process, which is what every other implementation does and
        // what a fleet driver expects.
        SysSignal(Sigpipe, IntPtr.Zero);

        // .NET-specific. Number rendering is part of the output
        // contract, so the process runs under the invariant culture
        // rather than the operator's locale; every formatter names the
        // culture as well, and this pin is the second line of defence.
        CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
        CultureInfo.DefaultThreadCurrentUICulture = CultureInfo.InvariantCulture;
        return Run(args);
    }
}
