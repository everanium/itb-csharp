// The worker: its thread body (one warmup iteration, the warmup
// barrier, the main loop), one iteration, the session pump loop the
// stream shape drives, and the round-trip comparison that decides
// between a worker error and a data mismatch.

using System.Diagnostics;
using System.Globalization;

namespace Everanium.Itb3.Loop;

/// <summary>Cipher surfaces the --shape flag selects.</summary>
internal enum Shape
{
    /// <summary>Session pump: begin / write / read / end.</summary>
    Stream,

    /// <summary>Single Message: one whole-buffer call.</summary>
    Message,

    /// <summary>Stream surface, one whole-buffer call.</summary>
    StreamOneShot,

    /// <summary>All three, rotating by iteration number.</summary>
    Both,
}

internal static class Worker
{
    private static readonly (string Name, Shape Shape)[] ShapeNames =
    [
        ("stream", Shape.Stream),
        ("message", Shape.Message),
        ("stream_one_shot", Shape.StreamOneShot),
        ("both", Shape.Both),
    ];

    internal static string Name(this Shape shape)
    {
        foreach (var (name, s) in ShapeNames)
        {
            if (s == shape)
            {
                return name;
            }
        }
        return "stream";
    }

    internal static Shape? ParseShape(string s)
    {
        foreach (var (name, s2) in ShapeNames)
        {
            if (name == s)
            {
                return s2;
            }
        }
        return null;
    }

    /// <summary>Renders a binding error the way every implementation
    /// reports a failed library call: <c>status &lt;code&gt;: &lt;last
    /// error&gt;</c>; any other failure carries its own text. The
    /// library assembles the whole sentence — the class of failure and
    /// the case that raised it — so this reports what arrived and
    /// composes nothing.</summary>
    internal static string Detail(Exception e)
    {
        if (e is not ItbException ie)
        {
            return e.Message;
        }
        var inv = CultureInfo.InvariantCulture;
        int code = (int)ie.Status;
        // The binding folds the diagnostic into the exception message
        // behind a fixed prefix; strip that prefix to recover the
        // library's own text.
        string prefix = $"itb: status={code.ToString(inv)} ({ie.Status}): ";
        string message = ie.Message.StartsWith(prefix, StringComparison.Ordinal)
            ? ie.Message[prefix.Length..]
            : ie.Message;
        return $"status {code.ToString(inv)}: {message}";
    }

    /// <summary>Records the worker's error text (first error wins) and
    /// requests a stop of the whole run.</summary>
    internal static void Fail(RunState r, int id, string text)
    {
        var c = r.Workers[id];
        lock (c.ErrorLock)
        {
            c.Error ??= text;
        }
        r.Stop = true;
    }

    /// <summary>
    /// Pump loop. The Go harness hands ITB an io.Reader / io.Writer
    /// pair and ITB drives the chunk loop internally; the C ABI has no
    /// reader / writer entry, so the caller drives it: open a session,
    /// feed slices of at most 1 MiB, drain whatever the session has
    /// produced after every write (a read before end never blocks),
    /// end, then drain until the session reports finished (after end, a
    /// read on an empty spool blocks until the terminal bytes arrive).
    /// The whole produced output lands in the worker's reusable
    /// accumulator. The loop is written here rather than delegated to
    /// the binding's pump convenience so it stands in the utility, at
    /// the same place, in every language. On failure the result names
    /// the failing call and carries its error.
    /// </summary>
    private static (string What, Exception Err)? Pump(
        Pipeline pipe, bool encrypt, byte[] src, int srcLen, MemoryStream acc, byte[] scratch)
    {
        acc.SetLength(0);
        EncryptStream? es = null;
        DecryptStream? ds = null;
        try
        {
            try
            {
                if (encrypt)
                {
                    es = pipe.BeginEncryptStream();
                }
                else
                {
                    ds = pipe.BeginDecryptStream();
                }
            }
            catch (Exception e)
            {
                return ("StreamBegin", e);
            }

            // .NET-specific. The two session directions are distinct
            // sealed types with identical members, so the loop body
            // reaches them through local functions rather than one
            // handle variable.
            void Write(ReadOnlySpan<byte> s)
            {
                if (es is not null)
                {
                    es.Write(s);
                }
                else
                {
                    ds!.Write(s);
                }
            }

            int Read(Span<byte> d, out bool finished) =>
                es is not null ? es.Read(d, out finished) : ds!.Read(d, out finished);

            void End()
            {
                if (es is not null)
                {
                    es.End();
                }
                else
                {
                    ds!.End();
                }
            }

            for (int off = 0; off < srcLen; off += Program.PumpSlice)
            {
                int n = Math.Min(Program.PumpSlice, srcLen - off);
                try
                {
                    Write(src.AsSpan(off, n));
                }
                catch (Exception e)
                {
                    return ("StreamWrite", e);
                }
                while (true)
                {
                    int m;
                    try
                    {
                        m = Read(scratch, out _);
                    }
                    catch (Exception e)
                    {
                        return ("StreamRead", e);
                    }
                    if (m == 0)
                    {
                        break;
                    }
                    acc.Write(scratch, 0, m);
                }
            }
            try
            {
                End();
            }
            catch (Exception e)
            {
                return ("StreamEnd", e);
            }
            while (true)
            {
                int m;
                bool finished;
                try
                {
                    m = Read(scratch, out finished);
                }
                catch (Exception e)
                {
                    return ("StreamRead", e);
                }
                acc.Write(scratch, 0, m);
                if (finished)
                {
                    break;
                }
            }
            return null;
        }
        finally
        {
            es?.Dispose();
            ds?.Dispose();
        }
    }

    /// <summary>First offset at which a and b differ; the shorter
    /// length when one is a prefix of the other.</summary>
    private static int FirstDifference(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        int n = Math.Min(a.Length, b.Length);
        for (int i = 0; i < n; i++)
        {
            if (a[i] != b[i])
            {
                return i;
            }
        }
        return n;
    }

    /// <summary>Up to 16 bytes of buf from off as lowercase hex, or "-"
    /// when buf has no bytes there.</summary>
    private static string HexWindow(ReadOnlySpan<byte> buf, int off)
    {
        if (off >= buf.Length)
        {
            return "-";
        }
        int n = Math.Min(16, buf.Length - off);
        return Convert.ToHexStringLower(buf.Slice(off, n));
    }

    /// <summary>Records a worker error for a failed cipher call.</summary>
    private static void CipherFail(
        RunState r, int id, long iter, Shape shape, string direction, string? what, Exception e)
    {
        var inv = CultureInfo.InvariantCulture;
        string head = $"g{id.ToString(inv)} iter {iter.ToString(inv)} shape={shape.Name()}: {direction}";
        Fail(r, id, what is null
            ? $"{head}: {Detail(e)}"
            : $"{head}: {what}: {Detail(e)}");
    }

    /// <summary>
    /// One iteration. In order: refill the plaintext under rotating
    /// mode; take the read lock; pick the surface; encrypt (timed);
    /// decrypt (timed); compare the round-trip with the plaintext; bump
    /// the counters; release the lock. The whole round-trip runs under
    /// the read lock so handle-mutating maintenance (rekey, blob
    /// reopen) never lands between an encrypt and its matching decrypt
    /// — maintenance runs after this returns, from the worker loop.
    /// False after recording a worker error.
    /// </summary>
    private static bool Iterate(RunState r, WorkerState w, long iter)
    {
        var inv = CultureInfo.InvariantCulture;
        var c = r.Workers[w.Id];
        if (w.PayloadMode == PayloadMode.Rotating
            && !Payload.Fill(PayloadMode.Rotating, w.Seeded, ref w.Rng, w.Plaintext))
        {
            Fail(r, w.Id, $"g{w.Id.ToString(inv)} iter {iter.ToString(inv)}: payload refill: csprng");
            return false;
        }

        r.PipesLock.EnterReadLock();
        try
        {
            // Shape dispatch. message is one whole-buffer call on the
            // Single Message Pipeline; stream_one_shot is one
            // whole-buffer call on the streaming Pipeline (the C ABI's
            // ITB_Triple_EncryptStream, which routes to the same
            // one-shot stream entry the Go harness calls by name);
            // stream opens a session on the same streaming Pipeline and
            // drives the chunk loop from here. Under both the three
            // rotate by iteration number so the session path and the
            // whole-buffer path alternate on one handle inside every
            // worker — the cross-path state-reuse hazard this harness
            // exists to catch.
            Shape shape = r.Cfg.Shape;
            if (shape == Shape.Both)
            {
                shape = (iter % 3) switch
                {
                    0 => Shape.Stream,
                    1 => Shape.Message,
                    _ => Shape.StreamOneShot,
                };
            }

            // .NET-specific. The message and one-shot entries return a
            // fresh array per call that the collector reclaims at the
            // end of the iteration; the pump accumulators are the
            // worker's own and are reused. `got` / `gotLen` hold the
            // round-trip output for either posture, so one comparison
            // below serves both.
            byte[] got;
            int gotLen;
            long t0;
            switch (shape)
            {
                case Shape.Stream:
                {
                    var pipe = r.Pipes.Stream!;
                    t0 = Stopwatch.GetTimestamp();
                    var fail = Pump(pipe, true, w.Plaintext, w.Plaintext.Length, w.Wire, w.Scratch);
                    if (fail is not null)
                    {
                        CipherFail(r, w.Id, iter, shape, "encrypt", fail.Value.What, fail.Value.Err);
                        return false;
                    }
                    c.AddEncrypt(Program.ElapsedNs(t0));
                    t0 = Stopwatch.GetTimestamp();
                    fail = Pump(
                        pipe, false, w.Wire.GetBuffer(), (int)w.Wire.Length, w.Plain, w.Scratch);
                    if (fail is not null)
                    {
                        CipherFail(r, w.Id, iter, shape, "decrypt", fail.Value.What, fail.Value.Err);
                        return false;
                    }
                    c.AddDecrypt(Program.ElapsedNs(t0));
                    got = w.Plain.GetBuffer();
                    gotLen = (int)w.Plain.Length;
                    break;
                }

                case Shape.StreamOneShot:
                {
                    var pipe = r.Pipes.Stream!;
                    byte[] wire;
                    t0 = Stopwatch.GetTimestamp();
                    try
                    {
                        wire = pipe.EncryptStreamOneShot(w.Plaintext);
                    }
                    catch (Exception e)
                    {
                        CipherFail(r, w.Id, iter, shape, "encrypt", null, e);
                        return false;
                    }
                    c.AddEncrypt(Program.ElapsedNs(t0));
                    t0 = Stopwatch.GetTimestamp();
                    try
                    {
                        got = pipe.DecryptStreamOneShot(wire);
                    }
                    catch (Exception e)
                    {
                        CipherFail(r, w.Id, iter, shape, "decrypt", null, e);
                        return false;
                    }
                    c.AddDecrypt(Program.ElapsedNs(t0));
                    gotLen = got.Length;
                    break;
                }

                default:
                {
                    var pipe = r.Pipes.Msg!;
                    byte[] wire;
                    t0 = Stopwatch.GetTimestamp();
                    try
                    {
                        wire = pipe.EncryptMessage(w.Plaintext);
                    }
                    catch (Exception e)
                    {
                        CipherFail(r, w.Id, iter, shape, "encrypt", null, e);
                        return false;
                    }
                    c.AddEncrypt(Program.ElapsedNs(t0));
                    t0 = Stopwatch.GetTimestamp();
                    try
                    {
                        got = pipe.DecryptMessage(wire);
                    }
                    catch (Exception e)
                    {
                        CipherFail(r, w.Id, iter, shape, "decrypt", null, e);
                        return false;
                    }
                    c.AddDecrypt(Program.ElapsedNs(t0));
                    gotLen = got.Length;
                    break;
                }
            }

            // Failure model. A cipher call that returns a non-OK status
            // is a worker error: it is recorded, the run is asked to
            // stop, the other workers finish their in-flight iteration,
            // and the error is listed in the summary with the FAIL
            // verdict. A round-trip that returns OK with different
            // bytes is a data mismatch: the process terminates here,
            // without summary or cleanup, because the Pipeline state
            // that produced the wrong bytes is the evidence and nothing
            // that runs afterwards may touch it. .NET-specific:
            // Environment.Exit is the exit that leaves handle
            // finalizers unrun, which is the point — a
            // finalizer-driven free would release the very state the
            // operator is meant to inspect.
            var want = w.Plaintext.AsSpan();
            var gotSpan = got.AsSpan(0, gotLen);
            if (!want.SequenceEqual(gotSpan))
            {
                int off = FirstDifference(want, gotSpan);
                Console.Error.WriteLine(
                    $"loop: DATA MISMATCH g{w.Id.ToString(inv)} iter {iter.ToString(inv)} "
                    + $"shape={shape.Name()}: want {want.Length.ToString(inv)} bytes, "
                    + $"got {gotLen.ToString(inv)} bytes, "
                    + $"first difference at offset {off.ToString(inv)}: "
                    + $"want {HexWindow(want, off)} got {HexWindow(gotSpan, off)}");
                Console.Error.Flush();
                Environment.Exit(3);
            }

            c.AddIteration(want.Length, gotLen);
            return true;
        }
        finally
        {
            r.PipesLock.ExitReadLock();
        }
    }

    /// <summary>Marks this worker returned; the last one to return
    /// stamps the finish instant and wakes main.</summary>
    private static void Done(RunState r)
    {
        lock (r.DoneLock)
        {
            r.Active--;
            if (r.Active == 0)
            {
                r.FinishTimestamp = Stopwatch.GetTimestamp();
                Monitor.Pulse(r.DoneLock);
            }
        }
    }

    /// <summary>
    /// The worker thread body: one warmup iteration, the warmup
    /// barrier, then the main loop until a stop is requested or the
    /// fixed per-worker iteration budget (warmup included) is spent. A
    /// failing warmup still passes both barriers so the launcher never
    /// waits on a worker that has already given up.
    /// </summary>
    internal static void Run(RunState r, WorkerState w)
    {
        // Warmup iteration — counted in the totals; its completion feeds
        // the post-warmup baselines.
        bool ok = Iterate(r, w, 0);
        r.WarmupDone.SignalAndWait();
        r.Release.SignalAndWait();
        if (!ok)
        {
            Done(r);
            return;
        }

        for (long iter = 1; ; iter++)
        {
            if (r.Cfg.Iterations > 0 && iter >= r.Cfg.Iterations)
            {
                break;
            }
            if (r.Stop)
            {
                break;
            }
            if (!Iterate(r, w, iter))
            {
                break;
            }
            if (!Ops.Maintenance(r, w.Id, iter))
            {
                break;
            }
        }
        Done(r);
    }
}
