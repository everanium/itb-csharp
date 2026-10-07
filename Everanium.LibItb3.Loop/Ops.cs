// The maintenance operations that mutate a live Pipeline handle
// between iterations: master rotation (--rekey-every) and blob
// reopen (--blob-cycle-every).

using System.Globalization;

namespace Everanium.Itb3.Loop;

internal static class Ops
{
    /// <summary>Byte length of each fresh master drawn for a rotation.
    /// Matches the size Init auto-generates for both the parallax and
    /// the wrapper master.</summary>
    private const int RekeyMasterSize = 32;

    /// <summary>
    /// Master rotation. Rotates the parallax + wrapper masters on every
    /// active Pipeline under the write lock and retains the refreshed
    /// blob for subsequent blob reopens. Masters are drawn fresh from
    /// the OS CSPRNG on every rotation regardless of --seed (master
    /// rotation is pipeline keying, not plaintext content); a disabled
    /// layer passes no bytes, which Rekey ignores. The eight inner
    /// seeds and the MAC key are untouched by design — Rekey targets
    /// only the two outer-layer master secrets.
    /// </summary>
    private static bool RekeyPipes(RunState r, int id, long iter)
    {
        var inv = CultureInfo.InvariantCulture;
        byte[] perm = [];
        byte[] wrap = [];
        if (r.Cfg.Parallax)
        {
            perm = new byte[RekeyMasterSize];
            if (!Payload.FillRandom(perm))
            {
                Worker.Fail(
                    r, id,
                    $"g{id.ToString(inv)} iter {iter.ToString(inv)}: csprng: parallax master");
                return false;
            }
        }
        if (r.Cfg.Wrapper)
        {
            wrap = new byte[RekeyMasterSize];
            if (!Payload.FillRandom(wrap))
            {
                Worker.Fail(
                    r, id,
                    $"g{id.ToString(inv)} iter {iter.ToString(inv)}: csprng: wrapper master");
                return false;
            }
        }

        r.PipesLock.EnterWriteLock();
        try
        {
            if (r.Pipes.Stream is not null)
            {
                try
                {
                    r.Pipes.StreamBlob = r.Pipes.Stream.Rekey(perm, wrap);
                }
                catch (Exception e)
                {
                    Worker.Fail(
                        r, id,
                        $"g{id.ToString(inv)} iter {iter.ToString(inv)}: "
                        + $"Rekey({r.StreamProfile}): {Worker.Detail(e)}");
                    return false;
                }
            }
            if (r.Pipes.Msg is not null)
            {
                try
                {
                    r.Pipes.MsgBlob = r.Pipes.Msg.Rekey(perm, wrap);
                }
                catch (Exception e)
                {
                    Worker.Fail(
                        r, id,
                        $"g{id.ToString(inv)} iter {iter.ToString(inv)}: "
                        + $"Rekey({r.MsgProfile}): {Worker.Detail(e)}");
                    return false;
                }
            }
        }
        finally
        {
            r.PipesLock.ExitWriteLock();
        }
        long n = Interlocked.Increment(ref r.Rekeys);
        Program.LogLine(
            $"rekey: g{id.ToString(inv)} iter {iter.ToString(inv)} "
            + $"rotated parallax + wrapper masters (rekey #{n.ToString(inv)})");
        return true;
    }

    /// <summary>
    /// Blob reopen. Reopens every active Pipeline from its retained
    /// blob under the write lock: a fresh handle is loaded from the
    /// blob, the running handle is freed, and the fresh one is swapped
    /// in, so every later iteration round-trips through seeds and
    /// masters that survived a blob crossing. The input is the blob
    /// Init or the latest Rekey handed out, not a fresh Save: that is
    /// what a receiver holds, and reopening from it proves the
    /// handed-out bytes rather than the live state. The blob carries
    /// the Pipeline's full shape, so no override reaches the reopen. On
    /// a Load failure the running handle stays and the failure aborts
    /// the run.
    /// </summary>
    private static bool BlobCyclePipes(RunState r, int id, long iter)
    {
        var inv = CultureInfo.InvariantCulture;
        r.PipesLock.EnterWriteLock();
        try
        {
            if (r.Pipes.Stream is not null)
            {
                Pipeline fresh;
                try
                {
                    fresh = Pipeline.Load(r.Pipes.StreamBlob);
                }
                catch (Exception e)
                {
                    Worker.Fail(
                        r, id,
                        $"g{id.ToString(inv)} iter {iter.ToString(inv)}: "
                        + $"Load({r.StreamProfile}): {Worker.Detail(e)}");
                    return false;
                }
                r.Pipes.Stream.Dispose();
                r.Pipes.Stream = fresh;
            }
            if (r.Pipes.Msg is not null)
            {
                Pipeline fresh;
                try
                {
                    fresh = Pipeline.Load(r.Pipes.MsgBlob);
                }
                catch (Exception e)
                {
                    Worker.Fail(
                        r, id,
                        $"g{id.ToString(inv)} iter {iter.ToString(inv)}: "
                        + $"Load({r.MsgProfile}): {Worker.Detail(e)}");
                    return false;
                }
                r.Pipes.Msg.Dispose();
                r.Pipes.Msg = fresh;
            }
        }
        finally
        {
            r.PipesLock.ExitWriteLock();
        }
        long n = Interlocked.Increment(ref r.BlobCycles);
        Program.LogLine(
            $"blob-cycle: g{id.ToString(inv)} iter {iter.ToString(inv)} "
            + $"reopened from session blob (cycle #{n.ToString(inv)})");
        return true;
    }

    /// <summary>
    /// Handle mutation. Runs the periodic Pipeline-mutating operations
    /// after a completed iteration: master rotation (--rekey-every) and
    /// blob reopen (--blob-cycle-every). Both intervals count
    /// per-worker iterations; the warmup iteration (iter 0) never
    /// triggers because the worker loop calls this for iter >= 1 only.
    /// Rekey rewrites the outer-layer keying of a live handle and a
    /// blob reopen replaces the handle outright; each takes the write
    /// lock, so in-flight cipher calls on other workers drain before
    /// anything changes and no encrypt is separated from its decrypt by
    /// either. False after recording the worker error.
    /// </summary>
    internal static bool Maintenance(RunState r, int id, long iter)
    {
        var cfg = r.Cfg;
        if (cfg.RekeyEvery > 0 && iter % cfg.RekeyEvery == 0 && !RekeyPipes(r, id, iter))
        {
            return false;
        }
        if (cfg.BlobCycleEvery > 0
            && iter % cfg.BlobCycleEvery == 0
            && !BlobCyclePipes(r, id, iter))
        {
            return false;
        }
        return true;
    }
}
