// Incremental stream sessions over an open Pipeline.
//
// A session is a dumb byte pump: EncryptStream takes plaintext in
// through Write and yields wire through Read / CopyTo; DecryptStream
// is the mirror (wire in, plaintext out). All chunking, MAC,
// envelope, and wire-format decisions stay inside libitb. Disposing
// a session cancels it and frees the Go-side state; the session
// keeps a reference to the parent Pipeline so the pipeline object
// stays reachable while a session on it is live.

namespace Itb;

/// <summary>Shared body for the two session directions.</summary>
internal sealed unsafe class StreamSession : IDisposable
{
    /// <summary>Feed / drain block size used by the pump loops.</summary>
    internal const int PumpBuf = 1 << 20;

    private readonly StreamHandle _handle;
    // Keeps the parent Pipeline reachable while the session is live.
    private readonly Pipeline _pipe;
    private bool _ended;

    internal StreamSession(Pipeline pipe, bool encrypt)
    {
        _pipe = pipe;
        int rc = encrypt
            ? NativeMethods.ITB_Triple_EncryptStreamBegin(pipe.Handle, out _handle)
            : NativeMethods.ITB_Triple_DecryptStreamBegin(pipe.Handle, out _handle);
        if (rc != (int)Status.Ok)
        {
            _handle.Dispose();
            throw ItbException.FromRc(rc);
        }
    }

    internal void Write(ReadOnlySpan<byte> src)
    {
        int rc;
        fixed (byte* p = src)
        {
            rc = NativeMethods.ITB_Triple_StreamWrite(_handle, p, (nuint)src.Length);
        }
        ItbException.Check(rc);
    }

    internal void End()
    {
        ItbException.Check(NativeMethods.ITB_Triple_StreamEnd(_handle));
        _ended = true;
    }

    internal int Read(Span<byte> dst, out bool finished)
    {
        nuint n;
        int fin;
        int rc;
        fixed (byte* p = dst)
        {
            rc = NativeMethods.ITB_Triple_StreamRead(
                _handle, p, (nuint)dst.Length, out n, out fin);
        }
        ItbException.Check(rc);
        finished = fin != 0;
        return checked((int)n);
    }

    internal void CopyTo(System.IO.Stream destination)
    {
        if (!_ended)
        {
            End();
        }
        var buf = new byte[PumpBuf];
        while (true)
        {
            int n = Read(buf, out bool finished);
            destination.Write(buf, 0, n);
            if (finished)
            {
                return;
            }
        }
    }

    internal void Pump(System.IO.Stream source, System.IO.Stream destination)
    {
        var inBuf = new byte[PumpBuf];
        var outBuf = new byte[PumpBuf];
        int n;
        while ((n = source.Read(inBuf, 0, inBuf.Length)) > 0)
        {
            Write(inBuf.AsSpan(0, n));
            // Drain whatever the chain has produced so far; a read
            // before End() never blocks.
            while (true)
            {
                int m = Read(outBuf, out _);
                if (m == 0)
                {
                    break;
                }
                destination.Write(outBuf, 0, m);
            }
        }
        End();
        while (true)
        {
            int m = Read(outBuf, out bool finished);
            if (m > 0)
            {
                destination.Write(outBuf, 0, m);
            }
            if (finished)
            {
                break;
            }
        }
        destination.Flush();
    }

    /// <summary>The parent Pipeline this session runs against.</summary>
    internal Pipeline Pipeline => _pipe;

    public void Dispose() => _handle.Dispose();
}

/// <summary>
/// Incremental encrypt session: plaintext in through
/// <see cref="Write"/>, wire out through <see cref="Read"/> /
/// <see cref="CopyTo"/>. Disposing cancels the session and frees the
/// Go-side state.
/// </summary>
public sealed class EncryptStream : IDisposable
{
    private readonly StreamSession _session;

    internal EncryptStream(Pipeline pipe) => _session = new StreamSession(pipe, encrypt: true);

    /// <summary>Feeds bytes into the session. Blocks until the cipher
    /// chain accepts them; errors are sticky.</summary>
    public void Write(ReadOnlySpan<byte> src) => _session.Write(src);

    /// <summary>Signals end-of-input. Idempotent; <see cref="Write"/>
    /// after End fails with <see cref="Status.BadInput"/>.</summary>
    public void End() => _session.End();

    /// <summary>
    /// Drains up to <paramref name="dst"/>.Length produced bytes;
    /// returns the count read and sets <paramref name="finished"/>
    /// when the session output is complete. Partial drains are
    /// normal. After End, an empty-spool read blocks until the
    /// terminal bytes arrive or the session errors.
    /// </summary>
    public int Read(Span<byte> dst, out bool finished) => _session.Read(dst, out finished);

    /// <summary>Calls <see cref="End"/> (if not yet called) and
    /// writes every remaining output byte to
    /// <paramref name="destination"/>.</summary>
    public void CopyTo(System.IO.Stream destination) => _session.CopyTo(destination);

    internal void Pump(System.IO.Stream source, System.IO.Stream destination) =>
        _session.Pump(source, destination);

    public void Dispose() => _session.Dispose();
}

/// <summary>
/// Incremental decrypt session: wire in through <see cref="Write"/>,
/// plaintext out through <see cref="Read"/> / <see cref="CopyTo"/>.
/// Disposing cancels the session and frees the Go-side state.
/// </summary>
public sealed class DecryptStream : IDisposable
{
    private readonly StreamSession _session;

    internal DecryptStream(Pipeline pipe) => _session = new StreamSession(pipe, encrypt: false);

    /// <summary>Feeds bytes into the session. Blocks until the cipher
    /// chain accepts them; errors are sticky.</summary>
    public void Write(ReadOnlySpan<byte> src) => _session.Write(src);

    /// <summary>Signals end-of-input. Idempotent; <see cref="Write"/>
    /// after End fails with <see cref="Status.BadInput"/>.</summary>
    public void End() => _session.End();

    /// <summary>
    /// Drains up to <paramref name="dst"/>.Length produced bytes;
    /// returns the count read and sets <paramref name="finished"/>
    /// when the session output is complete. Partial drains are
    /// normal. After End, an empty-spool read blocks until the
    /// terminal bytes arrive or the session errors.
    /// </summary>
    public int Read(Span<byte> dst, out bool finished) => _session.Read(dst, out finished);

    /// <summary>Calls <see cref="End"/> (if not yet called) and
    /// writes every remaining output byte to
    /// <paramref name="destination"/>.</summary>
    public void CopyTo(System.IO.Stream destination) => _session.CopyTo(destination);

    internal void Pump(System.IO.Stream source, System.IO.Stream destination) =>
        _session.Pump(source, destination);

    public void Dispose() => _session.Dispose();
}
