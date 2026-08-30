// Managed lifetime wrapper around the Triple Pipeline handle.

namespace Itb;

/// <summary>
/// A Triple Pipeline session plus its exported blob bytes.
///
/// The blob carries the session bundle the receiver feeds to
/// <see cref="Open"/>; <see cref="Rekey"/> refreshes it. Disposing
/// the Pipeline frees the handle (libitb zeroes key material
/// internally); an undisposed Pipeline is reclaimed by the
/// SafeHandle finalizer.
///
/// Streaming-decrypt caveat: chunked Streaming AEAD verifies per
/// chunk, so plaintext of verified chunks is released before a later
/// chunk can fail authentication.
/// </summary>
public sealed unsafe class Pipeline : IDisposable
{
    /// <summary>Floor capacity for blob output buffers (Init /
    /// Rekey).</summary>
    private const int BlobCap = 64 * 1024;

    private readonly PipelineHandle _handle;
    private byte[] _blob;

    private Pipeline(PipelineHandle handle, byte[] blob)
    {
        _handle = handle;
        _blob = blob;
    }

    /// <summary>The exported session bundle bytes for the receiver
    /// side.</summary>
    public ReadOnlySpan<byte> Blob => _blob;

    /// <summary>
    /// Constructs a fresh Pipeline against the named profile. On a
    /// blob-buffer retry the Init re-runs and yields a fresh session
    /// (the undersized attempt is closed by libitb before returning).
    /// </summary>
    public static Pipeline Init(string profile, Opts? opts = null)
    {
        string optsStr = opts?.Build() ?? string.Empty;
        var blob = new byte[BlobCap];
        nuint blobLen;
        PipelineHandle handle;
        int rc;
        fixed (byte* p = blob)
        {
            rc = NativeMethods.ITB_Triple_Init(
                profile, optsStr, p, (nuint)blob.Length, out blobLen, out handle);
        }
        // Retry only when the reported length strictly exceeds the
        // current capacity — pattern P1 in the fleet audit.
        if (rc == (int)Status.BufferTooSmall && blobLen > (nuint)blob.Length)
        {
            handle.Dispose();
            blob = new byte[checked((int)blobLen)];
            fixed (byte* p = blob)
            {
                rc = NativeMethods.ITB_Triple_Init(
                    profile, optsStr, p, (nuint)blob.Length, out blobLen, out handle);
            }
        }
        if (rc != (int)Status.Ok)
        {
            handle.Dispose();
            throw ItbException.FromRc(rc);
        }
        return new Pipeline(handle, Shrink(blob, blobLen));
    }

    /// <summary>
    /// Reconstructs a Pipeline from a blob produced by
    /// <see cref="Init"/> or <see cref="Rekey"/>. Omitting
    /// <paramref name="permMaster"/> / <paramref name="wrapMaster"/>
    /// uses the blob-embedded masters; supplying both (non-empty)
    /// overrides them.
    /// </summary>
    public static Pipeline Open(
        string profile, ReadOnlySpan<byte> blob, Opts? opts = null,
        byte[]? permMaster = null, byte[]? wrapMaster = null)
    {
        if ((permMaster is null) != (wrapMaster is null))
        {
            throw new ArgumentException(
                "permMaster and wrapMaster must be supplied together or not at all");
        }
        string optsStr = opts?.Build() ?? string.Empty;
        nuint mastersCount = permMaster is null ? 0u : 2u;
        var pm = permMaster ?? Array.Empty<byte>();
        var wm = wrapMaster ?? Array.Empty<byte>();
        PipelineHandle handle;
        int rc;
        fixed (byte* pb = blob)
        fixed (byte* pp = pm)
        fixed (byte* pw = wm)
        {
            rc = NativeMethods.ITB_Triple_Open(
                profile, pb, (nuint)blob.Length, optsStr,
                pp, (nuint)pm.Length, pw, (nuint)wm.Length,
                mastersCount, out handle);
        }
        if (rc != (int)Status.Ok)
        {
            handle.Dispose();
            throw ItbException.FromRc(rc);
        }
        return new Pipeline(handle, blob.ToArray());
    }

    /// <summary>
    /// Registers a user-defined Triple profile under
    /// <paramref name="name"/> so subsequent <see cref="Init"/> /
    /// <see cref="Open"/> calls resolve it. The opts follow the
    /// register-profile grammar validated by Go (<c>mode</c>,
    /// <c>width</c>, <c>innerHash</c> / <c>innerHashes</c>,
    /// <c>keyBits</c>, <c>macName</c>, <c>outerCipher</c>,
    /// <c>parallaxPalette</c>, <c>parallaxSegmentSize</c>,
    /// <c>chunkSize</c>, <c>parallaxOn</c>, <c>wrapperOn</c>) — build
    /// them with <see cref="Opts.WithRaw"/> plus the typed setters
    /// where key names coincide. A duplicate name fails with
    /// <see cref="Status.ProfileExists"/>.
    /// </summary>
    public static void RegisterProfile(string name, Opts opts)
    {
        ItbException.Check(NativeMethods.ITB_Triple_RegisterProfile(name, opts.Build()));
    }

    /// <summary>
    /// Rotates the parallax + wrapper masters and refreshes
    /// <see cref="Blob"/>. Must not run concurrently with cipher
    /// calls or open stream sessions on the same Pipeline.
    /// </summary>
    public void Rekey(ReadOnlySpan<byte> permMaster, ReadOnlySpan<byte> wrapMaster)
    {
        var blob = new byte[Math.Max(BlobCap, _blob.Length)];
        nuint blobLen;
        int rc;
        fixed (byte* pp = permMaster)
        fixed (byte* pw = wrapMaster)
        {
            fixed (byte* pb = blob)
            {
                rc = NativeMethods.ITB_Triple_Rekey(
                    _handle, pp, (nuint)permMaster.Length, pw, (nuint)wrapMaster.Length,
                    pb, (nuint)blob.Length, out blobLen);
            }
            if (rc == (int)Status.BufferTooSmall && blobLen > (nuint)blob.Length)
            {
                blob = new byte[checked((int)blobLen)];
                fixed (byte* pb = blob)
                {
                    rc = NativeMethods.ITB_Triple_Rekey(
                        _handle, pp, (nuint)permMaster.Length, pw, (nuint)wrapMaster.Length,
                        pb, (nuint)blob.Length, out blobLen);
                }
            }
        }
        ItbException.Check(rc);
        _blob = Shrink(blob, blobLen);
    }

    /// <summary>
    /// Zeroes the Pipeline's key material and marks it closed.
    /// Idempotent; subsequent cipher calls fail with
    /// <see cref="Status.TripleClosed"/>. The handle itself is
    /// released by <see cref="Dispose"/>.
    /// </summary>
    public void Close()
    {
        ItbException.Check(NativeMethods.ITB_Triple_Close(_handle));
    }

    /// <summary>Single Message encrypt: one call, one self-contained
    /// wire.</summary>
    public byte[] EncryptMessage(ReadOnlySpan<byte> plaintext) =>
        Cipher(NativeMethods.ITB_Triple_EncryptMessage, plaintext);

    /// <summary>Receive-side counterpart of
    /// <see cref="EncryptMessage"/>.</summary>
    public byte[] DecryptMessage(ReadOnlySpan<byte> wire) =>
        Cipher(NativeMethods.ITB_Triple_DecryptMessage, wire);

    /// <summary>
    /// One-shot stream encrypt for callers holding the whole
    /// plaintext in memory. For bounded-memory streaming use
    /// <see cref="BeginEncryptStream"/> /
    /// <see cref="EncryptStreamPump"/>.
    /// </summary>
    public byte[] EncryptStreamOneShot(ReadOnlySpan<byte> plaintext) =>
        Cipher(NativeMethods.ITB_Triple_EncryptStream, plaintext);

    /// <summary>Receive-side counterpart of
    /// <see cref="EncryptStreamOneShot"/>.</summary>
    public byte[] DecryptStreamOneShot(ReadOnlySpan<byte> wire) =>
        Cipher(NativeMethods.ITB_Triple_DecryptStream, wire);

    /// <summary>Opens an incremental encrypt session (plaintext in,
    /// wire out).</summary>
    public EncryptStream BeginEncryptStream() => new(this);

    /// <summary>Opens an incremental decrypt session (wire in,
    /// plaintext out).</summary>
    public DecryptStream BeginDecryptStream() => new(this);

    /// <summary>
    /// Pumps <paramref name="source"/> through an encrypt session
    /// into <paramref name="destination"/> with bounded memory: feed
    /// a block, drain available wire, repeat; end + final drain on
    /// source EOF. The session is freed on return.
    /// </summary>
    public void EncryptStreamPump(System.IO.Stream source, System.IO.Stream destination)
    {
        using var session = BeginEncryptStream();
        session.Pump(source, destination);
    }

    /// <summary>Receive-side counterpart of
    /// <see cref="EncryptStreamPump"/>.</summary>
    public void DecryptStreamPump(System.IO.Stream source, System.IO.Stream destination)
    {
        using var session = BeginDecryptStream();
        session.Pump(source, destination);
    }

    public void Dispose() => _handle.Dispose();

    internal PipelineHandle Handle => _handle;

    /// <summary>Pre-allocation formula for Message / one-shot stream
    /// outputs: <c>max(131072, payload * 5/4 + 131072)</c>.</summary>
    private static int OutCap(int payload)
    {
        long cap = (long)payload + payload / 4 + 131_072;
        return (int)Math.Min(int.MaxValue, Math.Max(131_072, cap));
    }

    /// <summary>
    /// Shared body for the four buffer-in / buffer-out cipher
    /// entries: pre-allocate, and on <see cref="Status.BufferTooSmall"/>
    /// retry once with the exact size the FFI reported through the
    /// length out-param.
    /// </summary>
    private byte[] Cipher(NativeMethods.CipherFn fn, ReadOnlySpan<byte> src)
    {
        var buf = new byte[OutCap(src.Length)];
        nuint len;
        int rc;
        fixed (byte* ps = src)
        {
            fixed (byte* pd = buf)
            {
                rc = fn(_handle, ps, (nuint)src.Length, pd, (nuint)buf.Length, out len);
            }
            if (rc == (int)Status.BufferTooSmall && len > (nuint)buf.Length)
            {
                buf = new byte[checked((int)len)];
                fixed (byte* pd = buf)
                {
                    rc = fn(_handle, ps, (nuint)src.Length, pd, (nuint)buf.Length, out len);
                }
            }
        }
        ItbException.Check(rc);
        return Shrink(buf, len);
    }

    private static byte[] Shrink(byte[] buf, nuint len)
    {
        int n = checked((int)len);
        if (n == buf.Length)
        {
            return buf;
        }
        return buf[..n];
    }
}
