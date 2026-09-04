// Managed lifetime wrapper around the Triple Pipeline handle.

using System.Text;

namespace Itb;

/// <summary>
/// A Triple Pipeline session.
///
/// <see cref="Save"/> exports the self-describing session blob the
/// receiver feeds to <see cref="Load"/> / <see cref="LoadF"/>;
/// <see cref="Rekey"/> refreshes it. Disposing the Pipeline frees the
/// handle (libitb zeroes key material internally); an undisposed
/// Pipeline is reclaimed by the SafeHandle finalizer.
///
/// Streaming-decrypt caveat: chunked Streaming AEAD verifies per
/// chunk, so plaintext of verified chunks is released before a later
/// chunk can fail authentication.
/// </summary>
public sealed unsafe class Pipeline : IDisposable
{
    /// <summary>Floor capacity for blob output buffers (Init / Save /
    /// Rekey).</summary>
    private const int BlobCap = 64 * 1024;

    /// <summary>Floor capacity for profile-JSON output buffers
    /// (Inspect / Lookup / Profiles).</summary>
    private const int JsonCap = 4 * 1024;

    private readonly PipelineHandle _handle;

    private Pipeline(PipelineHandle handle)
    {
        _handle = handle;
    }

    /// <summary>
    /// Constructs a fresh Pipeline against the named profile. On a
    /// blob-buffer retry the Init re-runs and yields a fresh session
    /// (the undersized attempt is closed by libitb before returning).
    /// The session blob is available through <see cref="Save"/>.
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
        return new Pipeline(handle);
    }

    /// <summary>
    /// Reconstructs a Pipeline from a blob produced by
    /// <see cref="Save"/> or <see cref="Rekey"/>. The blob's embedded
    /// profile record is the sole structural source. Omitting
    /// <paramref name="permMaster"/> / <paramref name="wrapMaster"/>
    /// uses the blob-embedded masters; supplying both (non-empty)
    /// overrides them.
    /// </summary>
    public static Pipeline Load(
        ReadOnlySpan<byte> blob, byte[]? permMaster = null, byte[]? wrapMaster = null)
    {
        nuint mastersCount = MastersCount(permMaster, wrapMaster);
        var pm = permMaster ?? Array.Empty<byte>();
        var wm = wrapMaster ?? Array.Empty<byte>();
        PipelineHandle handle;
        int rc;
        fixed (byte* pb = blob)
        fixed (byte* pp = pm)
        fixed (byte* pw = wm)
        {
            rc = NativeMethods.ITB_Triple_Load(
                pb, (nuint)blob.Length,
                pp, (nuint)pm.Length, pw, (nuint)wm.Length,
                mastersCount, out handle);
        }
        if (rc != (int)Status.Ok)
        {
            handle.Dispose();
            throw ItbException.FromRc(rc);
        }
        return new Pipeline(handle);
    }

    /// <summary><see cref="Load"/> for a blob stored in a file; the
    /// file is read inside the library. Same masters
    /// semantics.</summary>
    public static Pipeline LoadF(
        string path, byte[]? permMaster = null, byte[]? wrapMaster = null)
    {
        nuint mastersCount = MastersCount(permMaster, wrapMaster);
        var pm = permMaster ?? Array.Empty<byte>();
        var wm = wrapMaster ?? Array.Empty<byte>();
        PipelineHandle handle;
        int rc;
        fixed (byte* pp = pm)
        fixed (byte* pw = wm)
        {
            rc = NativeMethods.ITB_Triple_LoadF(
                path, pp, (nuint)pm.Length, pw, (nuint)wm.Length,
                mastersCount, out handle);
        }
        if (rc != (int)Status.Ok)
        {
            handle.Dispose();
            throw ItbException.FromRc(rc);
        }
        return new Pipeline(handle);
    }

    private static nuint MastersCount(byte[]? permMaster, byte[]? wrapMaster)
    {
        if ((permMaster is null) != (wrapMaster is null))
        {
            throw new ArgumentException(
                "permMaster and wrapMaster must be supplied together or not at all");
        }
        return permMaster is null ? 0u : 2u;
    }

    /// <summary>Decodes the blob's embedded profile record without
    /// opening a Pipeline. No registry read, no primitive
    /// probe.</summary>
    public static Profile Inspect(ReadOnlySpan<byte> blob)
    {
        byte[] json;
        fixed (byte* pb = blob)
        {
            byte* blobPtr = pb;
            nuint blobLen = (nuint)blob.Length;
            json = RetryOnce(JsonCap, (byte* dst, nuint cap, out nuint len) =>
                NativeMethods.ITB_Triple_Inspect(blobPtr, blobLen, dst, cap, out len));
        }
        return Profile.FromJson(Encoding.UTF8.GetString(json));
    }

    /// <summary>
    /// Registers <paramref name="profile"/> under
    /// <paramref name="name"/> so subsequent <see cref="Init"/> /
    /// <see cref="Lookup"/> calls resolve it. Every field rule is
    /// validated by Go; a duplicate name fails with
    /// <see cref="Status.ProfileExists"/>.
    /// </summary>
    public static void Register(string name, Profile profile)
    {
        ItbException.Check(NativeMethods.ITB_Triple_Register(name, profile.ToJson()));
    }

    /// <summary>Looks up a registered profile (shipped or
    /// <see cref="Register"/>ed) by name; an unknown name fails with
    /// <see cref="Status.UnknownProfile"/>.</summary>
    public static Profile Lookup(string name)
    {
        var json = RetryOnce(JsonCap, (byte* dst, nuint cap, out nuint len) =>
            NativeMethods.ITB_Triple_Lookup(name, dst, cap, out len));
        return Profile.FromJson(Encoding.UTF8.GetString(json));
    }

    /// <summary>The sorted names of every registered profile.</summary>
    public static string[] Profiles()
    {
        var json = RetryOnce(JsonCap, (byte* dst, nuint cap, out nuint len) =>
            NativeMethods.ITB_Triple_Profiles(dst, cap, out len));
        return Profile.StringsFromJson(Encoding.UTF8.GetString(json));
    }

    /// <summary>The current self-describing session blob: the bytes
    /// <see cref="Init"/> produced, the bytes <see cref="Load"/>
    /// re-marshalled, or the bytes of the latest
    /// <see cref="Rekey"/>.</summary>
    public byte[] Save() =>
        RetryOnce(BlobCap, (byte* dst, nuint cap, out nuint len) =>
            NativeMethods.ITB_Triple_Save(_handle, dst, cap, out len));

    /// <summary>Writes <see cref="Save"/> to <paramref name="path"/>
    /// inside the library with mode 0600; the containing directory
    /// must exist.</summary>
    public void SaveF(string path)
    {
        ItbException.Check(NativeMethods.ITB_Triple_SaveF(_handle, path));
    }

    /// <summary>Sets the worker cap for every subsequent cipher call.
    /// <paramref name="n"/> is clamped, never rejected: <c>n &lt;= 0</c>
    /// selects auto (CPU count), <c>n &gt; 256</c> is treated as 256.
    /// Only the handle statuses throw.</summary>
    public void MaxWorkers(int n)
    {
        ItbException.Check(NativeMethods.ITB_Triple_MaxWorkers(_handle, n));
    }

    /// <summary>
    /// Rotates the parallax + wrapper masters and returns the fresh
    /// session blob (also available through <see cref="Save"/>). Must
    /// not run concurrently with cipher calls or open stream sessions
    /// on the same Pipeline.
    /// </summary>
    public byte[] Rekey(ReadOnlySpan<byte> permMaster, ReadOnlySpan<byte> wrapMaster)
    {
        fixed (byte* pp = permMaster)
        fixed (byte* pw = wrapMaster)
        {
            byte* permPtr = pp;
            byte* wrapPtr = pw;
            nuint permLen = (nuint)permMaster.Length;
            nuint wrapLen = (nuint)wrapMaster.Length;
            return RetryOnce(BlobCap, (byte* dst, nuint cap, out nuint len) =>
                NativeMethods.ITB_Triple_Rekey(
                    _handle, permPtr, permLen, wrapPtr, wrapLen, dst, cap, out len));
        }
    }

    /// <summary>Shape shared by every variable-size output entry
    /// (Save / Rekey / Inspect / Lookup / Profiles).</summary>
    private delegate int OutFn(byte* dst, nuint cap, out nuint outLen);

    /// <summary>Single retry-once dispatch site for the variable-size
    /// output buffers: pre-allocate <paramref name="cap"/>, and on
    /// <see cref="Status.BufferTooSmall"/> retry once with the exact
    /// size the FFI reported (gated on the reported length strictly
    /// exceeding the current capacity).</summary>
    private static byte[] RetryOnce(int cap, OutFn fn)
    {
        var buf = new byte[cap];
        nuint len;
        int rc;
        fixed (byte* p = buf)
        {
            rc = fn(p, (nuint)buf.Length, out len);
        }
        if (rc == (int)Status.BufferTooSmall && len > (nuint)buf.Length)
        {
            buf = new byte[checked((int)len)];
            fixed (byte* p = buf)
            {
                rc = fn(p, (nuint)buf.Length, out len);
            }
        }
        ItbException.Check(rc);
        return Shrink(buf, len);
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
