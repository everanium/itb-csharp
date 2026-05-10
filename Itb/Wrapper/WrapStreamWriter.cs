// Streaming wrap-encrypt handle for the format-deniability wrapper.
//
// Owns one libitb wrap-stream handle keyed by (cipher, key, nonce)
// where nonce is a fresh CSPRNG draw made at construction. The nonce
// is exposed via WrapStreamWriter.Nonce so the caller can emit it
// once at stream start (typically as the wire prefix); subsequent
// Update calls XOR caller plaintext through the keystream and return
// the encrypted bytes; the keystream counter advances monotonically
// across calls.
//
// Lifecycle is RAII via IDisposable — Dispose calls
// ITB_WrapStreamWriter_Free best-effort; the finalizer is the
// safety-net path. Mirrors the Encryptor / Mac / Seed lifecycle
// convention used elsewhere in the binding.

using Itb.Native;

namespace Itb.Wrapper;

/// <summary>
/// Streaming wrap-encrypt handle.
/// </summary>
/// <remarks>
/// <para>Owns one libitb wrap-stream handle keyed by
/// <c>(cipher, key, nonce)</c> where <c>nonce</c> is a fresh CSPRNG
/// draw made at construction. The nonce is exposed via
/// <see cref="Nonce"/> so the caller can emit it once at stream
/// start (typically as the wire prefix); subsequent
/// <see cref="Update(ReadOnlySpan{byte})"/> calls XOR caller
/// plaintext through the keystream and return the encrypted bytes;
/// the keystream counter advances monotonically across calls.</para>
/// <para>Pair every <see cref="WrapStreamWriter"/> with an
/// <see cref="UnwrapStreamReader"/> keyed by the same
/// <c>(cipher, key)</c> and the nonce read off the wire.</para>
/// <para><b>Thread-safety.</b> The writer is single-feeder by
/// construction. Do not interleave <see cref="Update(ReadOnlySpan{byte})"/>
/// / <see cref="UpdateInPlace(Span{byte})"/> calls from multiple
/// threads on the same writer — the underlying libitb keystream is
/// stateful.</para>
/// <para><b>Lifecycle.</b> Use <see cref="Dispose"/> via
/// <c>using var ww = new WrapStreamWriter(...)</c> for explicit
/// release at scope exit, or call <see cref="Dispose"/> manually.
/// The finalizer is best-effort — relying on it under a heap-scan
/// threat model is inadequate.</para>
/// </remarks>
public sealed class WrapStreamWriter : IDisposable
{
    private nuint _handle;
    private bool _closed;
    private readonly byte[] _nonce;
    private readonly Cipher _cipher;

    /// <summary>
    /// Constructs a fresh streaming wrap-encrypt handle. Draws a
    /// CSPRNG nonce, opens a libitb wrap-stream handle bound to
    /// <c>(cipher, key, nonce)</c>, and stores the nonce on the
    /// instance for later retrieval via <see cref="Nonce"/>.
    /// </summary>
    public unsafe WrapStreamWriter(Cipher cipher, ReadOnlySpan<byte> key)
    {
        var name = cipher.ToFfiName();
        Wrapper.CheckKeyLen(cipher, key);
        var nlen = Wrapper.NonceSize(cipher);
        _nonce = new byte[nlen];
        nuint handle;
        int rc;
        fixed (byte* keyPtr = key)
        fixed (byte* noncePtr = _nonce)
        {
            rc = ItbNative.ITB_WrapStreamWriter_Init(
                name,
                keyPtr, (nuint)key.Length,
                noncePtr, (nuint)nlen,
                out handle);
        }
        ItbException.Check(rc);
        _handle = handle;
        _cipher = cipher;
        _closed = false;
    }

    /// <summary>
    /// The per-stream CSPRNG nonce. The caller emits this once at
    /// stream start (typically as the wire prefix) so the matching
    /// <see cref="UnwrapStreamReader"/> can be constructed against
    /// it. Returns a defensive copy — the underlying buffer is
    /// stable across calls but the array reference is reusable.
    /// </summary>
    public byte[] Nonce
    {
        get
        {
            var copy = new byte[_nonce.Length];
            Buffer.BlockCopy(_nonce, 0, copy, 0, _nonce.Length);
            return copy;
        }
    }

    /// <summary>The outer cipher selected at construction.</summary>
    public Cipher Cipher => _cipher;

    /// <summary>
    /// XOR-encrypts <paramref name="src"/> through the keystream and
    /// returns a fresh <see cref="byte"/>[] carrying the result. The
    /// keystream counter advances by <c>src.Length</c> bytes
    /// regardless of input length.
    /// </summary>
    /// <exception cref="WrapperHandleClosedException">The writer has
    /// been disposed.</exception>
    public unsafe byte[] Update(ReadOnlySpan<byte> src)
    {
        ThrowIfClosed();
        if (src.Length == 0)
        {
            return Array.Empty<byte>();
        }
        var dst = new byte[src.Length];
        int rc;
        fixed (byte* srcPtr = src)
        fixed (byte* dstPtr = dst)
        {
            rc = ItbNative.ITB_WrapStreamWriter_Update(
                _handle,
                srcPtr, (nuint)src.Length,
                dstPtr, (nuint)dst.Length);
        }
        ItbException.Check(rc);
        GC.KeepAlive(this);
        return dst;
    }

    /// <summary>
    /// XOR-encrypts <paramref name="buf"/> in place through the
    /// keystream. The keystream counter advances by <c>buf.Length</c>
    /// bytes. The zero-allocation alternative to <see cref="Update"/>
    /// for callers that already own a writable buffer.
    /// </summary>
    /// <exception cref="WrapperHandleClosedException">The writer has
    /// been disposed.</exception>
    public unsafe void UpdateInPlace(Span<byte> buf)
    {
        ThrowIfClosed();
        if (buf.Length == 0)
        {
            return;
        }
        int rc;
        fixed (byte* bufPtr = buf)
        {
            // Same-pointer src + dst: the libitb side accepts in-
            // place XOR (the Go-side keystream cipher writes the
            // result over the same buffer).
            rc = ItbNative.ITB_WrapStreamWriter_Update(
                _handle,
                bufPtr, (nuint)buf.Length,
                bufPtr, (nuint)buf.Length);
        }
        ItbException.Check(rc);
        GC.KeepAlive(this);
    }

    private void ThrowIfClosed()
    {
        if (_closed || _handle == 0)
        {
            throw new WrapperHandleClosedException("wrap stream writer has been closed");
        }
    }

    /// <summary>
    /// Releases the underlying libitb wrap-stream handle. Idempotent;
    /// a second <see cref="Dispose"/> is a no-op.
    /// </summary>
    public void Dispose()
    {
        if (_closed || _handle == 0)
        {
            _closed = true;
            _handle = 0;
            GC.SuppressFinalize(this);
            return;
        }
        _ = ItbNative.ITB_WrapStreamWriter_Free(_handle);
        _handle = 0;
        _closed = true;
        GC.SuppressFinalize(this);
    }

    ~WrapStreamWriter()
    {
        if (!_closed && _handle != 0)
        {
            _ = ItbNative.ITB_WrapStreamWriter_Free(_handle);
            _handle = 0;
            _closed = true;
        }
    }
}
