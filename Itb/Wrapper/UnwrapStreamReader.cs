// Streaming unwrap-decrypt handle for the format-deniability wrapper.
//
// Counterpart of WrapStreamWriter. Constructed against the per-stream
// nonce read off the wire (typically the leading NonceSize(cipher)
// bytes). The libitb wrap-stream handle is keyed by
// (cipher, key, wireNonce); subsequent Update calls XOR-decrypt
// caller-supplied wire bytes into recovered plaintext.

using Itb.Native;

namespace Itb.Wrapper;

/// <summary>
/// Streaming unwrap-decrypt handle. Counterpart of
/// <see cref="WrapStreamWriter"/>.
/// </summary>
/// <remarks>
/// <para>Constructed against the per-stream nonce read off the wire
/// (typically the leading <c>NonceSize(cipher)</c> bytes). The
/// libitb wrap-stream handle is keyed by
/// <c>(cipher, key, wireNonce)</c>; subsequent
/// <see cref="Update(ReadOnlySpan{byte})"/> /
/// <see cref="UpdateInPlace(Span{byte})"/> calls XOR-decrypt caller-
/// supplied wire bytes into recovered plaintext.</para>
/// <para><b>Thread-safety.</b> Same single-feeder contract as
/// <see cref="WrapStreamWriter"/>.</para>
/// <para><b>Lifecycle.</b> Use <see cref="Dispose"/> via
/// <c>using var ur = new UnwrapStreamReader(...)</c> for explicit
/// release at scope exit, or call <see cref="Dispose"/> manually.
/// The finalizer is best-effort — relying on it under a heap-scan
/// threat model is inadequate.</para>
/// </remarks>
public sealed class UnwrapStreamReader : IDisposable
{
    private nuint _handle;
    private bool _closed;
    private readonly Cipher _cipher;

    /// <summary>
    /// Constructs a fresh streaming unwrap-decrypt handle keyed by
    /// <c>(cipher, key, wireNonce)</c>. <paramref name="wireNonce"/>
    /// must be exactly <c>NonceSize(cipher)</c> bytes long.
    /// </summary>
    public unsafe UnwrapStreamReader(Cipher cipher, ReadOnlySpan<byte> key, ReadOnlySpan<byte> wireNonce)
    {
        var name = cipher.ToFfiName();
        Wrapper.CheckKeyLen(cipher, key);
        var nlen = Wrapper.NonceSize(cipher);
        if (wireNonce.Length != nlen)
        {
            throw new InvalidNonceException(
                $"wrapper {cipher.ToFfiName()}: nonce must be {nlen} bytes, got {wireNonce.Length}");
        }
        nuint handle;
        int rc;
        fixed (byte* keyPtr = key)
        fixed (byte* noncePtr = wireNonce)
        {
            rc = ItbNative.ITB_UnwrapStreamReader_Init(
                name,
                keyPtr, (nuint)key.Length,
                noncePtr, (nuint)wireNonce.Length,
                out handle);
        }
        ItbException.Check(rc);
        _handle = handle;
        _cipher = cipher;
        _closed = false;
    }

    /// <summary>The outer cipher selected at construction.</summary>
    public Cipher Cipher => _cipher;

    /// <summary>
    /// XOR-decrypts <paramref name="src"/> through the keystream and
    /// returns the recovered plaintext bytes. The keystream counter
    /// advances by <c>src.Length</c> bytes regardless of input
    /// length.
    /// </summary>
    /// <exception cref="WrapperHandleClosedException">The reader has
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
            rc = ItbNative.ITB_UnwrapStreamReader_Update(
                _handle,
                srcPtr, (nuint)src.Length,
                dstPtr, (nuint)dst.Length);
        }
        ItbException.Check(rc);
        GC.KeepAlive(this);
        return dst;
    }

    /// <summary>
    /// XOR-decrypts <paramref name="buf"/> in place through the
    /// keystream. The zero-allocation alternative to
    /// <see cref="Update"/> for callers that already own a writable
    /// buffer carrying the wire bytes.
    /// </summary>
    /// <exception cref="WrapperHandleClosedException">The reader has
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
            rc = ItbNative.ITB_UnwrapStreamReader_Update(
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
            throw new WrapperHandleClosedException("unwrap stream reader has been closed");
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
        _ = ItbNative.ITB_UnwrapStreamReader_Free(_handle);
        _handle = 0;
        _closed = true;
        GC.SuppressFinalize(this);
    }

    ~UnwrapStreamReader()
    {
        if (!_closed && _handle != 0)
        {
            _ = ItbNative.ITB_UnwrapStreamReader_Free(_handle);
            _handle = 0;
            _closed = true;
        }
    }
}
