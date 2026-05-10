// Format-deniability wrapper for ITB ciphertext.
//
// C#-idiomatic surface over the 12 ITB_Wrap* / ITB_Unwrap* /
// ITB_WrapStream* / ITB_UnwrapStream* / ITB_WrapperKeySize /
// ITB_WrapperNonceSize exports in cmd/cshared/main.go. Wraps an ITB
// ciphertext under one of three outer keystream ciphers
// (AES-128-CTR / ChaCha20 / SipHash-2-4 in CTR mode) so the on-wire
// bytes carry no ITB-specific format pattern (W / H / container
// layout for Non-AEAD; 32-byte streamID prefix + per-chunk metadata
// for Streaming AEAD). The wrap exists for format-deniability
// ONLY — ITB already provides content-deniability and the AEAD
// path already provides integrity.
//
// Quick start (Single Message Wrap / Unwrap):
//
//     var key = Wrapper.GenerateKey(Cipher.Aes128Ctr);
//     byte[] blob = ...;
//     byte[] wire = Wrapper.Wrap(Cipher.Aes128Ctr, key, blob);
//     byte[] recovered = Wrapper.Unwrap(Cipher.Aes128Ctr, key, wire);
//     Debug.Assert(recovered.SequenceEqual(blob));
//
// Single Message in-place mutation (zero-allocation steady state):
//
//     Span<byte> mutable = blob.ToArray();
//     byte[] nonce = Wrapper.WrapInPlace(Cipher.ChaCha20, key, mutable);
//     // wire = nonce || mutated blob
//
// Streaming wrap (caller-side framing through one keystream so length
// prefixes also XOR through):
//
//     using var ww = new WrapStreamWriter(Cipher.SipHash24, key);
//     // ww.Nonce — emit once at stream start
//     output.Write(ww.Update(chunk1));
//
// Threading. Each WrapStreamWriter / UnwrapStreamReader owns one
// libitb stream handle and is single-feeder by construction. Multiple
// instances run independently. The static Wrap / Unwrap / WrapInPlace
// / UnwrapInPlace methods are thread-safe — each call allocates its
// own outer cipher handle internally and the underlying libitb
// keystream constructor draws a fresh CSPRNG nonce per call.

using System.Security.Cryptography;
using Itb.Native;

namespace Itb.Wrapper;

/// <summary>
/// Outer keystream cipher selected per wrap session. Each variant
/// maps to one of the three cipher-name strings the underlying FFI
/// accepts: <c>"aes"</c> / <c>"chacha"</c> / <c>"siphash"</c>. The
/// Go-side constants are <c>wrapper.CipherAES128CTR</c> /
/// <c>wrapper.CipherChaCha20</c> / <c>wrapper.CipherSipHash24</c>.
/// </summary>
public enum Cipher
{
    /// <summary>AES-128-CTR — 16-byte key, 16-byte nonce, AES-NI
    /// accelerated on the libitb side via the Go stdlib
    /// <c>crypto/cipher.NewCTR</c>.</summary>
    Aes128Ctr,
    /// <summary>ChaCha20 (RFC 8439) — 32-byte key, 12-byte nonce. No
    /// AES-NI dependency.</summary>
    ChaCha20,
    /// <summary>SipHash-2-4 in CTR mode — 16-byte key, 16-byte nonce.
    /// Custom CTR construction over the SipHash-2-4 PRF; sound under
    /// the standard PRF assumption that justifies AES-CTR.</summary>
    SipHash24,
}

/// <summary>
/// Extension helpers translating <see cref="Cipher"/> values into the
/// canonical FFI strings.
/// </summary>
public static class CipherExtensions
{
    /// <summary>Returns the FFI cipher-name string used by every entry
    /// point.</summary>
    public static string ToFfiName(this Cipher cipher) => cipher switch
    {
        Cipher.Aes128Ctr => "aes",
        Cipher.ChaCha20 => "chacha",
        Cipher.SipHash24 => "siphash",
        _ => throw new ArgumentOutOfRangeException(nameof(cipher), cipher, "unknown wrapper cipher"),
    };
}

/// <summary>
/// Raised when the supplied <see cref="Cipher"/> value is outside the
/// three FFI-accepted variants. Carries
/// <see cref="StatusCode.BadInput"/>.
/// </summary>
public sealed class InvalidCipherException : ItbException
{
    /// <summary>The unparseable cipher value (or <c>null</c> if the
    /// FFI rejected a string-form name).</summary>
    public Cipher? Cipher { get; }

    /// <summary>The unparseable cipher name (when reaching the FFI
    /// boundary as a string).</summary>
    public string? CipherName { get; }

    internal InvalidCipherException(Cipher cipher)
        : base(StatusCode.BadInput, $"unknown wrapper cipher {cipher}")
    {
        Cipher = cipher;
    }

    internal InvalidCipherException(string cipherName)
        : base(StatusCode.BadInput, $"unknown wrapper cipher \"{cipherName}\"")
    {
        CipherName = cipherName;
    }
}

/// <summary>
/// Raised when the supplied key length does not match the cipher's
/// expected key size. Carries <see cref="StatusCode.BadInput"/>.
/// </summary>
public sealed class InvalidKeyException : ItbException
{
    internal InvalidKeyException(string message) : base(StatusCode.BadInput, message) { }
}

/// <summary>
/// Raised when an internal nonce buffer cannot be sized for the
/// selected cipher (e.g. a wire too short to carry the leading nonce
/// on the unwrap path). Carries <see cref="StatusCode.BadInput"/>.
/// </summary>
public sealed class InvalidNonceException : ItbException
{
    internal InvalidNonceException(string message) : base(StatusCode.BadInput, message) { }
}

/// <summary>
/// Raised when a streaming <see cref="WrapStreamWriter.Update"/> /
/// <see cref="UnwrapStreamReader.Update"/> call follows
/// <see cref="IDisposable.Dispose"/>. Carries
/// <see cref="StatusCode.BadHandle"/>.
/// </summary>
public sealed class WrapperHandleClosedException : ItbException
{
    internal WrapperHandleClosedException(string message)
        : base(StatusCode.BadHandle, message)
    {
    }
}

/// <summary>
/// Format-deniability wrapper static surface. Provides
/// <see cref="KeySize"/> / <see cref="NonceSize"/> /
/// <see cref="GenerateKey"/> introspection helpers plus the four
/// Single Message entry points (<see cref="Wrap"/> / <see cref="Unwrap"/>
/// / <see cref="WrapInPlace"/> / <see cref="UnwrapInPlace"/>).
/// Streaming surfaces are exposed through the
/// <see cref="WrapStreamWriter"/> / <see cref="UnwrapStreamReader"/>
/// types in this namespace.
/// </summary>
public static class Wrapper
{
    /// <summary>Iteration order over all three supported outer
    /// ciphers.</summary>
    public static readonly Cipher[] AllCiphers = new[]
    {
        Cipher.Aes128Ctr,
        Cipher.ChaCha20,
        Cipher.SipHash24,
    };

    /// <summary>
    /// Returns the byte length of the keystream-cipher key for the
    /// named outer cipher (16 / 32 / 16 for AES / ChaCha / SipHash).
    /// </summary>
    public static int KeySize(Cipher cipher)
    {
        var name = cipher.ToFfiName();
        var rc = ItbNative.ITB_WrapperKeySize(name, out var size);
        if (rc != Status.Ok)
        {
            throw new InvalidCipherException(cipher);
        }
        return (int)size;
    }

    /// <summary>
    /// Returns the on-wire nonce length the named outer cipher emits
    /// per stream (16 / 12 / 16 for AES / ChaCha / SipHash).
    /// </summary>
    public static int NonceSize(Cipher cipher)
    {
        var name = cipher.ToFfiName();
        var rc = ItbNative.ITB_WrapperNonceSize(name, out var size);
        if (rc != Status.Ok)
        {
            throw new InvalidCipherException(cipher);
        }
        return (int)size;
    }

    /// <summary>
    /// Returns a fresh CSPRNG key sized for the named outer cipher
    /// (16 / 32 / 16 bytes for AES / ChaCha / SipHash). Uses
    /// <see cref="RandomNumberGenerator.Fill(Span{byte})"/>.
    /// </summary>
    public static byte[] GenerateKey(Cipher cipher)
    {
        var n = KeySize(cipher);
        var buf = new byte[n];
        RandomNumberGenerator.Fill(buf);
        return buf;
    }

    /// <summary>
    /// Single Message wrap. Seals <paramref name="blob"/> under
    /// <paramref name="cipher"/> with a fresh per-call CSPRNG nonce;
    /// returns the wire bytes <c>nonce || keystream-XOR(blob)</c>.
    /// </summary>
    /// <remarks>
    /// Allocates a fresh output buffer of size
    /// <c>NonceSize(cipher) + blob.Length</c> per call. For zero-
    /// allocation steady state on the hot path use
    /// <see cref="WrapInPlace"/>.
    /// </remarks>
    public static unsafe byte[] Wrap(Cipher cipher, ReadOnlySpan<byte> key, ReadOnlySpan<byte> blob)
    {
        var name = cipher.ToFfiName();
        CheckKeyLen(cipher, key);
        var nlen = NonceSize(cipher);
        var cap = nlen + blob.Length;
        var outBuf = new byte[cap];
        nuint outLen;
        int rc;
        fixed (byte* keyPtr = key)
        fixed (byte* blobPtr = blob)
        fixed (byte* outPtr = outBuf)
        {
            rc = ItbNative.ITB_Wrap(
                name,
                keyPtr, (nuint)key.Length,
                blobPtr, (nuint)blob.Length,
                outPtr, (nuint)cap, out outLen);
        }
        ItbException.Check(rc);
        if ((int)outLen < outBuf.Length)
        {
            Array.Resize(ref outBuf, (int)outLen);
        }
        return outBuf;
    }

    /// <summary>
    /// Single Message unwrap. Reads the leading
    /// <c>NonceSize(cipher)</c> bytes of <paramref name="wire"/> as
    /// the per-stream nonce, XOR-decrypts the remainder under
    /// <c>(key, nonce)</c> and returns the recovered blob.
    /// </summary>
    /// <remarks>
    /// Allocates a fresh output buffer of size
    /// <c>wire.Length - NonceSize(cipher)</c> per call. For zero-
    /// allocation steady state use <see cref="UnwrapInPlace"/>.
    /// </remarks>
    public static unsafe byte[] Unwrap(Cipher cipher, ReadOnlySpan<byte> key, ReadOnlySpan<byte> wire)
    {
        var name = cipher.ToFfiName();
        CheckKeyLen(cipher, key);
        var nlen = NonceSize(cipher);
        if (wire.Length < nlen)
        {
            throw new InvalidNonceException(
                $"wrapper {cipher.ToFfiName()}: wire shorter than nonce ({wire.Length} < {nlen})");
        }
        var cap = wire.Length - nlen;
        // Pre-size to at least 1 so the pinned pointer is non-null
        // even when the body is empty; the FFI accepts NULL only
        // paired with cap=0 in BAD_INPUT validation.
        var outBuf = new byte[Math.Max(cap, 1)];
        nuint outLen;
        int rc;
        fixed (byte* keyPtr = key)
        fixed (byte* wirePtr = wire)
        fixed (byte* outPtr = outBuf)
        {
            rc = ItbNative.ITB_Unwrap(
                name,
                keyPtr, (nuint)key.Length,
                wirePtr, (nuint)wire.Length,
                outPtr, (nuint)cap, out outLen);
        }
        ItbException.Check(rc);
        if ((int)outLen < outBuf.Length)
        {
            Array.Resize(ref outBuf, (int)outLen);
        }
        return outBuf;
    }

    /// <summary>
    /// In-place Single Message wrap. XORs <paramref name="blob"/> under
    /// a fresh per-call CSPRNG nonce; returns the per-stream nonce.
    /// </summary>
    /// <remarks>
    /// <paramref name="blob"/> is <b>MUTATED</b>. The caller is
    /// expected to emit <c>nonce || blob</c> to the wire (or compose
    /// a single buffer). Suitable for hot paths where the caller has
    /// just produced an ITB ciphertext and will not re-read it (the
    /// typical case for buffered write-to-wire). For an immutable
    /// plaintext path use <see cref="Wrap"/>.
    /// </remarks>
    public static unsafe byte[] WrapInPlace(Cipher cipher, ReadOnlySpan<byte> key, Span<byte> blob)
    {
        var name = cipher.ToFfiName();
        CheckKeyLen(cipher, key);
        var nlen = NonceSize(cipher);
        var nonce = new byte[nlen];
        int rc;
        fixed (byte* keyPtr = key)
        fixed (byte* blobPtr = blob)
        fixed (byte* noncePtr = nonce)
        {
            rc = ItbNative.ITB_WrapInPlace(
                name,
                keyPtr, (nuint)key.Length,
                blobPtr, (nuint)blob.Length,
                noncePtr, (nuint)nlen);
        }
        ItbException.Check(rc);
        return nonce;
    }

    /// <summary>
    /// In-place Single Message unwrap. Strips the leading
    /// <c>NonceSize(cipher)</c> bytes from <paramref name="wire"/>
    /// and XOR-decrypts the remainder under <c>(key, nonce)</c>
    /// directly into the caller's buffer. Returns a slice aliasing
    /// <c>wire[NonceSize(cipher)..]</c> over the recovered blob; the
    /// leading nonce prefix is left unchanged.
    /// </summary>
    /// <remarks>
    /// <paramref name="wire"/> is <b>MUTATED</b>. For an immutable
    /// wire input use <see cref="Unwrap"/>.
    /// </remarks>
    public static unsafe Span<byte> UnwrapInPlace(Cipher cipher, ReadOnlySpan<byte> key, Span<byte> wire)
    {
        var name = cipher.ToFfiName();
        CheckKeyLen(cipher, key);
        var nlen = NonceSize(cipher);
        if (wire.Length < nlen)
        {
            throw new InvalidNonceException(
                $"wrapper {cipher.ToFfiName()}: wire shorter than nonce ({wire.Length} < {nlen})");
        }
        int rc;
        fixed (byte* keyPtr = key)
        fixed (byte* wirePtr = wire)
        {
            rc = ItbNative.ITB_UnwrapInPlace(
                name,
                keyPtr, (nuint)key.Length,
                wirePtr, (nuint)wire.Length);
        }
        ItbException.Check(rc);
        return wire.Slice(nlen);
    }

    /// <summary>
    /// Validates that <paramref name="key"/>'s length matches the
    /// cipher's expected key size; throws
    /// <see cref="InvalidKeyException"/> on mismatch.
    /// </summary>
    internal static void CheckKeyLen(Cipher cipher, ReadOnlySpan<byte> key)
    {
        var want = KeySize(cipher);
        if (key.Length != want)
        {
            throw new InvalidKeyException(
                $"wrapper {cipher.ToFfiName()}: key must be {want} bytes, got {key.Length}");
        }
    }
}
