// Low-level encrypt / decrypt entry points.
//
// Exposes the libitb encrypt / decrypt surface as static methods:
// Encrypt / Decrypt over a Single Ouroboros (noise, data, start) seed
// trio, EncryptTriple / DecryptTriple over a seven-seed Triple
// Ouroboros configuration, plus the four authenticated *Auth variants
// that take an additional Mac handle. Every method follows the
// probe-allocate-call idiom: a first call with a NULL out-buffer
// reports the required output capacity, and a second call writes the
// ciphertext / plaintext into the freshly allocated array.

using Itb.Native;

namespace Itb;

/// <summary>
/// Top-level static class exposing libitb's low-level cipher entry
/// points: <see cref="Encrypt"/> / <see cref="Decrypt"/> over a
/// (noise, data, start) Single Ouroboros seed trio,
/// <see cref="EncryptTriple"/> / <see cref="DecryptTriple"/> over a
/// seven-seed Triple Ouroboros configuration, and the four
/// authenticated variants that take an additional <see cref="Mac"/>
/// handle.
///
/// <para>Empty plaintext / ciphertext is rejected by libitb itself
/// with <see cref="StatusCode.EncryptFailed"/> (the Go-side
/// <c>Encrypt128</c> / <c>Decrypt128</c> family returns
/// <c>"itb: empty data"</c> before any work). The binding propagates
/// the rejection verbatim — pass at least one byte.</para>
/// </summary>
public static class Cipher
{
    // ----------------------------------------------------------------
    // Single Ouroboros — three seeds.
    // ----------------------------------------------------------------

    /// <summary>Encrypts <paramref name="plaintext"/> under the
    /// (noise, data, start) seed trio. All three seeds must share the
    /// same native hash width.</summary>
    public static unsafe byte[] Encrypt(Seed noise, Seed data, Seed start, ReadOnlySpan<byte> plaintext)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(start);
        try
        {
            return EncDecSingle(true, noise, data, start, plaintext);
        }
        finally
        {
            // Keep the Seed handles rooted past the FFI call so the JIT
            // cannot mark them dead after handle-field extraction and
            // let a finalizer race the in-flight ITB_Encrypt.
            GC.KeepAlive(noise);
            GC.KeepAlive(data);
            GC.KeepAlive(start);
        }
    }

    /// <summary>Decrypts ciphertext produced by
    /// <see cref="Encrypt"/> under the same seed trio.</summary>
    public static unsafe byte[] Decrypt(Seed noise, Seed data, Seed start, ReadOnlySpan<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(start);
        try
        {
            return EncDecSingle(false, noise, data, start, ciphertext);
        }
        finally
        {
            GC.KeepAlive(noise);
            GC.KeepAlive(data);
            GC.KeepAlive(start);
        }
    }

    private static unsafe byte[] EncDecSingle(bool encrypt, Seed noise, Seed data, Seed start, ReadOnlySpan<byte> payload)
    {
        var nh = noise.Handle;
        var dh = data.Handle;
        var sh = start.Handle;
        var payloadLen = payload.Length;
        // 1.25× + 128 KiB headroom — see Encryptor.CipherCall for the
        // measured-margin rationale. Skips the size-probe round-trip
        // the libitb C ABI charges (the cipher does the full crypto on
        // every call regardless of out-buffer capacity, then returns
        // BUFFER_TOO_SMALL without exposing the work — so
        // probe-then-retry doubles cipher work per call). The retry on
        // BUFFER_TOO_SMALL remains as the safety net for any future
        // barrier-fill / nonce-bits combination outside the measured
        // matrix.
        var cap = Math.Max(131072, payloadLen * 5 / 4 + 131072);
        var buf = new byte[cap];
        nuint outLen;
        int rc;
        fixed (byte* inPtr = payload)
        fixed (byte* outPtr = buf)
        {
            rc = encrypt
                ? ItbNative.ITB_Encrypt(nh, dh, sh, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen)
                : ItbNative.ITB_Decrypt(nh, dh, sh, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen);
        }
        if (rc == Status.BufferTooSmall)
        {
            buf = new byte[(int)outLen];
            fixed (byte* inPtr = payload)
            fixed (byte* outPtr = buf)
            {
                rc = encrypt
                    ? ItbNative.ITB_Encrypt(nh, dh, sh, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen)
                    : ItbNative.ITB_Decrypt(nh, dh, sh, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen);
            }
        }
        ItbException.Check(rc);
        if ((int)outLen < buf.Length)
        {
            Array.Resize(ref buf, (int)outLen);
        }
        return buf;
    }

    // ----------------------------------------------------------------
    // Triple Ouroboros — seven seeds.
    // ----------------------------------------------------------------

    /// <summary>
    /// Triple Ouroboros encrypt over seven seeds. Splits plaintext
    /// across three interleaved snake payloads. The on-wire ciphertext
    /// format is the same shape as <see cref="Encrypt"/> — only the
    /// internal split / interleave differs.
    /// </summary>
    public static unsafe byte[] EncryptTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        ReadOnlySpan<byte> plaintext)
    {
        ValidateTripleHandles(noise, data1, data2, data3, start1, start2, start3);
        try
        {
            return EncDecTriple(true, noise, data1, data2, data3, start1, start2, start3, plaintext);
        }
        finally
        {
            KeepAliveTriple(noise, data1, data2, data3, start1, start2, start3);
        }
    }

    /// <summary>Inverse of <see cref="EncryptTriple"/>.</summary>
    public static unsafe byte[] DecryptTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        ReadOnlySpan<byte> ciphertext)
    {
        ValidateTripleHandles(noise, data1, data2, data3, start1, start2, start3);
        try
        {
            return EncDecTriple(false, noise, data1, data2, data3, start1, start2, start3, ciphertext);
        }
        finally
        {
            KeepAliveTriple(noise, data1, data2, data3, start1, start2, start3);
        }
    }

    private static unsafe byte[] EncDecTriple(
        bool encrypt,
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        ReadOnlySpan<byte> payload)
    {
        var nh = noise.Handle;
        var d1 = data1.Handle;
        var d2 = data2.Handle;
        var d3 = data3.Handle;
        var s1 = start1.Handle;
        var s2 = start2.Handle;
        var s3 = start3.Handle;
        var payloadLen = payload.Length;
        // 1.25× + 128 KiB headroom; see Encryptor.CipherCall.
        var cap = Math.Max(131072, payloadLen * 5 / 4 + 131072);
        var buf = new byte[cap];
        nuint outLen;
        int rc;
        fixed (byte* inPtr = payload)
        fixed (byte* outPtr = buf)
        {
            rc = encrypt
                ? ItbNative.ITB_Encrypt3(nh, d1, d2, d3, s1, s2, s3, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen)
                : ItbNative.ITB_Decrypt3(nh, d1, d2, d3, s1, s2, s3, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen);
        }
        if (rc == Status.BufferTooSmall)
        {
            buf = new byte[(int)outLen];
            fixed (byte* inPtr = payload)
            fixed (byte* outPtr = buf)
            {
                rc = encrypt
                    ? ItbNative.ITB_Encrypt3(nh, d1, d2, d3, s1, s2, s3, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen)
                    : ItbNative.ITB_Decrypt3(nh, d1, d2, d3, s1, s2, s3, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen);
            }
        }
        ItbException.Check(rc);
        if ((int)outLen < buf.Length)
        {
            Array.Resize(ref buf, (int)outLen);
        }
        return buf;
    }

    // ----------------------------------------------------------------
    // Authenticated Single — three seeds + MAC.
    // ----------------------------------------------------------------

    /// <summary>Authenticated single-Ouroboros encrypt with
    /// MAC-Inside-Encrypt.</summary>
    public static unsafe byte[] EncryptAuth(
        Seed noise, Seed data, Seed start, Mac mac,
        ReadOnlySpan<byte> plaintext)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(mac);
        try
        {
            return EncDecAuthSingle(true, noise, data, start, mac, plaintext);
        }
        finally
        {
            GC.KeepAlive(noise);
            GC.KeepAlive(data);
            GC.KeepAlive(start);
            GC.KeepAlive(mac);
        }
    }

    /// <summary>Authenticated single-Ouroboros decrypt. Returns
    /// <see cref="ItbException"/> with status <c>MacFailure</c> on
    /// tampered ciphertext or wrong MAC key.</summary>
    public static unsafe byte[] DecryptAuth(
        Seed noise, Seed data, Seed start, Mac mac,
        ReadOnlySpan<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(mac);
        try
        {
            return EncDecAuthSingle(false, noise, data, start, mac, ciphertext);
        }
        finally
        {
            GC.KeepAlive(noise);
            GC.KeepAlive(data);
            GC.KeepAlive(start);
            GC.KeepAlive(mac);
        }
    }

    private static unsafe byte[] EncDecAuthSingle(
        bool encrypt,
        Seed noise, Seed data, Seed start, Mac mac,
        ReadOnlySpan<byte> payload)
    {
        var nh = noise.Handle;
        var dh = data.Handle;
        var sh = start.Handle;
        var mh = mac.Handle;
        var payloadLen = payload.Length;
        // 1.25× + 128 KiB headroom; see Encryptor.CipherCall.
        var cap = Math.Max(131072, payloadLen * 5 / 4 + 131072);
        var buf = new byte[cap];
        nuint outLen;
        int rc;
        fixed (byte* inPtr = payload)
        fixed (byte* outPtr = buf)
        {
            rc = encrypt
                ? ItbNative.ITB_EncryptAuth(nh, dh, sh, mh, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen)
                : ItbNative.ITB_DecryptAuth(nh, dh, sh, mh, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen);
        }
        if (rc == Status.BufferTooSmall)
        {
            buf = new byte[(int)outLen];
            fixed (byte* inPtr = payload)
            fixed (byte* outPtr = buf)
            {
                rc = encrypt
                    ? ItbNative.ITB_EncryptAuth(nh, dh, sh, mh, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen)
                    : ItbNative.ITB_DecryptAuth(nh, dh, sh, mh, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen);
            }
        }
        ItbException.Check(rc);
        if ((int)outLen < buf.Length)
        {
            Array.Resize(ref buf, (int)outLen);
        }
        return buf;
    }

    // ----------------------------------------------------------------
    // Authenticated Triple — seven seeds + MAC.
    // ----------------------------------------------------------------

    /// <summary>Authenticated Triple Ouroboros encrypt (7 seeds + MAC).</summary>
    public static unsafe byte[] EncryptAuthTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Mac mac,
        ReadOnlySpan<byte> plaintext)
    {
        ValidateTripleHandles(noise, data1, data2, data3, start1, start2, start3);
        ArgumentNullException.ThrowIfNull(mac);
        try
        {
            return EncDecAuthTriple(true, noise, data1, data2, data3, start1, start2, start3, mac, plaintext);
        }
        finally
        {
            KeepAliveTriple(noise, data1, data2, data3, start1, start2, start3);
            GC.KeepAlive(mac);
        }
    }

    /// <summary>Authenticated Triple Ouroboros decrypt. Returns
    /// <see cref="ItbException"/> with status <c>MacFailure</c> on
    /// tampered ciphertext or wrong MAC key.</summary>
    public static unsafe byte[] DecryptAuthTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Mac mac,
        ReadOnlySpan<byte> ciphertext)
    {
        ValidateTripleHandles(noise, data1, data2, data3, start1, start2, start3);
        ArgumentNullException.ThrowIfNull(mac);
        try
        {
            return EncDecAuthTriple(false, noise, data1, data2, data3, start1, start2, start3, mac, ciphertext);
        }
        finally
        {
            KeepAliveTriple(noise, data1, data2, data3, start1, start2, start3);
            GC.KeepAlive(mac);
        }
    }

    private static unsafe byte[] EncDecAuthTriple(
        bool encrypt,
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Mac mac,
        ReadOnlySpan<byte> payload)
    {
        var nh = noise.Handle;
        var d1 = data1.Handle;
        var d2 = data2.Handle;
        var d3 = data3.Handle;
        var s1 = start1.Handle;
        var s2 = start2.Handle;
        var s3 = start3.Handle;
        var mh = mac.Handle;
        var payloadLen = payload.Length;
        // 1.25× + 128 KiB headroom; see Encryptor.CipherCall.
        var cap = Math.Max(131072, payloadLen * 5 / 4 + 131072);
        var buf = new byte[cap];
        nuint outLen;
        int rc;
        fixed (byte* inPtr = payload)
        fixed (byte* outPtr = buf)
        {
            rc = encrypt
                ? ItbNative.ITB_EncryptAuth3(nh, d1, d2, d3, s1, s2, s3, mh, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen)
                : ItbNative.ITB_DecryptAuth3(nh, d1, d2, d3, s1, s2, s3, mh, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen);
        }
        if (rc == Status.BufferTooSmall)
        {
            buf = new byte[(int)outLen];
            fixed (byte* inPtr = payload)
            fixed (byte* outPtr = buf)
            {
                rc = encrypt
                    ? ItbNative.ITB_EncryptAuth3(nh, d1, d2, d3, s1, s2, s3, mh, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen)
                    : ItbNative.ITB_DecryptAuth3(nh, d1, d2, d3, s1, s2, s3, mh, inPtr, (nuint)payloadLen, outPtr, (nuint)buf.Length, out outLen);
            }
        }
        ItbException.Check(rc);
        if ((int)outLen < buf.Length)
        {
            Array.Resize(ref buf, (int)outLen);
        }
        return buf;
    }

    private static void ValidateTripleHandles(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data1);
        ArgumentNullException.ThrowIfNull(data2);
        ArgumentNullException.ThrowIfNull(data3);
        ArgumentNullException.ThrowIfNull(start1);
        ArgumentNullException.ThrowIfNull(start2);
        ArgumentNullException.ThrowIfNull(start3);
    }

    private static void KeepAliveTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3)
    {
        GC.KeepAlive(noise);
        GC.KeepAlive(data1);
        GC.KeepAlive(data2);
        GC.KeepAlive(data3);
        GC.KeepAlive(start1);
        GC.KeepAlive(start2);
        GC.KeepAlive(start3);
    }
}
