// Tests for the C# format-deniability wrapper namespace
// (Itb.Wrapper).
//
// Coverage mirrors the cross-binding contract for the wrapper
// surface:
//
//   - 3 outer ciphers × 4 Single Message variants
//     (Wrap / Unwrap / WrapInPlace / UnwrapInPlace) — round-trip
//     + nonce hygiene.
//   - 3 outer ciphers × streaming WrapStreamWriter +
//     UnwrapStreamReader multi-chunk round-trip.
//   - RAII / using-statement leak verification (handle stress test).
//   - Error paths: unknown cipher (unreachable through typed enum
//     but still validated through the FFI-level path), key length
//     mismatch, wire shorter than nonce, nonce length mismatch on
//     UnwrapStreamReader, closed-handle rejection on the streaming
//     surface.
//
// The wrap layer never touches the libitb encrypt / decrypt path;
// the assertions are about the keystream-XOR envelope round-trip
// alone.

using System.Security.Cryptography;
using Itb;
using OuterCipher = Itb.Wrapper.Cipher;
using WrapperCore = Itb.Wrapper.Wrapper;

namespace Itb.Tests.Wrapper;

public class TestWrapperConstants
{
    public static IEnumerable<object[]> KeyCiphers() =>
        new[]
        {
            new object[] { OuterCipher.Aes128Ctr, 16 },
            new object[] { OuterCipher.ChaCha20, 32 },
            new object[] { OuterCipher.SipHash24, 16 },
        };

    public static IEnumerable<object[]> NonceCiphers() =>
        new[]
        {
            new object[] { OuterCipher.Aes128Ctr, 16 },
            new object[] { OuterCipher.ChaCha20, 12 },
            new object[] { OuterCipher.SipHash24, 16 },
        };

    [Theory]
    [MemberData(nameof(KeyCiphers))]
    public void KeySizeMatchesContract(OuterCipher cipher, int keySize)
    {
        Assert.Equal(keySize, WrapperCore.KeySize(cipher));
    }

    [Theory]
    [MemberData(nameof(NonceCiphers))]
    public void NonceSizeMatchesContract(OuterCipher cipher, int nonceSize)
    {
        Assert.Equal(nonceSize, WrapperCore.NonceSize(cipher));
    }

    [Theory]
    [MemberData(nameof(KeyCiphers))]
    public void GenerateKeyReturnsCorrectLength(OuterCipher cipher, int keySize)
    {
        var k1 = WrapperCore.GenerateKey(cipher);
        var k2 = WrapperCore.GenerateKey(cipher);
        Assert.Equal(keySize, k1.Length);
        Assert.Equal(keySize, k2.Length);
        // CSPRNG: two draws should differ with overwhelming probability.
        Assert.NotEqual(k1, k2);
    }

    [Fact]
    public void AllCiphersOrderingIsCanonical()
    {
        Assert.Equal(
            new[] { OuterCipher.Aes128Ctr, OuterCipher.ChaCha20, OuterCipher.SipHash24 },
            WrapperCore.AllCiphers);
    }
}

public class TestWrapUnwrap
{
    public static IEnumerable<object[]> Ciphers() =>
        new[]
        {
            new object[] { OuterCipher.Aes128Ctr },
            new object[] { OuterCipher.ChaCha20 },
            new object[] { OuterCipher.SipHash24 },
        };

    [Theory]
    [MemberData(nameof(Ciphers))]
    public void RoundTripPerCipher(OuterCipher cipher)
    {
        var key = WrapperCore.GenerateKey(cipher);
        var blob = new byte[2048];
        RandomNumberGenerator.Fill(blob);
        var wire = WrapperCore.Wrap(cipher, key, blob);
        // Wire = nonce || ks-XOR(blob); length matches.
        Assert.Equal(WrapperCore.NonceSize(cipher) + blob.Length, wire.Length);
        var recovered = WrapperCore.Unwrap(cipher, key, wire);
        Assert.Equal(blob, recovered);
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public void RoundTripEmptyBlob(OuterCipher cipher)
    {
        var key = WrapperCore.GenerateKey(cipher);
        var wire = WrapperCore.Wrap(cipher, key, ReadOnlySpan<byte>.Empty);
        Assert.Equal(WrapperCore.NonceSize(cipher), wire.Length);
        var recovered = WrapperCore.Unwrap(cipher, key, wire);
        Assert.Empty(recovered);
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public void NonceFreshnessAcrossCalls(OuterCipher cipher)
    {
        var key = WrapperCore.GenerateKey(cipher);
        var blob = new byte[64];
        RandomNumberGenerator.Fill(blob);
        var w1 = WrapperCore.Wrap(cipher, key, blob);
        var w2 = WrapperCore.Wrap(cipher, key, blob);
        // Same key + same blob, distinct nonces → distinct wires.
        Assert.NotEqual(w1, w2);
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public void WrongKeyDecodesToNoise(OuterCipher cipher)
    {
        var key1 = WrapperCore.GenerateKey(cipher);
        var key2 = WrapperCore.GenerateKey(cipher);
        var blob = new byte[64];
        RandomNumberGenerator.Fill(blob);
        var wire = WrapperCore.Wrap(cipher, key1, blob);
        var recovered = WrapperCore.Unwrap(cipher, key2, wire);
        // The unwrap succeeds (no integrity check at this layer) but
        // the recovered bytes are noise.
        Assert.NotEqual(blob, recovered);
    }
}

public class TestWrapUnwrapInPlace
{
    public static IEnumerable<object[]> Ciphers() =>
        new[]
        {
            new object[] { OuterCipher.Aes128Ctr },
            new object[] { OuterCipher.ChaCha20 },
            new object[] { OuterCipher.SipHash24 },
        };

    [Theory]
    [MemberData(nameof(Ciphers))]
    public void InPlaceRoundTrip(OuterCipher cipher)
    {
        var key = WrapperCore.GenerateKey(cipher);
        var original = new byte[1024];
        RandomNumberGenerator.Fill(original);

        // Encrypt-side: WrapInPlace mutates `mutable` and returns the nonce.
        var mutable = (byte[])original.Clone();
        var nonce = WrapperCore.WrapInPlace(cipher, key, mutable);
        Assert.Equal(WrapperCore.NonceSize(cipher), nonce.Length);
        // After wrap, mutable bytes != original bytes (with overwhelming probability).
        Assert.NotEqual(original, mutable);

        // Compose the wire by concatenating nonce || mutated body.
        var wire = new byte[nonce.Length + mutable.Length];
        Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
        Buffer.BlockCopy(mutable, 0, wire, nonce.Length, mutable.Length);

        // Decrypt-side: UnwrapInPlace mutates `wire` and returns a Span over the body.
        var bodySpan = WrapperCore.UnwrapInPlace(cipher, key, wire);
        Assert.Equal(original.Length, bodySpan.Length);
        Assert.True(bodySpan.SequenceEqual(original));
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public void InPlaceMutatesBuffer(OuterCipher cipher)
    {
        var key = WrapperCore.GenerateKey(cipher);
        var blob = new byte[256];
        RandomNumberGenerator.Fill(blob);
        var snapshot = (byte[])blob.Clone();
        // The Span<byte> overload requires a writable buffer — verifies
        // the API actually mutates the input rather than allocating.
        _ = WrapperCore.WrapInPlace(cipher, key, blob);
        // After WrapInPlace, blob bytes have been XOR'd through the
        // keystream — they cannot match the snapshot anymore (with
        // overwhelming probability).
        Assert.NotEqual(snapshot, blob);
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public void UnwrapInPlaceReturnsAliasedSpan(OuterCipher cipher)
    {
        var key = WrapperCore.GenerateKey(cipher);
        var original = new byte[64];
        RandomNumberGenerator.Fill(original);
        var wire = WrapperCore.Wrap(cipher, key, original);
        var nlen = WrapperCore.NonceSize(cipher);
        // The returned span aliases the input wire array — writing
        // through the span should be observable in the original wire
        // buffer.
        var bodySpan = WrapperCore.UnwrapInPlace(cipher, key, wire);
        Assert.Equal(original.Length, bodySpan.Length);
        Assert.True(bodySpan.SequenceEqual(original));
        bodySpan[0] = 0xAB;
        Assert.Equal((byte)0xAB, wire[nlen]);
    }
}

public class TestWrapperStreaming
{
    public static IEnumerable<object[]> Ciphers() =>
        new[]
        {
            new object[] { OuterCipher.Aes128Ctr },
            new object[] { OuterCipher.ChaCha20 },
            new object[] { OuterCipher.SipHash24 },
        };

    [Theory]
    [MemberData(nameof(Ciphers))]
    public void StreamingRoundTripMultiChunk(OuterCipher cipher)
    {
        var key = WrapperCore.GenerateKey(cipher);
        var chunks = new[]
        {
            new byte[1024],
            new byte[2048],
            new byte[256],
        };
        foreach (var c in chunks) { RandomNumberGenerator.Fill(c); }

        // Sender — emit nonce + multi-chunk update sequence.
        byte[] nonce;
        using var wireBuf = new MemoryStream();
        using (var ww = new global::Itb.Wrapper.WrapStreamWriter(cipher, key))
        {
            nonce = ww.Nonce;
            wireBuf.Write(nonce);
            foreach (var c in chunks)
            {
                wireBuf.Write(ww.Update(c));
            }
        }
        var wire = wireBuf.ToArray();
        Assert.Equal(WrapperCore.NonceSize(cipher), nonce.Length);

        // Receiver — reconstruct from concatenated wire bytes.
        var nlen = WrapperCore.NonceSize(cipher);
        using var ur = new global::Itb.Wrapper.UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
        var recovered = ur.Update(wire.AsSpan(nlen));

        var concatenated = chunks.SelectMany(c => c).ToArray();
        Assert.Equal(concatenated, recovered);
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public void StreamingUpdateInPlaceRoundTrip(OuterCipher cipher)
    {
        var key = WrapperCore.GenerateKey(cipher);
        var original = new byte[4096];
        RandomNumberGenerator.Fill(original);

        byte[] wire;
        byte[] nonce;
        using (var ww = new global::Itb.Wrapper.WrapStreamWriter(cipher, key))
        {
            nonce = ww.Nonce;
            var body = (byte[])original.Clone();
            ww.UpdateInPlace(body);
            wire = new byte[nonce.Length + body.Length];
            Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
            Buffer.BlockCopy(body, 0, wire, nonce.Length, body.Length);
        }

        var nlen = WrapperCore.NonceSize(cipher);
        using var ur = new global::Itb.Wrapper.UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
        var bodyView = wire.AsSpan(nlen);
        ur.UpdateInPlace(bodyView);
        Assert.True(bodyView.SequenceEqual(original));
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public void StreamingHandleClosesAfterDispose(OuterCipher cipher)
    {
        var key = WrapperCore.GenerateKey(cipher);
        var ww = new global::Itb.Wrapper.WrapStreamWriter(cipher, key);
        var _ = ww.Nonce;
        ww.Dispose();
        Assert.Throws<global::Itb.Wrapper.WrapperHandleClosedException>(() =>
            ww.Update(new byte[16]));

        // Idempotent dispose.
        ww.Dispose();
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public void StreamingHandleStressManyInstances(OuterCipher cipher)
    {
        // RAII / using-statement leak verification — open and close
        // many handles in rapid succession; the libitb-side handle
        // table should not exhaust.
        var key = WrapperCore.GenerateKey(cipher);
        for (var i = 0; i < 256; i++)
        {
            using var ww = new global::Itb.Wrapper.WrapStreamWriter(cipher, key);
            var nonce = ww.Nonce;
            using var ur = new global::Itb.Wrapper.UnwrapStreamReader(cipher, key, nonce);
            var body = ww.Update(new byte[64]);
            var recovered = ur.Update(body);
            Assert.Equal(64, recovered.Length);
        }
    }
}

public class TestWrapperErrorPaths
{
    [Fact]
    public void WrapRejectsKeyLengthMismatchAes()
    {
        var badKey = new byte[8]; // expected 16
        Assert.Throws<global::Itb.Wrapper.InvalidKeyException>(() =>
            WrapperCore.Wrap(OuterCipher.Aes128Ctr, badKey, new byte[64]));
    }

    [Fact]
    public void WrapRejectsKeyLengthMismatchChacha()
    {
        var badKey = new byte[16]; // expected 32
        Assert.Throws<global::Itb.Wrapper.InvalidKeyException>(() =>
            WrapperCore.Wrap(OuterCipher.ChaCha20, badKey, new byte[64]));
    }

    [Fact]
    public void UnwrapRejectsKeyLengthMismatch()
    {
        var key = WrapperCore.GenerateKey(OuterCipher.Aes128Ctr);
        var wire = WrapperCore.Wrap(OuterCipher.Aes128Ctr, key, new byte[64]);
        var badKey = new byte[8];
        Assert.Throws<global::Itb.Wrapper.InvalidKeyException>(() =>
            WrapperCore.Unwrap(OuterCipher.Aes128Ctr, badKey, wire));
    }

    [Fact]
    public void UnwrapRejectsTooShortWire()
    {
        var key = WrapperCore.GenerateKey(OuterCipher.Aes128Ctr);
        var shortWire = new byte[8]; // shorter than 16-byte AES nonce
        Assert.Throws<global::Itb.Wrapper.InvalidNonceException>(() =>
            WrapperCore.Unwrap(OuterCipher.Aes128Ctr, key, shortWire));
    }

    [Fact]
    public void UnwrapInPlaceRejectsTooShortWire()
    {
        var key = WrapperCore.GenerateKey(OuterCipher.Aes128Ctr);
        var shortWire = new byte[8];
        Assert.Throws<global::Itb.Wrapper.InvalidNonceException>(() =>
            ItbWrapperHelper.UnwrapInPlaceShortHelper(OuterCipher.Aes128Ctr, key, shortWire));
    }

    [Fact]
    public void UnwrapStreamReaderRejectsBadNonceLength()
    {
        var key = WrapperCore.GenerateKey(OuterCipher.Aes128Ctr);
        var badNonce = new byte[8]; // expected 16
        Assert.Throws<global::Itb.Wrapper.InvalidNonceException>(() =>
            new global::Itb.Wrapper.UnwrapStreamReader(OuterCipher.Aes128Ctr, key, badNonce));
    }

    [Fact]
    public void UnknownCipherEnumValueThrows()
    {
        // The Cipher enum is closed at the type-system level, but the
        // FFI path's defensive InvalidCipherException is reachable
        // when a Cipher value cast from an out-of-range int slips
        // through. The cipher-name extension method protects against
        // most of this, surfacing ArgumentOutOfRangeException directly.
        var bogus = (OuterCipher)99;
        Assert.Throws<ArgumentOutOfRangeException>(() => WrapperCore.KeySize(bogus));
    }
}

/// <summary>
/// Helper that reproduces the failure-path call signature for tests
/// that need a ref-style argument from inside an Action lambda.
/// </summary>
internal static class ItbWrapperHelper
{
    internal static Span<byte> UnwrapInPlaceShortHelper(OuterCipher cipher, byte[] key, byte[] wire)
    {
        return WrapperCore.UnwrapInPlace(cipher, key, wire.AsSpan());
    }
}
