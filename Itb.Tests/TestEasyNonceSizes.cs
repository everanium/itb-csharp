// Round-trip tests across all per-instance nonce-size configurations.
//
// Symmetric counterpart to bindings/python/tests/easy/test_nonce_sizes.py.
// The Encryptor surface exposes nonce_bits as a per-instance setter
// (Encryptor.SetNonceBits) AND tracks the process-global default at
// construction time via Library.NonceBits. This file covers both axes:
//
//   - Library.NonceBits as the construction-time default that a fresh
//     encryptor inherits (NonceBits property reads through to libitb's
//     ITB_Easy_NonceBits, so a setter on Library.NonceBits BEFORE the
//     Encryptor is built is reflected on enc.NonceBits / enc.HeaderSize);
//   - Encryptor.SetNonceBits as the per-instance override that
//     mutates only this encryptor's Config copy.
//
// The class touches Library.NonceBits, which is process-global, so it
// is decorated with [Collection(TestCollections.GlobalState)] to
// serialise it with every other class in the same collection. Each
// [Fact] captures and restores the process-wide config via
// GlobalStateSnapshot so later tests see a clean state.

using Itb.Native;

namespace Itb.Tests;

[Collection(TestCollections.GlobalState)]
public sealed class TestEasyNonceSizes
{
    private static readonly int[] NonceSizes = { 128, 256, 512 };

    private static readonly string[] HashesByWidth =
    {
        "siphash24",
        "blake3",
        "blake2b512",
    };

    private static readonly string[] MacNames =
    {
        "kmac256", "hmac-sha256", "hmac-blake3",
    };

    /// <summary>
    /// Default nonce_bits is 128 with header_size 20 on a fresh
    /// encryptor when the process-global has not been altered.
    /// </summary>
    [Fact]
    public void DefaultIsTwentyByteHeader()
    {
        using var snap = GlobalStateSnapshot.Capture();
        Library.NonceBits = 128;
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        Assert.Equal(20, enc.HeaderSize);
        Assert.Equal(128, enc.NonceBits);
    }

    /// <summary>
    /// Setting <see cref="Library.NonceBits"/> before constructing the
    /// encryptor is reflected on <see cref="Encryptor.NonceBits"/> and
    /// <see cref="Encryptor.HeaderSize"/>.
    /// </summary>
    [Fact]
    public void GlobalNonceBitsTracksEncryptorOnConstruction()
    {
        using var snap = GlobalStateSnapshot.Capture();
        foreach (var n in NonceSizes)
        {
            Library.NonceBits = n;
            using var enc = new Encryptor("blake3", 1024, "kmac256");
            Assert.Equal(n, enc.NonceBits);
            Assert.Equal(n / 8 + 4, enc.HeaderSize);
        }
    }

    /// <summary>
    /// Per-instance setter <see cref="Encryptor.SetNonceBits"/> mutates
    /// the encryptor's Config copy without touching
    /// <see cref="Library.NonceBits"/>.
    /// </summary>
    [Fact]
    public void PerInstanceSetterTracks()
    {
        using var snap = GlobalStateSnapshot.Capture();
        foreach (var n in NonceSizes)
        {
            using var enc = new Encryptor("blake3", 1024, "kmac256");
            enc.SetNonceBits(n);
            Assert.Equal(n, enc.NonceBits);
            Assert.Equal(n / 8 + 4, enc.HeaderSize);
        }
    }

    /// <summary>
    /// Single Ouroboros one-shot encrypt / decrypt across all three
    /// nonce sizes via the per-instance setter.
    /// <see cref="Encryptor.ParseChunkLen"/> reports the full chunk
    /// length on the wire.
    /// </summary>
    [Fact]
    public void SingleEncryptDecryptAcrossNonceSizes()
    {
        using var snap = GlobalStateSnapshot.Capture();
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var hashName in HashesByWidth)
            {
                using var enc = new Encryptor(hashName, 1024, "kmac256");
                enc.SetNonceBits(n);
                var ct = enc.Encrypt(plaintext);
                var pt = enc.Decrypt(ct);
                Assert.Equal(plaintext, pt);
                Assert.Equal(ct.Length, enc.ParseChunkLen(ct.AsSpan(0, enc.HeaderSize)));
            }
        }
    }

    /// <summary>
    /// Triple Ouroboros one-shot encrypt / decrypt across all three
    /// nonce sizes via the per-instance setter.
    /// </summary>
    [Fact]
    public void TripleEncryptDecryptAcrossNonceSizes()
    {
        using var snap = GlobalStateSnapshot.Capture();
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var hashName in HashesByWidth)
            {
                using var enc = new Encryptor(hashName, 1024, "kmac256", mode: "triple");
                enc.SetNonceBits(n);
                var ct = enc.Encrypt(plaintext);
                var pt = enc.Decrypt(ct);
                Assert.Equal(plaintext, pt);
                Assert.Equal(ct.Length, enc.ParseChunkLen(ct.AsSpan(0, enc.HeaderSize)));
            }
        }
    }

    /// <summary>
    /// Single Ouroboros + Auth round trip + tamper rejection at the
    /// per-instance header offset across all three nonce sizes and all
    /// three MAC primitives.
    /// </summary>
    [Fact]
    public void SingleAuthAcrossNonceSizes()
    {
        using var snap = GlobalStateSnapshot.Capture();
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var macName in MacNames)
            {
                using var enc = new Encryptor("blake3", 1024, macName);
                enc.SetNonceBits(n);
                var ct = enc.EncryptAuth(plaintext);
                var pt = enc.DecryptAuth(ct);
                Assert.Equal(plaintext, pt);

                var tampered = (byte[])ct.Clone();
                var h = enc.HeaderSize;
                var end = Math.Min(h + 256, tampered.Length);
                for (var i = h; i < end; i++)
                {
                    tampered[i] ^= 0x01;
                }
                var ex = Assert.Throws<ItbException>(() => enc.DecryptAuth(tampered));
                Assert.Equal(Status.MacFailure, ex.Status);
            }
        }
    }

    /// <summary>
    /// Triple Ouroboros + Auth round trip + tamper rejection at the
    /// per-instance header offset across all three nonce sizes and
    /// all three MAC primitives.
    /// </summary>
    [Fact]
    public void TripleAuthAcrossNonceSizes()
    {
        using var snap = GlobalStateSnapshot.Capture();
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var macName in MacNames)
            {
                using var enc = new Encryptor("blake3", 1024, macName, mode: "triple");
                enc.SetNonceBits(n);
                var ct = enc.EncryptAuth(plaintext);
                var pt = enc.DecryptAuth(ct);
                Assert.Equal(plaintext, pt);

                var tampered = (byte[])ct.Clone();
                var h = enc.HeaderSize;
                var end = Math.Min(h + 256, tampered.Length);
                for (var i = h; i < end; i++)
                {
                    tampered[i] ^= 0x01;
                }
                var ex = Assert.Throws<ItbException>(() => enc.DecryptAuth(tampered));
                Assert.Equal(Status.MacFailure, ex.Status);
            }
        }
    }

    /// <summary>
    /// Per-instance nonce_bits are isolated: one encryptor's
    /// <see cref="Encryptor.SetNonceBits"/> does not affect another
    /// encryptor that uses the default.
    /// </summary>
    [Fact]
    public void TwoEncryptorsIndependentNonceBits()
    {
        using var snap = GlobalStateSnapshot.Capture();
        Library.NonceBits = 128;

        var plaintext = "isolation test"u8.ToArray();
        using var a = new Encryptor("blake3", 1024, "kmac256");
        using var b = new Encryptor("blake3", 1024, "kmac256");
        a.SetNonceBits(512);
        Assert.Equal(512, a.NonceBits);
        Assert.Equal(68, a.HeaderSize);
        Assert.Equal(128, b.NonceBits);
        Assert.Equal(20, b.HeaderSize);

        Assert.Equal(plaintext, a.Decrypt(a.Encrypt(plaintext)));
        Assert.Equal(plaintext, b.Decrypt(b.Encrypt(plaintext)));
    }
}
