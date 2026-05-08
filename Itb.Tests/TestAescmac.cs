// AES-CMAC-focused C# binding coverage.
//
// W128 counterpart to TestChacha20.cs / TestBlake3.cs: the same
// coverage shape (nonce-size sweep, single + Triple Ouroboros
// roundtrip, single + triple auth with tamper rejection, persistence
// sweep, plaintext-size sweep) applied to aescmac. AES-CMAC ships at
// a single width (-128 — the AES block size) so this file iterates
// the single primitive across the same axes TestChacha20.cs covers.
//
// Mirrors bindings/python/tests/test_aescmac.py one-to-one. Each
// Python TestCase.test_* becomes a single [Fact] method here; the
// per-class subTest loops are inlined since xunit's runner has no
// equivalent of unittest subTest.
//
// Every test mutates the process-global NonceBits, so each test
// class is decorated with [Collection(TestCollections.GlobalState)]
// to serialise it with every other class touching libitb globals.
// A GlobalStateSnapshot captures and restores NonceBits / BitSoup /
// LockSoup / MaxWorkers / BarrierFill across the test body.
//
// The Python skip set covered by C#'s static type system / IDisposable
// contract:
//   * test_double_free_idempotent — Dispose() is idempotent in C#.
//   * test_context_manager — `using var ...` enforced at compile time.
//   * test_bytearray_input / test_memoryview_input — ReadOnlySpan<byte>
//     accepts any byte-slice reference uniformly.
//   * test_type_check — non-Seed arguments rejected at compile time.

using Itb.Native;

namespace Itb.Tests;

[Collection(TestCollections.GlobalState)]
public sealed class TestAescmac
{
    /// <summary>Hash registry rows exercised by the test class —
    /// AES-CMAC ships only at <c>aescmac</c>/-128.</summary>
    private static readonly (string Name, int Width)[] Hashes =
    {
        ("aescmac", 128),
    };

    /// <summary>Native fixed-key length per primitive — AES-CMAC
    /// carries a 16-byte AES-128 key.</summary>
    private static int ExpectedKeyLen(string name) => name switch
    {
        "aescmac" => 16,
        _ => throw new ArgumentException($"unknown hash {name}"),
    };

    private static readonly int[] NonceSizes = { 128, 256, 512 };

    private static readonly string[] MacNames =
    {
        "kmac256", "hmac-sha256", "hmac-blake3",
    };

    /// <summary>
    /// Single Ouroboros encrypt / decrypt over aescmac × all three
    /// nonce sizes. The four-pixel-batched ASM kernel runs a length-
    /// specialised path at 20 / 36 / 68 bytes; the loop below drives
    /// every shape through the FFI surface.
    /// </summary>
    [Fact]
    public void RoundtripAcrossNonceSizes()
    {
        using var snap = GlobalStateSnapshot.Capture();
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var (hashName, _) in Hashes)
            {
                Library.NonceBits = n;
                using var s0 = new Seed(hashName, 1024);
                using var s1 = new Seed(hashName, 1024);
                using var s2 = new Seed(hashName, 1024);
                var ct = Cipher.Encrypt(s0, s1, s2, plaintext);
                var pt = Cipher.Decrypt(s0, s1, s2, ct);
                Assert.Equal(plaintext, pt);
                var h = Library.HeaderSize;
                var chunkLen = Library.ParseChunkLen(ct.AsSpan(0, h));
                Assert.Equal(ct.Length, chunkLen);
            }
        }
    }

    /// <summary>
    /// Triple Ouroboros (7 seeds) encrypt / decrypt over aescmac ×
    /// all three nonce sizes.
    /// </summary>
    [Fact]
    public void TripleRoundtripAcrossNonceSizes()
    {
        using var snap = GlobalStateSnapshot.Capture();
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var (hashName, _) in Hashes)
            {
                Library.NonceBits = n;
                var seeds = new Seed[7];
                try
                {
                    for (var i = 0; i < 7; i++)
                    {
                        seeds[i] = new Seed(hashName, 1024);
                    }
                    var ct = Cipher.EncryptTriple(
                        seeds[0], seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6],
                        plaintext);
                    var pt = Cipher.DecryptTriple(
                        seeds[0], seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6],
                        ct);
                    Assert.Equal(plaintext, pt);
                }
                finally
                {
                    foreach (var s in seeds)
                    {
                        s?.Dispose();
                    }
                }
            }
        }
    }

    /// <summary>
    /// Single + Auth round trip + tamper rejection over aescmac × all
    /// three nonce sizes. Each MAC primitive is paired with aescmac
    /// to confirm the auth scaffolding is width-agnostic.
    /// </summary>
    [Fact]
    public void AuthAcrossNonceSizes()
    {
        using var snap = GlobalStateSnapshot.Capture();
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var macName in MacNames)
            {
                foreach (var (hashName, _) in Hashes)
                {
                    Library.NonceBits = n;
                    using var mac = new Mac(macName, TestRng.Bytes(32));
                    using var s0 = new Seed(hashName, 1024);
                    using var s1 = new Seed(hashName, 1024);
                    using var s2 = new Seed(hashName, 1024);
                    var ct = Cipher.EncryptAuth(s0, s1, s2, mac, plaintext);
                    var pt = Cipher.DecryptAuth(s0, s1, s2, mac, ct);
                    Assert.Equal(plaintext, pt);

                    // Tamper at the dynamic header offset.
                    var tampered = (byte[])ct.Clone();
                    var h = Library.HeaderSize;
                    var end = Math.Min(h + 256, tampered.Length);
                    for (var i = h; i < end; i++)
                    {
                        tampered[i] ^= 0x01;
                    }
                    var ex = Assert.Throws<ItbException>(() =>
                        Cipher.DecryptAuth(s0, s1, s2, mac, tampered));
                    Assert.Equal(Status.MacFailure, ex.Status);
                }
            }
        }
    }

    /// <summary>
    /// Triple + Auth (7 seeds) round trip + tamper rejection over
    /// aescmac × all three nonce sizes.
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
                foreach (var (hashName, _) in Hashes)
                {
                    Library.NonceBits = n;
                    using var mac = new Mac(macName, TestRng.Bytes(32));
                    var seeds = new Seed[7];
                    try
                    {
                        for (var i = 0; i < 7; i++)
                        {
                            seeds[i] = new Seed(hashName, 1024);
                        }
                        var ct = Cipher.EncryptAuthTriple(
                            seeds[0], seeds[1], seeds[2], seeds[3],
                            seeds[4], seeds[5], seeds[6],
                            mac, plaintext);
                        var pt = Cipher.DecryptAuthTriple(
                            seeds[0], seeds[1], seeds[2], seeds[3],
                            seeds[4], seeds[5], seeds[6],
                            mac, ct);
                        Assert.Equal(plaintext, pt);

                        var tampered = (byte[])ct.Clone();
                        var h = Library.HeaderSize;
                        var end = Math.Min(h + 256, tampered.Length);
                        for (var i = h; i < end; i++)
                        {
                            tampered[i] ^= 0x01;
                        }
                        var ex = Assert.Throws<ItbException>(() =>
                            Cipher.DecryptAuthTriple(
                                seeds[0], seeds[1], seeds[2], seeds[3],
                                seeds[4], seeds[5], seeds[6],
                                mac, tampered));
                        Assert.Equal(Status.MacFailure, ex.Status);
                    }
                    finally
                    {
                        foreach (var s in seeds)
                        {
                            s?.Dispose();
                        }
                    }
                }
            }
        }
    }

    /// <summary>
    /// Encrypt with aescmac, snapshot (components + hash key), free
    /// the seeds, reconstruct via <see cref="Seed.FromComponents"/>,
    /// decrypt, verify the plaintext is bit-identical. Each
    /// (key_bits, nonce_bits) combination must roundtrip — a
    /// regression in the AES-CMAC ASM kernel that drifts between
    /// original and restored seeds (a mis-broadcast AES round key or
    /// a wrong lenTag fold) would surface as a decrypt mismatch on
    /// the day-2 path while leaving the day-1 encrypt path silent.
    /// </summary>
    [Fact]
    public void PersistenceAcrossNonceSizes()
    {
        using var snap = GlobalStateSnapshot.Capture();
        var prefix = System.Text.Encoding.ASCII.GetBytes("persistence payload ");
        var tail = TestRng.Bytes(1024);
        var plaintext = new byte[prefix.Length + tail.Length];
        Buffer.BlockCopy(prefix, 0, plaintext, 0, prefix.Length);
        Buffer.BlockCopy(tail, 0, plaintext, prefix.Length, tail.Length);

        foreach (var (hashName, width) in Hashes)
        {
            var validKeyBits = new[] { 512, 1024, 2048 }
                .Where(k => k % width == 0)
                .ToArray();
            foreach (var keyBits in validKeyBits)
            {
                foreach (var n in NonceSizes)
                {
                    Library.NonceBits = n;

                    // Day 1 — random seeds.
                    ulong[] nsComps, dsComps, ssComps;
                    byte[] nsKey, dsKey, ssKey;
                    byte[] ciphertext;
                    using (var ns = new Seed(hashName, keyBits))
                    using (var ds = new Seed(hashName, keyBits))
                    using (var ss = new Seed(hashName, keyBits))
                    {
                        nsComps = ns.GetComponents();
                        dsComps = ds.GetComponents();
                        ssComps = ss.GetComponents();
                        nsKey = ns.GetHashKey();
                        dsKey = ds.GetHashKey();
                        ssKey = ss.GetHashKey();

                        Assert.Equal(ExpectedKeyLen(hashName), nsKey.Length);
                        Assert.Equal(keyBits, nsComps.Length * 64);

                        ciphertext = Cipher.Encrypt(ns, ds, ss, plaintext);
                    }

                    // Day 2 — restore from saved material.
                    using var ns2 = Seed.FromComponents(hashName, nsComps, nsKey);
                    using var ds2 = Seed.FromComponents(hashName, dsComps, dsKey);
                    using var ss2 = Seed.FromComponents(hashName, ssComps, ssKey);
                    var decrypted = Cipher.Decrypt(ns2, ds2, ss2, ciphertext);
                    Assert.Equal(plaintext, decrypted);
                }
            }
        }
    }

    /// <summary>
    /// Roundtrip aescmac on plaintext sizes that span multiple chunk
    /// boundaries. ITB's processChunk128 batches 4 pixels per
    /// BatchHash call; trailing partial batches must dispatch via the
    /// per-lane fallback, and the test surfaces any boundary bug
    /// where the batched arm runs on incomplete lane data.
    /// </summary>
    [Fact]
    public void RoundtripSizes()
    {
        using var snap = GlobalStateSnapshot.Capture();
        var sizes = new[] { 1, 17, 4096, 65536, 1 << 20 };
        foreach (var (hashName, _) in Hashes)
        {
            foreach (var n in NonceSizes)
            {
                foreach (var sz in sizes)
                {
                    Library.NonceBits = n;
                    var plaintext = TestRng.Bytes(sz);
                    using var ns = new Seed(hashName, 1024);
                    using var ds = new Seed(hashName, 1024);
                    using var ss = new Seed(hashName, 1024);
                    var ct = Cipher.Encrypt(ns, ds, ss, plaintext);
                    var pt = Cipher.Decrypt(ns, ds, ss, ct);
                    Assert.Equal(plaintext, pt);
                }
            }
        }
    }

    /// <summary>
    /// Width / hash-name introspection plus the bad-keyBits and
    /// unrecognised-hash-name negative paths. Matches the constructor
    /// + introspection coverage that lived in the Python suite's
    /// shared TestPersistence file but locks it in per-primitive here.
    /// </summary>
    [Fact]
    public void IntrospectionAndInvalidInputs()
    {
        using var snap = GlobalStateSnapshot.Capture();
        foreach (var (hashName, width) in Hashes)
        {
            using var seed = new Seed(hashName, 1024);
            Assert.Equal(width, seed.Width);
            Assert.Equal(hashName, seed.HashName);
            Assert.Equal(hashName, seed.HashNameIntrospect());

            var key = seed.GetHashKey();
            Assert.Equal(ExpectedKeyLen(hashName), key.Length);

            var comps = seed.GetComponents();
            Assert.Equal(1024 / 64, comps.Length);
            Assert.True(comps.Length is >= 8 and <= 32);
            Assert.Equal(0, comps.Length % 8);
        }

        // Bad key bits.
        var badBits = Assert.Throws<ItbException>(() =>
            new Seed("aescmac", 333));
        Assert.Equal(Status.BadKeyBits, badBits.Status);

        // Unrecognised hash name.
        var badHash = Assert.Throws<ItbException>(() =>
            new Seed("not-a-real-hash", 1024));
        Assert.Equal(Status.BadHash, badHash.Status);
    }
}
