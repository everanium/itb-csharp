// BLAKE3-focused Encryptor coverage.
//
// Symmetric counterpart to bindings/python/tests/easy/test_blake3.py
// applied to the high-level Encryptor surface. BLAKE3 ships at a single
// width (-256), so the matrix iterates a single primitive across the
// three nonce sizes, both Ouroboros modes, and the persistence +
// plaintext-size sweeps.
//
// Encryptor.SetNonceBits is per-instance and does not touch process-
// global state, so these tests do not need [Collection(GlobalState)].
// Persistence rides on Encryptor.Export / Import (JSON blob, single
// round-trip).

using Itb.Native;

namespace Itb.Tests;

[Collection(TestCollections.MismatchField)]
public class TestEasyBlake3
{
    // (hash, ITB_seed_width) — BLAKE3 ships only at -256.
    private static readonly (string Hash, int Width)[] Blake3Hashes = new[]
    {
        ("blake3", 256),
    };

    // Hash-key length (bytes) per primitive.
    private static readonly Dictionary<string, int> ExpectedKeyLen = new()
    {
        ["blake3"] = 32,
    };

    private static readonly int[] NonceSizes = { 128, 256, 512 };
    private static readonly string[] MacNames = { "kmac256", "hmac-sha256", "hmac-blake3" };

    private static int[] KeyBitsFor(int width) =>
        new[] { 512, 1024, 2048 }.Where(k => k % width == 0).ToArray();

    [Fact]
    public void RoundtripAcrossNonceSizes()
    {
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var (hashName, _) in Blake3Hashes)
            {
                using var enc = new Encryptor(hashName, 1024, "kmac256");
                enc.SetNonceBits(n);
                var ct = enc.Encrypt(plaintext);
                var pt = enc.Decrypt(ct);
                Assert.Equal(plaintext, pt);
            }
        }
    }

    [Fact]
    public void TripleRoundtripAcrossNonceSizes()
    {
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var (hashName, _) in Blake3Hashes)
            {
                using var enc = new Encryptor(hashName, 1024, "kmac256", mode: "triple");
                enc.SetNonceBits(n);
                var ct = enc.Encrypt(plaintext);
                var pt = enc.Decrypt(ct);
                Assert.Equal(plaintext, pt);
            }
        }
    }

    [Fact]
    public void AuthAcrossNonceSizes()
    {
        // Tamper region starts past the chunk header (nonce + 2-byte
        // width + 2-byte height) so the body bytes get bit-flipped, not
        // the header dimensions. Header size comes from the encryptor's
        // per-instance NonceBits.
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var macName in MacNames)
            {
                foreach (var (hashName, _) in Blake3Hashes)
                {
                    using var enc = new Encryptor(hashName, 1024, macName);
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
    }

    [Fact]
    public void TripleAuthAcrossNonceSizes()
    {
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var macName in MacNames)
            {
                foreach (var (hashName, _) in Blake3Hashes)
                {
                    using var enc = new Encryptor(hashName, 1024, macName, mode: "triple");
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
    }

    [Fact]
    public void PersistenceAcrossNonceSizes()
    {
        // Encrypt → export blob → free encryptor → fresh encryptor →
        // import blob → decrypt → verify plaintext bit-identical. The
        // SetNonceBits state is per-instance and not carried in the
        // blob (deployment config), so the receiver mirrors it via a
        // matching SetNonceBits call.
        var prefix = "persistence payload "u8.ToArray();
        var plaintext = prefix.Concat(TestRng.Bytes(1024)).ToArray();

        foreach (var (hashName, width) in Blake3Hashes)
        {
            foreach (var keyBits in KeyBitsFor(width))
            {
                foreach (var n in NonceSizes)
                {
                    // Day 1.
                    var src = new Encryptor(hashName, keyBits, "kmac256");
                    src.SetNonceBits(n);
                    Assert.Equal(ExpectedKeyLen[hashName], src.PRFKey(0).Length);
                    Assert.Equal(keyBits, src.SeedComponents(0).Length * 64);
                    var blob = src.Export();
                    var ct = src.Encrypt(plaintext);
                    src.Dispose();

                    // Day 2.
                    using var dst = new Encryptor(hashName, keyBits, "kmac256");
                    dst.SetNonceBits(n);
                    dst.Import(blob);
                    var pt = dst.Decrypt(ct);
                    Assert.Equal(plaintext, pt);
                }
            }
        }
    }

    [Fact]
    public void RoundtripSizes()
    {
        // Round-trip across plaintext sizes that span multiple chunk
        // boundaries. ITB's processChunk batches 4 pixels per BatchHash
        // call; trailing partial batches dispatch via the per-lane
        // fallback.
        foreach (var (hashName, _) in Blake3Hashes)
        {
            foreach (var n in NonceSizes)
            {
                foreach (var sz in new[] { 1, 16, 1024, 16 * 1024 })
                {
                    var plaintext = TestRng.Bytes(sz);
                    using var enc = new Encryptor(hashName, 1024, "kmac256");
                    enc.SetNonceBits(n);
                    var ct = enc.Encrypt(plaintext);
                    var pt = enc.Decrypt(ct);
                    Assert.Equal(plaintext, pt);
                }
            }
        }
    }

    [Fact]
    public void ConstructorFieldsReflectArguments()
    {
        foreach (var (hashName, _) in Blake3Hashes)
        {
            foreach (var keyBits in new[] { 512, 1024, 2048 })
            {
                using var enc = new Encryptor(hashName, keyBits, "kmac256");
                Assert.Equal(hashName, enc.Primitive);
                Assert.Equal(keyBits, enc.KeyBits);
                Assert.Equal(1, enc.Mode);
                Assert.Equal("kmac256", enc.MacName);
                Assert.False(enc.IsMixed);
            }

            using var triple = new Encryptor(hashName, 1024, "kmac256", mode: "triple");
            Assert.Equal(3, triple.Mode);
        }
    }

    [Fact]
    public void DefaultMacOverridesToHmacBlake3()
    {
        foreach (var (hashName, _) in Blake3Hashes)
        {
            using var enc = new Encryptor(hashName, 1024);
            Assert.Equal("hmac-blake3", enc.MacName);
        }
    }

    [Fact]
    public void HasPRFKeysIsTrueForBlake3()
    {
        foreach (var (hashName, _) in Blake3Hashes)
        {
            using var enc = new Encryptor(hashName, 1024, "kmac256");
            Assert.True(enc.HasPRFKeys);
            Assert.Equal(ExpectedKeyLen[hashName], enc.PRFKey(0).Length);
            Assert.NotEmpty(enc.MacKey());
        }
    }

    [Fact]
    public void SeedComponentsCountReflectsKeyBits()
    {
        foreach (var keyBits in new[] { 512, 1024, 2048 })
        {
            using var enc = new Encryptor("blake3", keyBits, "kmac256");
            var components = enc.SeedComponents(0);
            Assert.Equal(keyBits / 64, components.Length);
            Assert.InRange(components.Length, 8, 32);
        }
    }

    [Fact]
    public void SetBarrierFillRoundtrip()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        foreach (var bf in new[] { 1, 2, 4, 8, 16, 32 })
        {
            enc.SetBarrierFill(bf);
        }
        var ct = enc.Encrypt(TestRng.Bytes(256));
        var pt = enc.Decrypt(ct);
        Assert.Equal(256, pt.Length);
    }

    [Fact]
    public void ImportWrongPrimitiveRaisesMismatch()
    {
        using var src = new Encryptor("blake3", 1024, "kmac256");
        var blob = src.Export();

        using var dst = new Encryptor("blake2s", 1024, "kmac256");
        var ex = Assert.Throws<ItbEasyMismatchException>(() => dst.Import(blob));
        Assert.Equal("primitive", ex.Field);
    }

    // SKIPPED — test_double_free_idempotent: Encryptor.Dispose / Close
    // are idempotent in the C# binding.
    // SKIPPED — test_context_manager: covered by `using var ...`.
    // SKIPPED — test_bytearray_input / test_memoryview_input: covered
    // by ReadOnlySpan<byte>.
    // SKIPPED — test_type_check: covered by the static type system.
}
