// SipHash-2-4-focused Encryptor coverage.
//
// Symmetric counterpart to bindings/python/tests/easy/test_siphash24.py
// applied to the high-level Encryptor surface. SipHash-2-4 ships only
// at -128 and is the unique primitive with no fixed PRF key —
// HasPRFKeys reports false, PRFKey raises ItbException with status
// BadInput. The persistence path therefore exports / imports without
// prf_keys carried in the JSON blob; the seed components alone
// reconstruct the SipHash keying material.

using Itb.Native;

namespace Itb.Tests;

[Collection(TestCollections.MismatchField)]
public class TestEasySiphash24
{
    private static readonly (string Hash, int Width)[] SiphashHashes = new[]
    {
        ("siphash24", 128),
    };

    // SipHash has no internal fixed key — HasPRFKeys reports false.
    private static readonly Dictionary<string, int> ExpectedKeyLen = new()
    {
        ["siphash24"] = 0,
    };

    private static readonly int[] NonceSizes = { 128, 256, 512 };
    private static readonly string[] MacNames = { "kmac256", "hmac-sha256", "hmac-blake3" };

    private static int[] KeyBitsFor(int width) =>
        new[] { 512, 1024, 2048 }.Where(k => k % width == 0).ToArray();

    [Fact]
    public void HasNoPRFKeys()
    {
        // SipHash is the lone primitive with HasPRFKeys == false; the
        // PRF key getter rejects indexed access with status BadInput.
        using var enc = new Encryptor("siphash24", 1024, "kmac256");
        Assert.False(enc.HasPRFKeys);
        var ex = Assert.Throws<ItbException>(() => enc.PRFKey(0));
        Assert.Equal(Status.BadInput, ex.Status);
    }

    [Fact]
    public void RoundtripAcrossNonceSizes()
    {
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var (hashName, _) in SiphashHashes)
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
            foreach (var (hashName, _) in SiphashHashes)
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
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var macName in MacNames)
            {
                foreach (var (hashName, _) in SiphashHashes)
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
                foreach (var (hashName, _) in SiphashHashes)
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
        // Persistence sweep without prf_keys: SipHash's seed components
        // alone reconstruct the keying material. The exported blob omits
        // prf_keys, and Import on a fresh encryptor restores the seeds
        // without consulting them.
        var prefix = "persistence payload "u8.ToArray();
        var plaintext = prefix.Concat(TestRng.Bytes(1024)).ToArray();

        foreach (var (hashName, width) in SiphashHashes)
        {
            foreach (var keyBits in KeyBitsFor(width))
            {
                foreach (var n in NonceSizes)
                {
                    var src = new Encryptor(hashName, keyBits, "kmac256");
                    src.SetNonceBits(n);
                    Assert.False(src.HasPRFKeys);
                    Assert.Equal(keyBits, src.SeedComponents(0).Length * 64);
                    var blob = src.Export();
                    var ct = src.Encrypt(plaintext);
                    src.Dispose();

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
        foreach (var (hashName, _) in SiphashHashes)
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
        foreach (var (hashName, _) in SiphashHashes)
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
        foreach (var (hashName, _) in SiphashHashes)
        {
            using var enc = new Encryptor(hashName, 1024);
            Assert.Equal("hmac-blake3", enc.MacName);
        }
    }

    [Fact]
    public void MacKeyIsNonEmpty()
    {
        // SipHash has no PRF key but the encryptor still owns a MAC key
        // — Encryptor.MacKey returns those bytes.
        using var enc = new Encryptor("siphash24", 1024, "kmac256");
        Assert.NotEmpty(enc.MacKey());
    }

    [Fact]
    public void SeedComponentsCountReflectsKeyBits()
    {
        foreach (var keyBits in new[] { 512, 1024, 2048 })
        {
            using var enc = new Encryptor("siphash24", keyBits, "kmac256");
            var components = enc.SeedComponents(0);
            Assert.Equal(keyBits / 64, components.Length);
            Assert.InRange(components.Length, 8, 32);
        }
    }

    [Fact]
    public void SetBarrierFillRoundtrip()
    {
        using var enc = new Encryptor("siphash24", 1024, "kmac256");
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
        using var src = new Encryptor("siphash24", 1024, "kmac256");
        var blob = src.Export();

        using var dst = new Encryptor("blake3", 1024, "kmac256");
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
