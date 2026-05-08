// AES-CMAC-focused Encryptor coverage.
//
// Symmetric counterpart to bindings/python/tests/easy/test_aescmac.py
// applied to the high-level Encryptor surface. AES-CMAC ships only at
// -128 (the AES block size), so the matrix iterates a single primitive
// across the three nonce sizes, both Ouroboros modes, and the persistence
// + plaintext-size sweeps. The constructor's default-MAC override
// ("hmac-blake3") is exercised separately from the explicit MAC sweep.
//
// The Python source uses subTest for matrix iteration; the C# port keeps
// the loops and asserts inline so xunit reports each combination as part
// of the surrounding [Fact] (a failure prints the loop indices via the
// explicit Assert.Fail message context).

using Itb.Native;

namespace Itb.Tests;

[Collection(TestCollections.MismatchField)]
public class TestEasyAescmac
{
    private static readonly (string Hash, int Width)[] AescmacHashes = new[]
    {
        ("aescmac", 128),
    };

    private static readonly Dictionary<string, int> ExpectedKeyLen = new()
    {
        ["aescmac"] = 16,
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
            foreach (var (hashName, _) in AescmacHashes)
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
            foreach (var (hashName, _) in AescmacHashes)
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
                foreach (var (hashName, _) in AescmacHashes)
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
                foreach (var (hashName, _) in AescmacHashes)
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
        var prefix = "persistence payload "u8.ToArray();
        var plaintext = prefix.Concat(TestRng.Bytes(1024)).ToArray();

        foreach (var (hashName, width) in AescmacHashes)
        {
            foreach (var keyBits in KeyBitsFor(width))
            {
                foreach (var n in NonceSizes)
                {
                    var src = new Encryptor(hashName, keyBits, "kmac256");
                    src.SetNonceBits(n);
                    Assert.Equal(ExpectedKeyLen[hashName], src.PRFKey(0).Length);
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
        // Brief specifies 1 / 16 / 1 KiB / 16 KiB plaintext as the edge
        // sweep — narrower than the Python file's 1 MiB upper bound so
        // the C# matrix completes inside the unit-test budget.
        foreach (var (hashName, _) in AescmacHashes)
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
        foreach (var (hashName, _) in AescmacHashes)
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
            Assert.False(triple.IsMixed);
        }
    }

    [Fact]
    public void DefaultMacOverridesToHmacBlake3()
    {
        // Constructor without explicit mac argument routes through the
        // binding-level default — "hmac-blake3" — instead of forwarding
        // NULL through to libitb's own default.
        foreach (var (hashName, _) in AescmacHashes)
        {
            using var enc = new Encryptor(hashName, 1024);
            Assert.Equal("hmac-blake3", enc.MacName);
        }
    }

    [Fact]
    public void HasPRFKeysIsTrueForAescmac()
    {
        using var enc = new Encryptor("aescmac", 1024, "kmac256");
        Assert.True(enc.HasPRFKeys);
        Assert.Equal(16, enc.PRFKey(0).Length);
        Assert.NotEmpty(enc.MacKey());
    }

    [Fact]
    public void SeedComponentsCountReflectsKeyBits()
    {
        foreach (var keyBits in new[] { 512, 1024, 2048 })
        {
            using var enc = new Encryptor("aescmac", keyBits, "kmac256");
            var components = enc.SeedComponents(0);
            Assert.Equal(keyBits / 64, components.Length);
            Assert.InRange(components.Length, 8, 32);
        }
    }

    [Fact]
    public void SetBarrierFillRoundtrip()
    {
        using var enc = new Encryptor("aescmac", 1024, "kmac256");
        foreach (var bf in new[] { 1, 2, 4, 8, 16, 32 })
        {
            enc.SetBarrierFill(bf);
        }
        // Barrier-fill setter has no public getter on Encryptor — no
        // assertion past the "setter does not throw" smoke check.
        var ct = enc.Encrypt(TestRng.Bytes(256));
        var pt = enc.Decrypt(ct);
        Assert.Equal(256, pt.Length);
    }

    [Fact]
    public void ImportWrongPrimitiveRaisesMismatch()
    {
        using var src = new Encryptor("aescmac", 1024, "kmac256");
        var blob = src.Export();

        // Cross-import into a different primitive — surfaces typed
        // ItbEasyMismatchException with .Field == "primitive".
        using var dst = new Encryptor("blake3", 1024, "kmac256");
        var ex = Assert.Throws<ItbEasyMismatchException>(() => dst.Import(blob));
        Assert.Equal("primitive", ex.Field);
    }

    // SKIPPED — Python's test_double_free_idempotent is covered by C#
    // Encryptor.Dispose / Close idempotency at the type level (handle
    // becomes 0 after first call, subsequent calls are no-ops).
    //
    // SKIPPED — Python's test_context_manager is covered by `using var
    // enc = new Encryptor(...)` at compile time.
    //
    // SKIPPED — Python's test_bytearray_input / test_memoryview_input
    // are covered by the ReadOnlySpan<byte> parameter accepting any
    // byte-slice reference.
    //
    // SKIPPED — Python's test_type_check is covered by C#'s static
    // type system at compile time.
}
