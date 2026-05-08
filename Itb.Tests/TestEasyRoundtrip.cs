// End-to-end Encryptor surface coverage.
//
// Mirrors bindings/python/tests/easy/test_roundtrip.py. Cross-primitive
// matrix at 512 / 1024 / 2048 keyBits, Single + Triple Ouroboros, both
// Encrypt and EncryptAuth paths. Adds the lifecycle, defaults, and
// per-instance-config setter coverage that lives in the same Python
// file.
//
// Skipped Python tests with C# typed-language equivalents (covered at
// compile time, no runtime [Fact] needed):
//   - test_double_free_idempotent — Dispose() is idempotent.
//   - test_context_manager — `using var enc = new Encryptor(...)`.
//   - test_bytearray_input / test_memoryview_input — ReadOnlySpan<byte>
//     covers any byte-slice reference.
//   - test_type_check — non-Seed arguments rejected at compile time.

using Itb.Native;

namespace Itb.Tests;

public sealed class TestEasyRoundtrip
{
    /// <summary>Canonical hash registry rows. Order mirrors the
    /// Python source-of-truth file exactly so the C# matrix walks the
    /// primitive list identically across binding implementations.</summary>
    private static readonly (string Name, int Width)[] CanonicalHashes =
    {
        ("areion256", 256),
        ("areion512", 512),
        ("siphash24", 128),
        ("aescmac", 128),
        ("blake2b256", 256),
        ("blake2b512", 512),
        ("blake2s", 256),
        ("blake3", 256),
        ("chacha20", 256),
    };

    private static int[] KeyBitsFor(int width) =>
        new[] { 512, 1024, 2048 }.Where(k => k % width == 0).ToArray();

    /// <summary>
    /// Constructor populates the introspection accessors and Dispose
    /// idempotently zeroes the handle.
    /// </summary>
    [Fact]
    public void NewAndFree()
    {
        var enc = new Encryptor("blake3", 1024, "kmac256");
        Assert.Equal("blake3", enc.Primitive);
        Assert.Equal(1024, enc.KeyBits);
        Assert.Equal(1, enc.Mode);
        Assert.Equal("kmac256", enc.MacName);
        enc.Dispose();
        var ex = Assert.Throws<ItbException>(() => _ = enc.Primitive);
        Assert.Equal(Itb.Native.Status.EasyClosed, ex.Status);
    }

    /// <summary>
    /// Calling an Encryptor method after <see cref="Encryptor.Close"/>
    /// surfaces as <see cref="ItbException"/> with status
    /// <c>EasyClosed</c>.
    /// </summary>
    [Fact]
    public void CloseThenMethodRaises()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        enc.Close();
        var ex = Assert.Throws<ItbException>(() =>
            enc.Encrypt("after close"u8.ToArray()));
        Assert.Equal(Status.EasyClosed, ex.Status);
    }

    /// <summary>
    /// Constructor with no-explicit-MAC routes through the
    /// binding-level default "hmac-blake3".
    /// </summary>
    [Fact]
    public void DefaultMacOverride()
    {
        using var enc = new Encryptor("blake3", 1024);
        Assert.Equal("hmac-blake3", enc.MacName);
    }

    /// <summary>
    /// An unknown primitive name rejected by libitb's hash registry
    /// surfaces as <see cref="ItbException"/>.
    /// </summary>
    [Fact]
    public void BadPrimitive()
    {
        Assert.Throws<ItbException>(() =>
            new Encryptor("nonsense-hash", 1024, "kmac256"));
    }

    /// <summary>
    /// An unknown MAC name surfaces as <see cref="ItbException"/>.
    /// </summary>
    [Fact]
    public void BadMac()
    {
        Assert.Throws<ItbException>(() =>
            new Encryptor("blake3", 1024, "nonsense-mac"));
    }

    /// <summary>
    /// keyBits values outside the 512 / 1024 / 2048 grid (or wrong
    /// multiple of the native hash width) surface as
    /// <see cref="ItbException"/>.
    /// </summary>
    [Fact]
    public void BadKeyBits()
    {
        foreach (var bits in new[] { 256, 511, 999, 2049 })
        {
            Assert.Throws<ItbException>(() =>
                new Encryptor("blake3", bits, "kmac256"));
        }
    }

    /// <summary>
    /// An unrecognised mode string surfaces as
    /// <see cref="ItbException"/> with status <c>BadInput</c>.
    /// </summary>
    [Fact]
    public void BadMode()
    {
        var ex = Assert.Throws<ItbException>(() =>
            new Encryptor("blake3", 1024, "kmac256", mode: "bogus"));
        Assert.Equal(Status.BadInput, ex.Status);
    }

    /// <summary>
    /// Single Ouroboros (mode = "single", 3 seeds) end-to-end across
    /// every primitive at every supported ITB key width — plain
    /// <see cref="Encryptor.Encrypt"/> path.
    /// </summary>
    [Fact]
    public void SingleAllHashesAllWidths()
    {
        var plaintext = TestRng.Bytes(4096);
        foreach (var (name, width) in CanonicalHashes)
        {
            foreach (var keyBits in KeyBitsFor(width))
            {
                using var enc = new Encryptor(name, keyBits, "kmac256");
                var ct = enc.Encrypt(plaintext);
                Assert.True(ct.Length > plaintext.Length);
                var pt = enc.Decrypt(ct);
                Assert.Equal(plaintext, pt);
            }
        }
    }

    /// <summary>
    /// Single Ouroboros + Auth round-trip across every primitive at
    /// every supported ITB key width.
    /// </summary>
    [Fact]
    public void SingleAllHashesAllWidthsAuth()
    {
        var plaintext = TestRng.Bytes(4096);
        foreach (var (name, width) in CanonicalHashes)
        {
            foreach (var keyBits in KeyBitsFor(width))
            {
                using var enc = new Encryptor(name, keyBits, "kmac256");
                var ct = enc.EncryptAuth(plaintext);
                var pt = enc.DecryptAuth(ct);
                Assert.Equal(plaintext, pt);
            }
        }
    }

    /// <summary>
    /// Triple Ouroboros (mode = "triple", 7 seeds) end-to-end across
    /// every primitive at every supported ITB key width — plain
    /// <see cref="Encryptor.Encrypt"/> path.
    /// </summary>
    [Fact]
    public void TripleAllHashesAllWidths()
    {
        var plaintext = TestRng.Bytes(4096);
        foreach (var (name, width) in CanonicalHashes)
        {
            foreach (var keyBits in KeyBitsFor(width))
            {
                using var enc = new Encryptor(name, keyBits, "kmac256", mode: "triple");
                var ct = enc.Encrypt(plaintext);
                Assert.True(ct.Length > plaintext.Length);
                var pt = enc.Decrypt(ct);
                Assert.Equal(plaintext, pt);
            }
        }
    }

    /// <summary>
    /// Triple Ouroboros + Auth round-trip across every primitive at
    /// every supported ITB key width.
    /// </summary>
    [Fact]
    public void TripleAllHashesAllWidthsAuth()
    {
        var plaintext = TestRng.Bytes(4096);
        foreach (var (name, width) in CanonicalHashes)
        {
            foreach (var keyBits in KeyBitsFor(width))
            {
                using var enc = new Encryptor(name, keyBits, "kmac256", mode: "triple");
                var ct = enc.EncryptAuth(plaintext);
                var pt = enc.DecryptAuth(ct);
                Assert.Equal(plaintext, pt);
            }
        }
    }

    /// <summary>
    /// Seed count reflects mode: 3 for Single Ouroboros, 7 for Triple.
    /// </summary>
    [Fact]
    public void SeedCountReflectsMode()
    {
        using (var enc = new Encryptor("blake3", 1024, "kmac256"))
        {
            Assert.Equal(3, enc.SeedCount);
        }
        using (var enc = new Encryptor("blake3", 1024, "kmac256", mode: "triple"))
        {
            Assert.Equal(7, enc.SeedCount);
        }
    }

    /// <summary>
    /// <see cref="Encryptor.SetBitSoup"/> is accepted; the encryptor
    /// continues to round-trip plaintext under bit-soup.
    /// </summary>
    [Fact]
    public void SetBitSoupRoundtrip()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        enc.SetBitSoup(1);
        var pt = "bit-soup payload"u8.ToArray();
        Assert.Equal(pt, enc.Decrypt(enc.Encrypt(pt)));
    }

    /// <summary>
    /// Activating LockSoup auto-couples Bit Soup on the same encryptor;
    /// round-trip works under the coupled overlay.
    /// </summary>
    [Fact]
    public void SetLockSoupCouplesBitSoup()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        enc.SetLockSoup(1);
        var pt = "lock-soup payload"u8.ToArray();
        Assert.Equal(pt, enc.Decrypt(enc.Encrypt(pt)));
    }

    /// <summary>
    /// <see cref="Encryptor.SetLockSeed"/> grows the seed count from 3
    /// to 4 on Single Ouroboros and round-trips a known plaintext.
    /// </summary>
    [Fact]
    public void SetLockSeedGrowsSeedCount()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        Assert.Equal(3, enc.SeedCount);
        enc.SetLockSeed(1);
        Assert.Equal(4, enc.SeedCount);
        var pt = "lockseed payload"u8.ToArray();
        Assert.Equal(pt, enc.Decrypt(enc.Encrypt(pt)));
    }

    /// <summary>
    /// Calling <see cref="Encryptor.SetLockSeed"/> after the first
    /// encrypt surfaces as <see cref="ItbException"/> with status
    /// <c>EasyLockSeedAfterEncrypt</c>.
    /// </summary>
    [Fact]
    public void SetLockSeedAfterEncryptRejected()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        _ = enc.Encrypt("first"u8.ToArray());
        var ex = Assert.Throws<ItbException>(() => enc.SetLockSeed(1));
        Assert.Equal(Status.EasyLockSeedAfterEncrypt, ex.Status);
    }

    /// <summary>
    /// <see cref="Encryptor.SetNonceBits"/> accepts 128 / 256 / 512 and
    /// rejects every other value with status <c>BadInput</c>.
    /// </summary>
    [Fact]
    public void SetNonceBitsValidation()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        foreach (var valid in new[] { 128, 256, 512 })
        {
            enc.SetNonceBits(valid);
        }
        foreach (var bad in new[] { 0, 1, 192, 1024 })
        {
            var ex = Assert.Throws<ItbException>(() => enc.SetNonceBits(bad));
            Assert.Equal(Status.BadInput, ex.Status);
        }
    }

    /// <summary>
    /// <see cref="Encryptor.SetBarrierFill"/> accepts 1 / 2 / 4 / 8 / 16 /
    /// 32 and rejects every other value with status <c>BadInput</c>.
    /// </summary>
    [Fact]
    public void SetBarrierFillValidation()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        foreach (var valid in new[] { 1, 2, 4, 8, 16, 32 })
        {
            enc.SetBarrierFill(valid);
        }
        foreach (var bad in new[] { 0, 3, 5, 7, 64 })
        {
            var ex = Assert.Throws<ItbException>(() => enc.SetBarrierFill(bad));
            Assert.Equal(Status.BadInput, ex.Status);
        }
    }

    /// <summary>
    /// <see cref="Encryptor.SetChunkSize"/> accepts both an explicit
    /// positive value and 0 (auto-detect) without raising.
    /// </summary>
    [Fact]
    public void SetChunkSizeAccepted()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        enc.SetChunkSize(1024);
        enc.SetChunkSize(0);
    }

    /// <summary>
    /// Setting LockSoup on one encryptor must not bleed into another
    /// encryptor — per-instance Config snapshots are independent.
    /// </summary>
    [Fact]
    public void TwoEncryptorsIsolated()
    {
        using var a = new Encryptor("blake3", 1024, "kmac256");
        using var b = new Encryptor("blake3", 1024, "kmac256");
        a.SetLockSoup(1);
        Assert.Equal("a"u8.ToArray(), a.Decrypt(a.Encrypt("a"u8.ToArray())));
        Assert.Equal("b"u8.ToArray(), b.Decrypt(b.Encrypt("b"u8.ToArray())));
    }
}
