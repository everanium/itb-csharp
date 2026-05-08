// Cross-process persistence round-trip tests for the Encryptor surface.
//
// Mirrors bindings/python/tests/easy/test_persistence.py. The Encryptor
// blob carries strictly more state than the low-level seed-handle path:
// PRF keys for every seed slot, MAC key, optional dedicated lockSeed
// material, plus the structural metadata (primitive / keyBits / mode /
// mac).
//
// The Encryptor.Export / Encryptor.Import / Encryptor.PeekConfig
// triplet is the persistence surface required for any deployment where
// encrypt and decrypt run in different processes.
//
// Mismatch on primitive / keyBits / mode / mac at Import surfaces as
// ItbEasyMismatchException with .Field populated; structural failures
// (malformed JSON, version-too-new) surface as ItbException with the
// EasyMalformed / EasyVersionTooNew status codes.

using System.Text;
using Itb.Native;

namespace Itb.Tests;

[Collection(TestCollections.MismatchField)]
public sealed class TestEasyPersistence
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

    private static readonly Dictionary<string, int> ExpectedPRFKeyLen = new()
    {
        ["siphash24"] = 0,
        ["aescmac"] = 16,
        ["areion256"] = 32,
        ["blake2b256"] = 32,
        ["blake2s"] = 32,
        ["blake3"] = 32,
        ["chacha20"] = 32,
        ["areion512"] = 64,
        ["blake2b512"] = 64,
    };

    private static int[] KeyBitsFor(int width) =>
        new[] { 512, 1024, 2048 }.Where(k => k % width == 0).ToArray();

    /// <summary>
    /// Encrypt — Export — Dispose — fresh Encryptor — Import — Decrypt
    /// round-trip across every primitive at every supported ITB key
    /// width on Single Ouroboros.
    /// </summary>
    [Fact]
    public void RoundtripAllHashesSingle()
    {
        var prefix = "any binary data, including 0x00 bytes -- "u8.ToArray();
        var rangeBytes = new byte[256];
        for (var i = 0; i < 256; i++)
        {
            rangeBytes[i] = (byte)i;
        }
        var plaintext = prefix.Concat(rangeBytes).ToArray();

        foreach (var (name, width) in CanonicalHashes)
        {
            foreach (var keyBits in KeyBitsFor(width))
            {
                // Day 1 — random encryptor.
                var src = new Encryptor(name, keyBits, "kmac256");
                var blob = src.Export();
                var ct = src.EncryptAuth(plaintext);
                src.Dispose();

                // Day 2 — restore from saved blob.
                using var dst = new Encryptor(name, keyBits, "kmac256");
                dst.Import(blob);
                var pt = dst.DecryptAuth(ct);
                Assert.Equal(plaintext, pt);
            }
        }
    }

    /// <summary>
    /// Triple Ouroboros counterpart of
    /// <see cref="RoundtripAllHashesSingle"/>.
    /// </summary>
    [Fact]
    public void RoundtripAllHashesTriple()
    {
        var prefix = "triple-mode persistence payload "u8.ToArray();
        var rangeBytes = new byte[64];
        for (var i = 0; i < 64; i++)
        {
            rangeBytes[i] = (byte)i;
        }
        var plaintext = prefix.Concat(rangeBytes).ToArray();

        foreach (var (name, width) in CanonicalHashes)
        {
            foreach (var keyBits in KeyBitsFor(width))
            {
                var src = new Encryptor(name, keyBits, "kmac256", mode: "triple");
                var blob = src.Export();
                var ct = src.EncryptAuth(plaintext);
                src.Dispose();

                using var dst = new Encryptor(name, keyBits, "kmac256", mode: "triple");
                dst.Import(blob);
                var pt = dst.DecryptAuth(ct);
                Assert.Equal(plaintext, pt);
            }
        }
    }

    /// <summary>
    /// Activating LockSeed grows the encryptor to 4 (Single) or 8
    /// (Triple Ouroboros) seed slots. The exported blob carries the
    /// dedicated lockSeed material and Import on a fresh encryptor
    /// restores the seed slot AND auto-couples the LockSoup + Bit Soup
    /// overlays — transparent for the binding consumer.
    /// </summary>
    [Fact]
    public void RoundtripWithLockSeed()
    {
        var prefix = "lockseed payload "u8.ToArray();
        var rangeBytes = new byte[32];
        for (var i = 0; i < 32; i++)
        {
            rangeBytes[i] = (byte)i;
        }
        var plaintext = prefix.Concat(rangeBytes).ToArray();

        foreach (var (mode, expectedCount) in new[] { ("single", 4), ("triple", 8) })
        {
            var src = new Encryptor("blake3", 1024, "kmac256", mode: mode);
            src.SetLockSeed(1);
            Assert.Equal(expectedCount, src.SeedCount);
            var blob = src.Export();
            var ct = src.EncryptAuth(plaintext);
            src.Dispose();

            using var dst = new Encryptor("blake3", 1024, "kmac256", mode: mode);
            Assert.Equal(expectedCount - 1, dst.SeedCount);
            dst.Import(blob);
            Assert.Equal(expectedCount, dst.SeedCount);
            var pt = dst.DecryptAuth(ct);
            Assert.Equal(plaintext, pt);
        }
    }

    /// <summary>
    /// Per-instance configuration knobs (NonceBits, BarrierFill, BitSoup,
    /// LockSoup) round-trip through the state blob along with the seed
    /// material. The receiver picks them up transparently; no manual
    /// mirror Set*() calls required.
    /// </summary>
    [Fact]
    public void RoundtripWithFullConfig()
    {
        var prefix = "full-config persistence "u8.ToArray();
        var rangeBytes = new byte[64];
        for (var i = 0; i < 64; i++)
        {
            rangeBytes[i] = (byte)i;
        }
        var plaintext = prefix.Concat(rangeBytes).ToArray();

        var src = new Encryptor("blake3", 1024, "kmac256");
        src.SetNonceBits(512);
        src.SetBarrierFill(4);
        src.SetBitSoup(1);
        src.SetLockSoup(1);
        var blob = src.Export();
        var ct = src.EncryptAuth(plaintext);
        src.Dispose();

        using var dst = new Encryptor("blake3", 1024, "kmac256");
        Assert.Equal(128, dst.NonceBits);  // default before Import
        dst.Import(blob);
        Assert.Equal(512, dst.NonceBits);  // restored from blob
        Assert.Equal(68, dst.HeaderSize);  // follows NonceBits
        Assert.Equal(plaintext, dst.DecryptAuth(ct));
    }

    /// <summary>
    /// BarrierFill is asymmetric — the receiver does not need the same
    /// margin as the sender. When the receiver explicitly installs a
    /// non-default BarrierFill before Import, that choice takes priority
    /// over the blob's stored value. A receiver that does not pre-set
    /// BarrierFill picks up the blob value transparently.
    /// </summary>
    [Fact]
    public void RoundtripBarrierFillReceiverPriority()
    {
        var plaintext = "barrier-fill priority"u8.ToArray();

        var src = new Encryptor("blake3", 1024, "kmac256");
        src.SetBarrierFill(4);
        var blob = src.Export();
        var ct = src.EncryptAuth(plaintext);
        src.Dispose();

        // Receiver pre-sets BarrierFill = 8; Import must NOT downgrade
        // it to the blob's 4.
        using (var dst = new Encryptor("blake3", 1024, "kmac256"))
        {
            dst.SetBarrierFill(8);
            dst.Import(blob);
            Assert.Equal(plaintext, dst.DecryptAuth(ct));
        }

        // A receiver that did NOT pre-set BarrierFill picks up the
        // blob's value transparently.
        using var dst2 = new Encryptor("blake3", 1024, "kmac256");
        dst2.Import(blob);
        Assert.Equal(plaintext, dst2.DecryptAuth(ct));
    }

    /// <summary>
    /// <see cref="Encryptor.PeekConfig"/> recovers
    /// (Primitive, KeyBits, Mode, MacName) from a state blob without
    /// requiring construction of a matching encryptor first.
    /// </summary>
    [Fact]
    public void PeekRecoversMetadata()
    {
        foreach (var (primitive, width) in CanonicalHashes)
        {
            foreach (var keyBits in KeyBitsFor(width))
            {
                foreach (var mode in new[] { "single", "triple" })
                {
                    foreach (var mac in new[] { "kmac256", "hmac-sha256", "hmac-blake3" })
                    {
                        byte[] blob;
                        using (var enc = new Encryptor(primitive, keyBits, mac, mode: mode))
                        {
                            blob = enc.Export();
                        }
                        var cfg = Encryptor.PeekConfig(blob);
                        Assert.Equal(primitive, cfg.Primitive);
                        Assert.Equal(keyBits, cfg.KeyBits);
                        Assert.Equal(mode == "single" ? 1 : 3, cfg.Mode);
                        Assert.Equal(mac, cfg.MacName);
                    }
                }
            }
        }
    }

    /// <summary>
    /// PeekConfig on malformed JSON / empty / minimal-non-conforming
    /// blobs surfaces as <see cref="ItbException"/> with status
    /// <c>EasyMalformed</c>.
    /// </summary>
    [Fact]
    public void PeekMalformedBlob()
    {
        var malformed = new[]
        {
            "not json"u8.ToArray(),
            Array.Empty<byte>(),
            "{}"u8.ToArray(),
            "{\"v\":1}"u8.ToArray(),
        };
        foreach (var blob in malformed)
        {
            var ex = Assert.Throws<ItbException>(() => Encryptor.PeekConfig(blob));
            Assert.Equal(Status.EasyMalformed, ex.Status);
        }
    }

    /// <summary>
    /// PeekConfig on a hand-crafted version-too-new blob surfaces as
    /// <see cref="ItbException"/> rather than silently parsing.
    /// </summary>
    [Fact]
    public void PeekTooNewVersion()
    {
        var blob = "{\"v\":99,\"kind\":\"itb-easy\"}"u8.ToArray();
        Assert.Throws<ItbException>(() => Encryptor.PeekConfig(blob));
    }

    /// <summary>
    /// Importing a blob whose <c>primitive</c> field disagrees with the
    /// receiver Encryptor surfaces as
    /// <see cref="ItbEasyMismatchException"/> with <c>.Field == "primitive"</c>.
    /// </summary>
    [Fact]
    public void ImportPrimitiveMismatch()
    {
        byte[] blob;
        using (var src = new Encryptor("blake3", 1024, "kmac256"))
        {
            blob = src.Export();
        }
        using var dst = new Encryptor("blake2s", 1024, "kmac256");
        var ex = Assert.Throws<ItbEasyMismatchException>(() => dst.Import(blob));
        Assert.Equal("primitive", ex.Field);
        Assert.Equal(Status.EasyMismatch, ex.Status);
    }

    /// <summary>
    /// Importing a blob whose <c>key_bits</c> field disagrees with the
    /// receiver Encryptor surfaces with <c>.Field == "key_bits"</c>.
    /// </summary>
    [Fact]
    public void ImportKeyBitsMismatch()
    {
        byte[] blob;
        using (var src = new Encryptor("blake3", 1024, "kmac256"))
        {
            blob = src.Export();
        }
        using var dst = new Encryptor("blake3", 2048, "kmac256");
        var ex = Assert.Throws<ItbEasyMismatchException>(() => dst.Import(blob));
        Assert.Equal("key_bits", ex.Field);
        Assert.Equal(Status.EasyMismatch, ex.Status);
    }

    /// <summary>
    /// Importing a blob whose <c>mode</c> field disagrees with the
    /// receiver Encryptor surfaces with <c>.Field == "mode"</c>.
    /// </summary>
    [Fact]
    public void ImportModeMismatch()
    {
        byte[] blob;
        using (var src = new Encryptor("blake3", 1024, "kmac256"))
        {
            blob = src.Export();
        }
        using var dst = new Encryptor("blake3", 1024, "kmac256", mode: "triple");
        var ex = Assert.Throws<ItbEasyMismatchException>(() => dst.Import(blob));
        Assert.Equal("mode", ex.Field);
        Assert.Equal(Status.EasyMismatch, ex.Status);
    }

    /// <summary>
    /// Importing a blob whose <c>mac</c> field disagrees with the
    /// receiver Encryptor surfaces with <c>.Field == "mac"</c>.
    /// </summary>
    [Fact]
    public void ImportMacMismatch()
    {
        byte[] blob;
        using (var src = new Encryptor("blake3", 1024, "kmac256"))
        {
            blob = src.Export();
        }
        using var dst = new Encryptor("blake3", 1024, "hmac-sha256");
        var ex = Assert.Throws<ItbEasyMismatchException>(() => dst.Import(blob));
        Assert.Equal("mac", ex.Field);
        Assert.Equal(Status.EasyMismatch, ex.Status);
    }

    /// <summary>
    /// Importing malformed JSON surfaces as <see cref="ItbException"/>
    /// with status <c>EasyMalformed</c>.
    /// </summary>
    [Fact]
    public void ImportMalformedJson()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        var ex = Assert.Throws<ItbException>(() =>
            enc.Import("this is not json"u8.ToArray()));
        Assert.Equal(Status.EasyMalformed, ex.Status);
    }

    /// <summary>
    /// Importing a hand-crafted version-too-new blob surfaces as
    /// <see cref="ItbException"/> with status <c>EasyVersionTooNew</c>.
    /// </summary>
    [Fact]
    public void ImportVersionTooNew()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        var blob = Encoding.UTF8.GetBytes("{\"v\":99,\"kind\":\"itb-easy\"}");
        var ex = Assert.Throws<ItbException>(() => enc.Import(blob));
        Assert.Equal(Status.EasyVersionTooNew, ex.Status);
    }

    /// <summary>
    /// Importing a blob whose <c>kind</c> field is not <c>"itb-easy"</c>
    /// surfaces as <see cref="ItbException"/> with status
    /// <c>EasyMalformed</c>.
    /// </summary>
    [Fact]
    public void ImportWrongKind()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        var blob = Encoding.UTF8.GetBytes("{\"v\":1,\"kind\":\"not-itb-easy\"}");
        var ex = Assert.Throws<ItbException>(() => enc.Import(blob));
        Assert.Equal(Status.EasyMalformed, ex.Status);
    }

    /// <summary>
    /// PRF-key length per primitive matches the registry's native
    /// fixed-key size; SipHash-2-4 reports
    /// <see cref="Encryptor.HasPRFKeys"/> = false and
    /// <see cref="Encryptor.PRFKey"/> raises.
    /// </summary>
    [Fact]
    public void PRFKeyLengthsPerPrimitive()
    {
        foreach (var (name, width) in CanonicalHashes)
        {
            foreach (var keyBits in KeyBitsFor(width))
            {
                using var enc = new Encryptor(name, keyBits, "kmac256");
                if (name == "siphash24")
                {
                    Assert.False(enc.HasPRFKeys);
                    Assert.Throws<ItbException>(() => enc.PRFKey(0));
                }
                else
                {
                    Assert.True(enc.HasPRFKeys);
                    for (var slot = 0; slot < enc.SeedCount; slot++)
                    {
                        var key = enc.PRFKey(slot);
                        Assert.Equal(ExpectedPRFKeyLen[name], key.Length);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Seed-component count per slot reflects keyBits / 64 for every
    /// primitive at every supported key width.
    /// </summary>
    [Fact]
    public void SeedComponentsLengthsPerKeyBits()
    {
        foreach (var (name, width) in CanonicalHashes)
        {
            foreach (var keyBits in KeyBitsFor(width))
            {
                using var enc = new Encryptor(name, keyBits, "kmac256");
                for (var slot = 0; slot < enc.SeedCount; slot++)
                {
                    var comps = enc.SeedComponents(slot);
                    Assert.Equal(keyBits, comps.Length * 64);
                }
            }
        }
    }

    /// <summary>
    /// Every shipped MAC primitive returns a non-empty fixed key.
    /// </summary>
    [Fact]
    public void MacKeyPresent()
    {
        foreach (var mac in new[] { "kmac256", "hmac-sha256", "hmac-blake3" })
        {
            using var enc = new Encryptor("blake3", 1024, mac);
            Assert.NotEmpty(enc.MacKey());
        }
    }

    /// <summary>
    /// Out-of-range slot index on
    /// <see cref="Encryptor.SeedComponents"/> surfaces as
    /// <see cref="ItbException"/> with status <c>BadInput</c>.
    /// </summary>
    [Fact]
    public void SeedComponentsOutOfRange()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        Assert.Equal(3, enc.SeedCount);
        var ex1 = Assert.Throws<ItbException>(() => enc.SeedComponents(3));
        Assert.Equal(Status.BadInput, ex1.Status);
        var ex2 = Assert.Throws<ItbException>(() => enc.SeedComponents(-1));
        Assert.Equal(Status.BadInput, ex2.Status);
    }
}
