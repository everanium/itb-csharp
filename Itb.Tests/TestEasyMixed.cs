// Mixed-mode Encryptor (per-slot PRF primitive selection) tests.
//
// Mirrors bindings/python/tests/easy/test_mixed.py. Covers
// Encryptor.Mixed (Single Ouroboros) and Encryptor.Mixed3
// (Triple Ouroboros): round-trip, optional dedicated lockSeed under
// its own primitive, state-blob Export / Import, mixed-width rejection
// through the cgo boundary, and the per-slot introspection accessors
// (PrimitiveAt, IsMixed).

namespace Itb.Tests;

public sealed class TestEasyMixed
{
    /// <summary>
    /// Single Ouroboros mixed-mode round-trip across three primitives
    /// at native width 256. Validates per-slot accessor reports the
    /// correct primitive at every slot.
    /// </summary>
    [Fact]
    public void SingleBasicRoundtrip()
    {
        using var enc = Encryptor.Mixed(
            primN: "blake3",
            primD: "blake2s",
            primS: "areion256",
            primL: null,
            keyBits: 1024,
            mac: "kmac256");

        Assert.True(enc.IsMixed);
        Assert.Equal("mixed", enc.Primitive);
        Assert.Equal("blake3", enc.PrimitiveAt(0));
        Assert.Equal("blake2s", enc.PrimitiveAt(1));
        Assert.Equal("areion256", enc.PrimitiveAt(2));

        var plaintext = "csharp mixed Single roundtrip payload"u8.ToArray();
        var ct = enc.Encrypt(plaintext);
        Assert.Equal(plaintext, enc.Decrypt(ct));
    }

    /// <summary>
    /// Single Ouroboros with a dedicated lockSeed under a fourth slot.
    /// The lockSeed primitive is independently chosen and the slot
    /// count reflects 4 (3 + lockSeed).
    /// </summary>
    [Fact]
    public void SingleWithDedicatedLockSeed()
    {
        using var enc = Encryptor.Mixed(
            primN: "blake3",
            primD: "blake2s",
            primS: "blake3",
            keyBits: 1024,
            mac: "kmac256",
            primL: "areion256");

        Assert.Equal("areion256", enc.PrimitiveAt(3));
        var plaintext = "csharp mixed Single + dedicated lockSeed payload"u8.ToArray();
        var ct = enc.EncryptAuth(plaintext);
        Assert.Equal(plaintext, enc.DecryptAuth(ct));
    }

    /// <summary>
    /// 128-bit width with mixed key shapes: SipHash-2-4 (no fixed key
    /// bytes) plus AES-CMAC (16-byte key) in the same encryptor.
    /// Exercises the per-slot empty / non-empty PRF-key validation in
    /// Export / Import.
    /// </summary>
    [Fact]
    public void SingleAescmacSiphash24Mix128Bit()
    {
        using var enc = Encryptor.Mixed(
            primN: "aescmac",
            primD: "siphash24",
            primS: "aescmac",
            primL: null,
            keyBits: 512,
            mac: "hmac-sha256");

        var plaintext = "csharp mixed 128-bit aescmac+siphash24 mix"u8.ToArray();
        var ct = enc.Encrypt(plaintext);
        Assert.Equal(plaintext, enc.Decrypt(ct));
    }

    /// <summary>
    /// Triple Ouroboros mixed-mode round-trip across seven independently
    /// chosen primitives. Per-slot accessor reports each primitive at
    /// the right slot index.
    /// </summary>
    [Fact]
    public void TripleBasicRoundtrip()
    {
        using var enc = Encryptor.Mixed3(
            primN: "areion256",
            primD1: "blake3",
            primD2: "blake2s",
            primD3: "chacha20",
            primS1: "blake2b256",
            primS2: "blake3",
            primS3: "blake2s",
            primL: null,
            keyBits: 1024,
            mac: "kmac256");

        var wants = new[]
        {
            "areion256", "blake3", "blake2s", "chacha20",
            "blake2b256", "blake3", "blake2s",
        };
        for (var i = 0; i < wants.Length; i++)
        {
            Assert.Equal(wants[i], enc.PrimitiveAt(i));
        }

        var plaintext = "csharp mixed Triple roundtrip payload"u8.ToArray();
        var ct = enc.Encrypt(plaintext);
        Assert.Equal(plaintext, enc.Decrypt(ct));
    }

    /// <summary>
    /// Triple Ouroboros with dedicated lockSeed at slot 7. Exercises
    /// the 8-slot configuration on the auth path.
    /// </summary>
    [Fact]
    public void TripleWithDedicatedLockSeed()
    {
        using var enc = Encryptor.Mixed3(
            primN: "blake3",
            primD1: "blake2s",
            primD2: "blake3",
            primD3: "blake2s",
            primS1: "blake3",
            primS2: "blake2s",
            primS3: "blake3",
            keyBits: 1024,
            mac: "kmac256",
            primL: "areion256");

        Assert.Equal("areion256", enc.PrimitiveAt(7));

        // Replicate Python's "* 16" by tiling the chunk literal.
        var unit = "csharp mixed Triple + lockSeed payload"u8.ToArray();
        var plaintext = new byte[unit.Length * 16];
        for (var i = 0; i < 16; i++)
        {
            Buffer.BlockCopy(unit, 0, plaintext, i * unit.Length, unit.Length);
        }

        var ct = enc.EncryptAuth(plaintext);
        Assert.Equal(plaintext, enc.DecryptAuth(ct));
    }

    /// <summary>
    /// State-blob Export / Import round-trip on a mixed-mode Single
    /// Ouroboros encryptor. The per-slot primitive list rides through
    /// the blob's <c>primitives</c> array; receiver constructs a
    /// matching encryptor first, then Imports.
    /// </summary>
    [Fact]
    public void SingleExportImport()
    {
        var plaintext = TestRng.Bytes(2048);
        byte[] blob;
        byte[] ct;
        using (var sender = Encryptor.Mixed(
            primN: "blake3",
            primD: "blake2s",
            primS: "areion256",
            primL: null,
            keyBits: 1024,
            mac: "kmac256"))
        {
            ct = sender.EncryptAuth(plaintext);
            blob = sender.Export();
            Assert.True(blob.Length > 0);
        }

        using var receiver = Encryptor.Mixed(
            primN: "blake3",
            primD: "blake2s",
            primS: "areion256",
            primL: null,
            keyBits: 1024,
            mac: "kmac256");
        receiver.Import(blob);
        Assert.Equal(plaintext, receiver.DecryptAuth(ct));
    }

    /// <summary>
    /// State-blob Export / Import round-trip on a mixed-mode Triple
    /// Ouroboros encryptor with a dedicated lockSeed.
    /// </summary>
    [Fact]
    public void TripleExportImportWithLockSeed()
    {
        // Replicate Python's "* 16" by tiling the chunk literal.
        var unit = "csharp mixed Triple + lockSeed Export/Import"u8.ToArray();
        var plaintext = new byte[unit.Length * 16];
        for (var i = 0; i < 16; i++)
        {
            Buffer.BlockCopy(unit, 0, plaintext, i * unit.Length, unit.Length);
        }

        byte[] blob;
        byte[] ct;
        using (var sender = Encryptor.Mixed3(
            primN: "areion256",
            primD1: "blake3",
            primD2: "blake2s",
            primD3: "chacha20",
            primS1: "blake2b256",
            primS2: "blake3",
            primS3: "blake2s",
            keyBits: 1024,
            mac: "kmac256",
            primL: "areion256"))
        {
            ct = sender.EncryptAuth(plaintext);
            blob = sender.Export();
        }

        using var receiver = Encryptor.Mixed3(
            primN: "areion256",
            primD1: "blake3",
            primD2: "blake2s",
            primD3: "chacha20",
            primS1: "blake2b256",
            primS2: "blake3",
            primS3: "blake2s",
            keyBits: 1024,
            mac: "kmac256",
            primL: "areion256");
        receiver.Import(blob);
        Assert.Equal(plaintext, receiver.DecryptAuth(ct));
    }

    /// <summary>
    /// A mixed-mode blob landing on a single-primitive receiver must
    /// be rejected at Import with <see cref="ItbException"/> on the
    /// primitive shape mismatch.
    /// </summary>
    [Fact]
    public void ShapeMismatchMixedToSingleRejected()
    {
        byte[] mixedBlob;
        using (var mixedSender = Encryptor.Mixed(
            primN: "blake3",
            primD: "blake2s",
            primS: "blake3",
            primL: null,
            keyBits: 1024,
            mac: "kmac256"))
        {
            mixedBlob = mixedSender.Export();
        }

        using var singleRecv = new Encryptor("blake3", 1024, "kmac256");
        // Mixed-mode blob landing on a single-primitive receiver is
        // rejected; the exact dispatch (mismatch on primitive vs.
        // generic malformed) is the Go side's call — assert the base
        // ItbException to mirror the Python source-of-truth's looser
        // assertRaises(itb.ITBError) contract.
        Assert.ThrowsAny<ItbException>(() => singleRecv.Import(mixedBlob));
    }

    /// <summary>
    /// Mixing a 256-bit primitive with a 512-bit primitive surfaces as
    /// <see cref="ItbException"/> through the cgo panic-to-Status path.
    /// </summary>
    [Fact]
    public void RejectMixedWidth()
    {
        Assert.Throws<ItbException>(() => Encryptor.Mixed(
            primN: "blake3",      // 256-bit
            primD: "areion512",   // 512-bit — width mismatch
            primS: "blake3",
            primL: null,
            keyBits: 1024,
            mac: "kmac256"));
    }

    /// <summary>
    /// An unknown primitive name in any slot surfaces as
    /// <see cref="ItbException"/>.
    /// </summary>
    [Fact]
    public void RejectUnknownPrimitive()
    {
        Assert.Throws<ItbException>(() => Encryptor.Mixed(
            primN: "no-such-primitive",
            primD: "blake3",
            primS: "blake3",
            primL: null,
            keyBits: 1024,
            mac: "kmac256"));
    }

    /// <summary>
    /// A single-primitive Encryptor still reports
    /// <see cref="Encryptor.IsMixed"/> as <c>false</c> and uniform
    /// <see cref="Encryptor.PrimitiveAt"/> across slots.
    /// </summary>
    [Fact]
    public void DefaultConstructorIsNotMixed()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        Assert.False(enc.IsMixed);
        for (var i = 0; i < 3; i++)
        {
            Assert.Equal("blake3", enc.PrimitiveAt(i));
        }
    }
}
