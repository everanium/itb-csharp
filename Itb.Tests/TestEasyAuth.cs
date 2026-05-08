// End-to-end Encryptor tests for Authenticated Encryption.
//
// Symmetric counterpart to bindings/python/tests/easy/test_auth.py. Same
// matrix (3 MACs x 3 hash widths x {Single, Triple Ouroboros} round trip
// plus tamper rejection) applied to the high-level Encryptor surface.
//
// The cross-MAC rejection cases (different MAC primitive on encrypt vs
// decrypt) are realised here by Export-ing the sender's state and Import-ing
// it into a receiver constructed with the wrong MAC primitive. Import
// enforces matching primitive / keyBits / mode / mac and refuses the swap
// with ItbEasyMismatchException carrying Field == "mac". The same security
// guarantee is covered by tampering the MAC bytes inside the ciphertext
// (header-adjacent flip), which is the Encryptor-level analogue.

using Itb.Native;

namespace Itb.Tests;

[Collection(TestCollections.MismatchField)]
public sealed class TestEasyAuth
{
    /// <summary>Three canonical MACs shipped through libitb's MAC
    /// registry. The MAC name is the only field consumed by the tests
    /// in this file.</summary>
    private static readonly string[] CanonicalMacs =
    {
        "kmac256",
        "hmac-sha256",
        "hmac-blake3",
    };

    /// <summary>Three hash primitives spanning the canonical 128 / 256 /
    /// 512-bit width spectrum.</summary>
    private static readonly (string Name, int Width)[] HashByWidth =
    {
        ("siphash24", 128),
        ("blake3", 256),
        ("blake2b512", 512),
    };

    /// <summary>
    /// Single Ouroboros + Auth: 3 MACs x 3 hash widths. Round-trip and
    /// tamper rejection at the dynamic header offset.
    /// </summary>
    [Fact]
    public void SingleAllMacsAllWidths()
    {
        var plaintext = TestRng.Bytes(4096);
        foreach (var macName in CanonicalMacs)
        {
            foreach (var (hashName, _) in HashByWidth)
            {
                using var enc = new Encryptor(hashName, 1024, macName);
                var ct = enc.EncryptAuth(plaintext);
                var pt = enc.DecryptAuth(ct);
                Assert.Equal(plaintext, pt);

                // Tamper: flip 256 bytes past the dynamic header.
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
    /// Triple Ouroboros + Auth: 3 MACs x 3 hash widths. Round-trip and
    /// tamper rejection at the dynamic header offset.
    /// </summary>
    [Fact]
    public void TripleAllMacsAllWidths()
    {
        var plaintext = TestRng.Bytes(4096);
        foreach (var macName in CanonicalMacs)
        {
            foreach (var (hashName, _) in HashByWidth)
            {
                using var enc = new Encryptor(hashName, 1024, macName, mode: "triple");
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
    /// Cross-MAC rejection at the structural level: an exported state
    /// blob carries the encryptor's MAC primitive name; Import on a
    /// receiver constructed with a different MAC primitive surfaces
    /// <see cref="ItbEasyMismatchException"/> with Field == "mac"
    /// rather than a runtime MAC verification miss.
    /// </summary>
    [Fact]
    public void CrossMacRejectionAtImport()
    {
        byte[] blob;
        using (var src = new Encryptor("blake3", 1024, "kmac256"))
        {
            blob = src.Export();
        }

        // Receiver with hmac-sha256 — Import must reject on Field == "mac".
        using var dst = new Encryptor("blake3", 1024, "hmac-sha256");
        var ex = Assert.Throws<ItbEasyMismatchException>(() => dst.Import(blob));
        Assert.Equal("mac", ex.Field);
        Assert.Equal(Status.EasyMismatch, ex.Status);
    }

    /// <summary>
    /// Same-primitive different-key MAC failure at the runtime level.
    /// Encrypt with one encryptor, attempt decrypt with a separately
    /// constructed encryptor (same primitive / keyBits / mode / mac
    /// but with its own random MAC key) — surfaces
    /// <see cref="ItbException"/> with status <c>MacFailure</c>.
    /// </summary>
    [Fact]
    public void SamePrimitiveDifferentKeyMacFailure()
    {
        var plaintext = "authenticated payload"u8.ToArray();
        using var enc1 = new Encryptor("blake3", 1024, "hmac-sha256");
        using var enc2 = new Encryptor("blake3", 1024, "hmac-sha256");

        // Day 1: encrypt with enc1's seeds and MAC key.
        var ct = enc1.EncryptAuth(plaintext);

        // Day 2: enc2 has its own (different) seed / MAC keys.
        // Decrypt the ct under enc2 — same primitive matrix but
        // different keying material — MAC verification failure.
        var ex = Assert.Throws<ItbException>(() => enc2.DecryptAuth(ct));
        Assert.Equal(Status.MacFailure, ex.Status);
    }

    /// <summary>
    /// Default-MAC override: the constructor without an explicit
    /// <c>mac</c> argument routes through the binding-level default
    /// "hmac-blake3" rather than libitb's own default. Confirms the
    /// default-path round-trip carries authenticated bytes.
    /// </summary>
    [Fact]
    public void DefaultMacRoundtripUsesHmacBlake3()
    {
        var plaintext = TestRng.Bytes(512);
        using var enc = new Encryptor("blake3", 1024);
        Assert.Equal("hmac-blake3", enc.MacName);
        var ct = enc.EncryptAuth(plaintext);
        var pt = enc.DecryptAuth(ct);
        Assert.Equal(plaintext, pt);
    }
}
