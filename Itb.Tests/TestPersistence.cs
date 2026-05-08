// Cross-process persistence round-trip tests for the C# binding.
//
// Mirrors bindings/python/tests/test_persistence.py. The shipped C#
// API exposes Seed.GetComponents() / Seed.GetHashKey() and
// Seed.FromComponents() — the persistence surface required for any
// deployment where encrypt and decrypt run in different processes
// (network, storage, backup, microservices). Without both
// <c>components</c> and <c>hashKey</c> captured at encrypt-side and
// re-supplied at decrypt-side, the seed state cannot be reconstructed
// and the ciphertext is unreadable.
//
// The class does NOT mutate process-global libitb state, so no
// [Collection(TestCollections.GlobalState)] annotation is required.

using System.Linq;

namespace Itb.Tests;

public class TestPersistence
{
    public static readonly (string name, int width)[] CanonicalHashes =
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

    public static readonly Dictionary<string, int> ExpectedHashKeyLen = new()
    {
        ["areion256"] = 32,
        ["areion512"] = 64,
        ["siphash24"] = 0, // no internal fixed key — keyed by seed components
        ["aescmac"] = 16,
        ["blake2b256"] = 32,
        ["blake2b512"] = 64,
        ["blake2s"] = 32,
        ["blake3"] = 32,
        ["chacha20"] = 32,
    };

    /// <summary>
    /// Iterates over the three ITB key-bit widths that are valid for
    /// a given native hash width — multiples of width in [512, 2048].
    /// </summary>
    private static IEnumerable<int> KeyBitsFor(int width)
    {
        foreach (var k in new[] { 512, 1024, 2048 })
        {
            if (k % width == 0) yield return k;
        }
    }

    [Fact]
    public void TestRoundtripAllHashes()
    {
        var prefix = new byte[]
        {
            0x61, 0x6e, 0x79, 0x20, 0x62, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x20,
            0x64, 0x61, 0x74, 0x61, 0x2c, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75,
            0x64, 0x69, 0x6e, 0x67, 0x20, 0x30, 0x78, 0x30, 0x30, 0x20, 0x62,
            0x79, 0x74, 0x65, 0x73, 0x20, 0x2d, 0x2d, 0x20,
        };
        var allBytes = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        var plaintext = prefix.Concat(allBytes).ToArray();

        foreach (var (name, width) in CanonicalHashes)
        {
            foreach (var keyBits in KeyBitsFor(width))
            {
                // Day 1 — random seeds.
                ulong[] nsComps, dsComps, ssComps;
                byte[] nsKey, dsKey, ssKey;
                byte[] ciphertext;
                using (var ns = new Seed(name, keyBits))
                using (var ds = new Seed(name, keyBits))
                using (var ss = new Seed(name, keyBits))
                {
                    nsComps = ns.GetComponents();
                    dsComps = ds.GetComponents();
                    ssComps = ss.GetComponents();
                    nsKey = ns.GetHashKey();
                    dsKey = ds.GetHashKey();
                    ssKey = ss.GetHashKey();

                    Assert.Equal(keyBits, nsComps.Length * 64);
                    Assert.Equal(ExpectedHashKeyLen[name], nsKey.Length);

                    ciphertext = Cipher.Encrypt(ns, ds, ss, plaintext);
                }

                // Day 2 — restore from saved material.
                using var ns2 = Seed.FromComponents(name, nsComps, nsKey);
                using var ds2 = Seed.FromComponents(name, dsComps, dsKey);
                using var ss2 = Seed.FromComponents(name, ssComps, ssKey);
                var decrypted = Cipher.Decrypt(ns2, ds2, ss2, ciphertext);
                Assert.Equal(plaintext, decrypted);

                // Restored seeds report the same key + components.
                Assert.Equal(nsComps, ns2.GetComponents());
                Assert.Equal(nsKey, ns2.GetHashKey());
            }
        }
    }

    [Fact]
    public void TestRandomKeyPath()
    {
        // Pass an empty hash key — Seed.FromComponents must generate
        // a fresh random key (and report a non-empty hash key for every
        // primitive except SipHash-2-4).
        var components = new ulong[8]; // 512-bit zero key — sufficient for non-SipHash
        foreach (var (name, _) in CanonicalHashes)
        {
            using var seed = Seed.FromComponents(name, components, Array.Empty<byte>());
            var key = seed.GetHashKey();
            if (name == "siphash24")
            {
                Assert.Empty(key);
            }
            else
            {
                Assert.Equal(ExpectedHashKeyLen[name], key.Length);
            }
        }
    }

    [Fact]
    public void TestExplicitKeyPreserved()
    {
        // The hash key bytes returned by FromComponents() match the
        // supplied key bit-exact. Use blake3 — symmetric 32-byte key,
        // easy to assert.
        var explicitKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var components = new ulong[8];
        for (var i = 0; i < 8; i++) components[i] = 0xCAFEBABEDEADBEEF;
        using var seed = Seed.FromComponents("blake3", components, explicitKey);
        Assert.Equal(explicitKey, seed.GetHashKey());
    }

    [Fact]
    public void TestBadKeySize()
    {
        // Wrong-size hash key for a primitive that expects fixed-key
        // bytes returns a clean ItbException (no panic across the FFI).
        var components = new ulong[16]; // 1024-bit
        Assert.Throws<ItbException>(() =>
            Seed.FromComponents("blake3", components, new byte[7]));
    }

    [Fact]
    public void TestSiphashRejectsHashKey()
    {
        // SipHash-2-4 takes no internal fixed key; passing one must
        // be rejected (not silently ignored).
        var components = new ulong[8];
        Assert.Throws<ItbException>(() =>
            Seed.FromComponents("siphash24", components, new byte[16]));
    }

    [Fact]
    public void TestEncryptorBlobSanityRoundtrip()
    {
        // Mirrors the Python persistence test's "use the wrapper APIs
        // not the raw FFI" intent — round-trip a random plaintext via
        // Blob256 export / import as the cross-process persistence
        // mechanism. Sender exports, receiver imports + rebuilds seeds
        // + decrypts; equivalence must hold.
        var plaintext = TestRng.Bytes(256);
        using var ns = new Seed("blake3", 1024);
        using var ds = new Seed("blake3", 1024);
        using var ss = new Seed("blake3", 1024);
        var ct = Cipher.Encrypt(ns, ds, ss, plaintext);

        byte[] blob;
        using (var src = new Blob256())
        {
            src.SetKey(BlobSlot.N, ns.GetHashKey());
            src.SetKey(BlobSlot.D, ds.GetHashKey());
            src.SetKey(BlobSlot.S, ss.GetHashKey());
            src.SetComponents(BlobSlot.N, ns.GetComponents());
            src.SetComponents(BlobSlot.D, ds.GetComponents());
            src.SetComponents(BlobSlot.S, ss.GetComponents());
            blob = src.Export();
        }

        using var dst = new Blob256();
        dst.Import(blob);
        using var ns2 = Seed.FromComponents("blake3",
            dst.GetComponents(BlobSlot.N), dst.GetKey(BlobSlot.N));
        using var ds2 = Seed.FromComponents("blake3",
            dst.GetComponents(BlobSlot.D), dst.GetKey(BlobSlot.D));
        using var ss2 = Seed.FromComponents("blake3",
            dst.GetComponents(BlobSlot.S), dst.GetKey(BlobSlot.S));
        Assert.Equal(plaintext, Cipher.Decrypt(ns2, ds2, ss2, ct));
    }
}
