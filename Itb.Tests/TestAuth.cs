// End-to-end tests for the authenticated-encryption surface.
//
// Mirrors bindings/python/tests/test_auth.py — exercises the
// 3 MACs x 3 hash widths matrix for both Single Ouroboros and Triple
// Ouroboros under <see cref="Cipher.EncryptAuth"/> /
// <see cref="Cipher.DecryptAuth"/> plus the cross-MAC rejection path
// (different primitive or different key produces MacFailure rather
// than corrupting the plaintext).
//
// The class does NOT mutate process-global libitb state, so no
// [Collection(TestCollections.GlobalState)] annotation is required.

namespace Itb.Tests;

public class TestAuth
{
    public static readonly (string name, int keySize, int tagSize, int minKeyBytes)[] CanonicalMacs =
    {
        ("kmac256", 32, 32, 16),
        ("hmac-sha256", 32, 32, 16),
        ("hmac-blake3", 32, 32, 32),
    };

    /// <summary>
    /// One representative hash per ITB key-width axis. Mirrors
    /// <c>HASH_BY_WIDTH</c> from <c>test_auth.py</c>.
    /// </summary>
    public static readonly (string name, int width)[] HashByWidth =
    {
        ("siphash24", 128),
        ("blake3", 256),
        ("blake2b512", 512),
    };

    // ----------------------------------------------------------------
    // MAC introspection + lifecycle.
    // ----------------------------------------------------------------

    [Fact]
    public void TestListMacs()
    {
        var got = Library.ListMacs();
        Assert.Equal(CanonicalMacs.Length, got.Count);
        for (var i = 0; i < CanonicalMacs.Length; i++)
        {
            Assert.Equal(CanonicalMacs[i].name, got[i].Name);
            Assert.Equal(CanonicalMacs[i].keySize, got[i].KeySize);
            Assert.Equal(CanonicalMacs[i].tagSize, got[i].TagSize);
            Assert.Equal(CanonicalMacs[i].minKeyBytes, got[i].MinKeyBytes);
        }
    }

    [Fact]
    public void TestMacCreateAndAccess()
    {
        foreach (var (name, _, _, _) in CanonicalMacs)
        {
            using var mac = new Mac(name, TestRng.Bytes(32));
            Assert.Equal(name, mac.MacName);
        }
    }

    [Fact]
    public void TestMacBadName()
    {
        var ex = Assert.Throws<ItbException>(() =>
            new Mac("nonsense-mac", TestRng.Bytes(32)));
        Assert.Equal(Native.Status.BadMac, ex.Status);
    }

    [Fact]
    public void TestMacShortKey()
    {
        foreach (var (name, _, _, minKey) in CanonicalMacs)
        {
            var ex = Assert.Throws<ItbException>(() =>
                new Mac(name, TestRng.Bytes(minKey - 1)));
            Assert.Equal(Native.Status.BadInput, ex.Status);
        }
    }

    // ----------------------------------------------------------------
    // Single Ouroboros + Auth: 3 MACs x 3 hash widths.
    // ----------------------------------------------------------------

    [Fact]
    public void TestSingleAuthAllMacsAllWidths()
    {
        var plaintext = TestRng.Bytes(4096);
        foreach (var (macName, _, _, _) in CanonicalMacs)
        {
            foreach (var (hashName, _) in HashByWidth)
            {
                using var mac = new Mac(macName, TestRng.Bytes(32));
                using var ns = new Seed(hashName, 1024);
                using var ds = new Seed(hashName, 1024);
                using var ss = new Seed(hashName, 1024);

                var ct = Cipher.EncryptAuth(ns, ds, ss, mac, plaintext);
                var pt = Cipher.DecryptAuth(ns, ds, ss, mac, ct);
                Assert.Equal(plaintext, pt);

                // Tamper: flip 256 bytes after the dynamic header.
                var tampered = (byte[])ct.Clone();
                var h = Library.HeaderSize;
                var end = Math.Min(h + 256, tampered.Length);
                for (var i = h; i < end; i++) tampered[i] ^= 0x01;
                var ex = Assert.Throws<ItbException>(() =>
                    Cipher.DecryptAuth(ns, ds, ss, mac, tampered));
                Assert.Equal(Native.Status.MacFailure, ex.Status);
            }
        }
    }

    // ----------------------------------------------------------------
    // Triple Ouroboros + Auth: 3 MACs x 3 hash widths x 7 seeds.
    // ----------------------------------------------------------------

    [Fact]
    public void TestTripleAuthAllMacsAllWidths()
    {
        var plaintext = TestRng.Bytes(4096);
        foreach (var (macName, _, _, _) in CanonicalMacs)
        {
            foreach (var (hashName, _) in HashByWidth)
            {
                using var mac = new Mac(macName, TestRng.Bytes(32));
                var seeds = new Seed[7];
                try
                {
                    for (var i = 0; i < 7; i++) seeds[i] = new Seed(hashName, 1024);
                    var ct = Cipher.EncryptAuthTriple(seeds[0],
                        seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6],
                        mac, plaintext);
                    var pt = Cipher.DecryptAuthTriple(seeds[0],
                        seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6],
                        mac, ct);
                    Assert.Equal(plaintext, pt);

                    var tampered = (byte[])ct.Clone();
                    var h = Library.HeaderSize;
                    var end = Math.Min(h + 256, tampered.Length);
                    for (var i = h; i < end; i++) tampered[i] ^= 0x01;
                    var ex = Assert.Throws<ItbException>(() =>
                        Cipher.DecryptAuthTriple(seeds[0],
                            seeds[1], seeds[2], seeds[3],
                            seeds[4], seeds[5], seeds[6],
                            mac, tampered));
                    Assert.Equal(Native.Status.MacFailure, ex.Status);
                }
                finally
                {
                    foreach (var s in seeds) s?.Dispose();
                }
            }
        }
    }

    // ----------------------------------------------------------------
    // Cross-MAC rejection — different primitive / different key both
    // surface as MacFailure rather than corrupting the plaintext.
    // ----------------------------------------------------------------

    [Fact]
    public void TestCrossMacDifferentPrimitive()
    {
        var seeds = new Seed[3];
        try
        {
            for (var i = 0; i < 3; i++) seeds[i] = new Seed("blake3", 1024);
            using var encMac = new Mac("kmac256", TestRng.Bytes(32));
            using var decMac = new Mac("hmac-sha256", TestRng.Bytes(32));
            var pt = new byte[]
            {
                0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64,
            };
            var ct = Cipher.EncryptAuth(seeds[0], seeds[1], seeds[2], encMac, pt);
            var ex = Assert.Throws<ItbException>(() =>
                Cipher.DecryptAuth(seeds[0], seeds[1], seeds[2], decMac, ct));
            Assert.Equal(Native.Status.MacFailure, ex.Status);
        }
        finally
        {
            foreach (var s in seeds) s?.Dispose();
        }
    }

    [Fact]
    public void TestCrossMacSamePrimitiveDifferentKey()
    {
        var seeds = new Seed[3];
        try
        {
            for (var i = 0; i < 3; i++) seeds[i] = new Seed("blake3", 1024);
            using var encMac = new Mac("hmac-sha256", TestRng.Bytes(32));
            using var decMac = new Mac("hmac-sha256", TestRng.Bytes(32));
            var pt = new byte[]
            {
                0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64,
            };
            var ct = Cipher.EncryptAuth(seeds[0], seeds[1], seeds[2], encMac, pt);
            var ex = Assert.Throws<ItbException>(() =>
                Cipher.DecryptAuth(seeds[0], seeds[1], seeds[2], decMac, ct));
            Assert.Equal(Native.Status.MacFailure, ex.Status);
        }
        finally
        {
            foreach (var s in seeds) s?.Dispose();
        }
    }
}
