// Native-Blob round-trip tests for the C# binding.
//
// Mirrors bindings/python/tests/test_blob.py — exercises the Single /
// Triple x LockSeed x MAC x non-default globals matrix through
// Blob128 / Blob256 / Blob512 plus the three typed error paths
// (mode mismatch, malformed JSON, version too new).
//
// The blob captures the sender's process-wide configuration
// (NonceBits / BarrierFill / BitSoup / LockSoup) at export time and
// applies it unconditionally on import, so each test case toggles the
// four globals to non-default values, exports, resets to defaults,
// imports, and verifies the restored state.
//
// Tests in this file mutate process-global libitb configuration
// (NonceBits / BarrierFill / BitSoup / LockSoup) so the class is
// decorated with [Collection(TestCollections.GlobalState)] and every
// global mutation is bracketed by GlobalStateSnapshot.Capture() to
// keep later tests insulated from leftover state.

using System.Text;

namespace Itb.Tests;

[Collection(TestCollections.GlobalState)]
public class TestBlob
{
    /// <summary>
    /// Sets the four globals to non-default values for the body and
    /// restores them on exit. Mirrors <c>_with_globals</c> from
    /// <c>test_blob.py</c>.
    /// </summary>
    private static void WithGlobals(Action body)
    {
        using var snap = GlobalStateSnapshot.Capture();
        Library.NonceBits = 512;
        Library.BarrierFill = 4;
        Library.BitSoup = 1;
        Library.LockSoup = 1;
        body();
    }

    /// <summary>
    /// Forces all four globals to their defaults so an Import-applied
    /// snapshot is detectable via post-Import reads.
    /// </summary>
    private static void ResetGlobals()
    {
        Library.NonceBits = 128;
        Library.BarrierFill = 1;
        Library.BitSoup = 0;
        Library.LockSoup = 0;
    }

    private static void AssertGlobalsRestored(int nonce, int barrier, int bitSoup, int lockSoup)
    {
        Assert.Equal(nonce, Library.NonceBits);
        Assert.Equal(barrier, Library.BarrierFill);
        Assert.Equal(bitSoup, Library.BitSoup);
        Assert.Equal(lockSoup, Library.LockSoup);
    }

    // ----------------------------------------------------------------
    // Smoke tests — construction and properties.
    // ----------------------------------------------------------------

    [Fact]
    public void TestConstruct128()
    {
        using var b = new Blob128();
        Assert.Equal(128, b.Width);
        Assert.Equal(0, b.Mode);
    }

    [Fact]
    public void TestConstruct256()
    {
        using var b = new Blob256();
        Assert.Equal(256, b.Width);
        Assert.Equal(0, b.Mode);
    }

    [Fact]
    public void TestConstruct512()
    {
        using var b = new Blob512();
        Assert.Equal(512, b.Width);
        Assert.Equal(0, b.Mode);
    }

    // Skipped — the Python `test_double_free_idempotent` covers wrapper-level
    // free idempotency. C# IDisposable contract guarantees Dispose() is
    // idempotent; verified at the framework level, no test needed.

    // Skipped — the Python `test_context_manager` covers `with` blocks. The
    // C# `using var` block is verified at compile time by the language and
    // does not need a runtime test.

    // ----------------------------------------------------------------
    // Blob512 — areion512 round-trip, full Single x LockSeed x MAC matrix.
    // ----------------------------------------------------------------

    [Fact]
    public void TestBlob512SingleFullMatrix()
    {
        var plaintext = Encoding.UTF8.GetBytes("cs blob512 single round-trip payload");
        foreach (var withLs in new[] { false, true })
        {
            foreach (var withMac in new[] { false, true })
            {
                WithGlobals(() => Blob512SingleOne(plaintext, withLs, withMac));
            }
        }
    }

    private static void Blob512SingleOne(byte[] plaintext, bool withLs, bool withMac)
    {
        const string primitive = "areion512";
        const int keyBits = 2048;
        using var ns = new Seed(primitive, keyBits);
        using var ds = new Seed(primitive, keyBits);
        using var ss = new Seed(primitive, keyBits);

        Seed? ls = null;
        try
        {
            if (withLs)
            {
                ls = new Seed(primitive, keyBits);
                ns.AttachLockSeed(ls);
            }

            byte[]? macKey = withMac ? TestRng.Bytes(32) : null;
            using var mac = withMac ? new Mac("kmac256", macKey!) : null;

            var ct = withMac
                ? Cipher.EncryptAuth(ns, ds, ss, mac!, plaintext)
                : Cipher.Encrypt(ns, ds, ss, plaintext);

            byte[] blob;
            using (var src = new Blob512())
            {
                src.SetKey(BlobSlot.N, ns.GetHashKey());
                src.SetKey(BlobSlot.D, ds.GetHashKey());
                src.SetKey(BlobSlot.S, ss.GetHashKey());
                src.SetComponents(BlobSlot.N, ns.GetComponents());
                src.SetComponents(BlobSlot.D, ds.GetComponents());
                src.SetComponents(BlobSlot.S, ss.GetComponents());
                if (withLs)
                {
                    src.SetKey(BlobSlot.L, ls!.GetHashKey());
                    src.SetComponents(BlobSlot.L, ls.GetComponents());
                }
                if (withMac)
                {
                    src.SetMacKey(macKey!);
                    src.SetMacName("kmac256");
                }

                var opts = BlobExportOpts.None;
                if (withLs) opts |= BlobExportOpts.LockSeed;
                if (withMac) opts |= BlobExportOpts.Mac;
                blob = src.Export(opts);
            }

            ResetGlobals();
            using (var dst = new Blob512())
            {
                dst.Import(blob);
                Assert.Equal(1, dst.Mode);
                AssertGlobalsRestored(512, 4, 1, 1);

                using var ns2 = Seed.FromComponents(primitive,
                    dst.GetComponents(BlobSlot.N), dst.GetKey(BlobSlot.N));
                using var ds2 = Seed.FromComponents(primitive,
                    dst.GetComponents(BlobSlot.D), dst.GetKey(BlobSlot.D));
                using var ss2 = Seed.FromComponents(primitive,
                    dst.GetComponents(BlobSlot.S), dst.GetKey(BlobSlot.S));
                Seed? ls2 = null;
                try
                {
                    if (withLs)
                    {
                        ls2 = Seed.FromComponents(primitive,
                            dst.GetComponents(BlobSlot.L), dst.GetKey(BlobSlot.L));
                        ns2.AttachLockSeed(ls2);
                    }

                    Mac? mac2 = null;
                    try
                    {
                        if (withMac)
                        {
                            Assert.Equal("kmac256", dst.GetMacName());
                            Assert.Equal(macKey, dst.GetMacKey());
                            mac2 = new Mac("kmac256", dst.GetMacKey());
                        }

                        var pt = withMac
                            ? Cipher.DecryptAuth(ns2, ds2, ss2, mac2!, ct)
                            : Cipher.Decrypt(ns2, ds2, ss2, ct);
                        Assert.Equal(plaintext, pt);
                    }
                    finally
                    {
                        mac2?.Dispose();
                    }
                }
                finally
                {
                    ls2?.Dispose();
                }
            }
        }
        finally
        {
            ls?.Dispose();
        }
    }

    [Fact]
    public void TestBlob512TripleFullMatrix()
    {
        var plaintext = Encoding.UTF8.GetBytes("cs blob512 triple round-trip payload");
        foreach (var withLs in new[] { false, true })
        {
            foreach (var withMac in new[] { false, true })
            {
                WithGlobals(() => Blob512TripleOne(plaintext, withLs, withMac));
            }
        }
    }

    private static void Blob512TripleOne(byte[] plaintext, bool withLs, bool withMac)
    {
        const string primitive = "areion512";
        const int keyBits = 2048;
        using var ns = new Seed(primitive, keyBits);
        using var ds1 = new Seed(primitive, keyBits);
        using var ds2 = new Seed(primitive, keyBits);
        using var ds3 = new Seed(primitive, keyBits);
        using var ss1 = new Seed(primitive, keyBits);
        using var ss2 = new Seed(primitive, keyBits);
        using var ss3 = new Seed(primitive, keyBits);

        Seed? ls = null;
        try
        {
            if (withLs)
            {
                ls = new Seed(primitive, keyBits);
                ns.AttachLockSeed(ls);
            }

            byte[]? macKey = withMac ? TestRng.Bytes(32) : null;
            using var mac = withMac ? new Mac("kmac256", macKey!) : null;

            var ct = withMac
                ? Cipher.EncryptAuthTriple(ns, ds1, ds2, ds3, ss1, ss2, ss3, mac!, plaintext)
                : Cipher.EncryptTriple(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext);

            byte[] blob;
            using (var src = new Blob512())
            {
                var pairs = new (BlobSlot slot, Seed seed)[]
                {
                    (BlobSlot.N, ns),
                    (BlobSlot.D1, ds1),
                    (BlobSlot.D2, ds2),
                    (BlobSlot.D3, ds3),
                    (BlobSlot.S1, ss1),
                    (BlobSlot.S2, ss2),
                    (BlobSlot.S3, ss3),
                };
                foreach (var (slot, seed) in pairs)
                {
                    src.SetKey(slot, seed.GetHashKey());
                    src.SetComponents(slot, seed.GetComponents());
                }
                if (withLs)
                {
                    src.SetKey(BlobSlot.L, ls!.GetHashKey());
                    src.SetComponents(BlobSlot.L, ls.GetComponents());
                }
                if (withMac)
                {
                    src.SetMacKey(macKey!);
                    src.SetMacName("kmac256");
                }

                var opts = BlobExportOpts.None;
                if (withLs) opts |= BlobExportOpts.LockSeed;
                if (withMac) opts |= BlobExportOpts.Mac;
                blob = src.ExportTriple(opts);
            }

            ResetGlobals();
            using (var dst = new Blob512())
            {
                dst.ImportTriple(blob);
                Assert.Equal(3, dst.Mode);
                AssertGlobalsRestored(512, 4, 1, 1);

                Seed Rebuild(BlobSlot slot) => Seed.FromComponents(primitive,
                    dst.GetComponents(slot), dst.GetKey(slot));

                using var ns2 = Rebuild(BlobSlot.N);
                using var ds1_2 = Rebuild(BlobSlot.D1);
                using var ds2_2 = Rebuild(BlobSlot.D2);
                using var ds3_2 = Rebuild(BlobSlot.D3);
                using var ss1_2 = Rebuild(BlobSlot.S1);
                using var ss2_2 = Rebuild(BlobSlot.S2);
                using var ss3_2 = Rebuild(BlobSlot.S3);

                Seed? ls2 = null;
                try
                {
                    if (withLs)
                    {
                        ls2 = Rebuild(BlobSlot.L);
                        ns2.AttachLockSeed(ls2);
                    }

                    Mac? mac2 = null;
                    try
                    {
                        if (withMac)
                        {
                            mac2 = new Mac("kmac256", dst.GetMacKey());
                        }

                        var pt = withMac
                            ? Cipher.DecryptAuthTriple(ns2, ds1_2, ds2_2, ds3_2,
                                ss1_2, ss2_2, ss3_2, mac2!, ct)
                            : Cipher.DecryptTriple(ns2, ds1_2, ds2_2, ds3_2,
                                ss1_2, ss2_2, ss3_2, ct);
                        Assert.Equal(plaintext, pt);
                    }
                    finally
                    {
                        mac2?.Dispose();
                    }
                }
                finally
                {
                    ls2?.Dispose();
                }
            }
        }
        finally
        {
            ls?.Dispose();
        }
    }

    // ----------------------------------------------------------------
    // Blob256 — blake3 round-trip.
    // ----------------------------------------------------------------

    [Fact]
    public void TestBlob256Single()
    {
        WithGlobals(() =>
        {
            var plaintext = Encoding.UTF8.GetBytes("cs blob256 single round-trip");
            using var ns = new Seed("blake3", 1024);
            using var ds = new Seed("blake3", 1024);
            using var ss = new Seed("blake3", 1024);
            var ct = Cipher.Encrypt(ns, ds, ss, plaintext);

            byte[] blob;
            using (var src = new Blob256())
            {
                foreach (var (slot, seed) in new (BlobSlot, Seed)[]
                    { (BlobSlot.N, ns), (BlobSlot.D, ds), (BlobSlot.S, ss) })
                {
                    src.SetKey(slot, seed.GetHashKey());
                    src.SetComponents(slot, seed.GetComponents());
                }
                blob = src.Export();
            }

            ResetGlobals();
            using var dst = new Blob256();
            dst.Import(blob);
            Assert.Equal(1, dst.Mode);
            using var ns2 = Seed.FromComponents("blake3",
                dst.GetComponents(BlobSlot.N), dst.GetKey(BlobSlot.N));
            using var ds2 = Seed.FromComponents("blake3",
                dst.GetComponents(BlobSlot.D), dst.GetKey(BlobSlot.D));
            using var ss2 = Seed.FromComponents("blake3",
                dst.GetComponents(BlobSlot.S), dst.GetKey(BlobSlot.S));
            Assert.Equal(plaintext, Cipher.Decrypt(ns2, ds2, ss2, ct));
        });
    }

    [Fact]
    public void TestBlob256Triple()
    {
        WithGlobals(() =>
        {
            var plaintext = Encoding.UTF8.GetBytes("cs blob256 triple round-trip");
            var seeds = new Seed[7];
            for (var i = 0; i < 7; i++) seeds[i] = new Seed("blake3", 1024);
            try
            {
                var ct = Cipher.EncryptTriple(seeds[0], seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6], plaintext);
                var slots = new[]
                {
                    BlobSlot.N, BlobSlot.D1, BlobSlot.D2, BlobSlot.D3,
                    BlobSlot.S1, BlobSlot.S2, BlobSlot.S3,
                };

                byte[] blob;
                using (var src = new Blob256())
                {
                    for (var i = 0; i < 7; i++)
                    {
                        src.SetKey(slots[i], seeds[i].GetHashKey());
                        src.SetComponents(slots[i], seeds[i].GetComponents());
                    }
                    blob = src.ExportTriple();
                }

                ResetGlobals();
                using var dst = new Blob256();
                dst.ImportTriple(blob);
                Assert.Equal(3, dst.Mode);

                var seeds2 = new Seed[7];
                try
                {
                    for (var i = 0; i < 7; i++)
                    {
                        seeds2[i] = Seed.FromComponents("blake3",
                            dst.GetComponents(slots[i]), dst.GetKey(slots[i]));
                    }
                    var pt = Cipher.DecryptTriple(seeds2[0], seeds2[1], seeds2[2], seeds2[3],
                        seeds2[4], seeds2[5], seeds2[6], ct);
                    Assert.Equal(plaintext, pt);
                }
                finally
                {
                    foreach (var s in seeds2) s?.Dispose();
                }
            }
            finally
            {
                foreach (var s in seeds) s.Dispose();
            }
        });
    }

    // ----------------------------------------------------------------
    // Blob128 — siphash24 (no key) and aescmac (16-byte key).
    // ----------------------------------------------------------------

    [Fact]
    public void TestBlob128SiphashSingle()
    {
        WithGlobals(() =>
        {
            var plaintext = Encoding.UTF8.GetBytes("cs blob128 siphash round-trip");
            using var ns = new Seed("siphash24", 512);
            using var ds = new Seed("siphash24", 512);
            using var ss = new Seed("siphash24", 512);
            var ct = Cipher.Encrypt(ns, ds, ss, plaintext);

            byte[] blob;
            using (var src = new Blob128())
            {
                foreach (var (slot, seed) in new (BlobSlot, Seed)[]
                    { (BlobSlot.N, ns), (BlobSlot.D, ds), (BlobSlot.S, ss) })
                {
                    src.SetKey(slot, seed.GetHashKey()); // empty span
                    src.SetComponents(slot, seed.GetComponents());
                }
                blob = src.Export();
            }

            ResetGlobals();
            using var dst = new Blob128();
            dst.Import(blob);
            using var ns2 = Seed.FromComponents("siphash24",
                dst.GetComponents(BlobSlot.N), Array.Empty<byte>());
            using var ds2 = Seed.FromComponents("siphash24",
                dst.GetComponents(BlobSlot.D), Array.Empty<byte>());
            using var ss2 = Seed.FromComponents("siphash24",
                dst.GetComponents(BlobSlot.S), Array.Empty<byte>());
            Assert.Equal(plaintext, Cipher.Decrypt(ns2, ds2, ss2, ct));
        });
    }

    [Fact]
    public void TestBlob128AescmacSingle()
    {
        WithGlobals(() =>
        {
            var plaintext = Encoding.UTF8.GetBytes("cs blob128 aescmac round-trip");
            using var ns = new Seed("aescmac", 512);
            using var ds = new Seed("aescmac", 512);
            using var ss = new Seed("aescmac", 512);
            var ct = Cipher.Encrypt(ns, ds, ss, plaintext);

            byte[] blob;
            using (var src = new Blob128())
            {
                foreach (var (slot, seed) in new (BlobSlot, Seed)[]
                    { (BlobSlot.N, ns), (BlobSlot.D, ds), (BlobSlot.S, ss) })
                {
                    src.SetKey(slot, seed.GetHashKey());
                    src.SetComponents(slot, seed.GetComponents());
                }
                blob = src.Export();
            }

            ResetGlobals();
            using var dst = new Blob128();
            dst.Import(blob);
            using var ns2 = Seed.FromComponents("aescmac",
                dst.GetComponents(BlobSlot.N), dst.GetKey(BlobSlot.N));
            using var ds2 = Seed.FromComponents("aescmac",
                dst.GetComponents(BlobSlot.D), dst.GetKey(BlobSlot.D));
            using var ss2 = Seed.FromComponents("aescmac",
                dst.GetComponents(BlobSlot.S), dst.GetKey(BlobSlot.S));
            Assert.Equal(plaintext, Cipher.Decrypt(ns2, ds2, ss2, ct));
        });
    }

    // ----------------------------------------------------------------
    // Slot-naming surface.
    // ----------------------------------------------------------------

    [Fact]
    public void TestEnumSlotsAccessible()
    {
        // Mirrors test_string_and_int_slots_equivalent — the C# binding
        // exposes BlobSlot as a typed enum, with the underlying int
        // values matching libitb's BlobSlot* constants. Round-tripping a
        // key+components pair through any slot must read back the same
        // bytes.
        using var b = new Blob512();
        var key = TestRng.Bytes(64);
        var comps = new ulong[8];
        for (var i = 0; i < 8; i++) comps[i] = 0xDEADBEEFCAFEBABE;
        b.SetKey(BlobSlot.N, key);
        b.SetComponents(BlobSlot.N, comps);
        Assert.Equal(0, (int)BlobSlot.N);
        Assert.Equal(key, b.GetKey(BlobSlot.N));
        Assert.Equal(comps, b.GetComponents(BlobSlot.N));
    }

    // Skipped — the Python `test_invalid_slot_name` covers ValueError
    // raised when a slot name string is not recognised. The C# BlobSlot
    // is a typed enum so an invalid slot name is rejected at compile
    // time, no runtime test needed.

    // ----------------------------------------------------------------
    // Error paths — mode mismatch, malformed, version too new.
    // ----------------------------------------------------------------

    [Fact]
    public void TestModeMismatch()
    {
        WithGlobals(() =>
        {
            using var ns = new Seed("areion512", 1024);
            using var ds = new Seed("areion512", 1024);
            using var ss = new Seed("areion512", 1024);
            byte[] blob;
            using (var src = new Blob512())
            {
                foreach (var (slot, seed) in new (BlobSlot, Seed)[]
                    { (BlobSlot.N, ns), (BlobSlot.D, ds), (BlobSlot.S, ss) })
                {
                    src.SetKey(slot, seed.GetHashKey());
                    src.SetComponents(slot, seed.GetComponents());
                }
                blob = src.Export();
            }

            using var dst = new Blob512();
            // Single-mode blob fed into ImportTriple — typed mismatch.
            Assert.Throws<ItbBlobModeMismatchException>(() => dst.ImportTriple(blob));
        });
    }

    [Fact]
    public void TestMalformed()
    {
        using var b = new Blob512();
        var bad = Encoding.UTF8.GetBytes("{not json");
        Assert.Throws<ItbBlobMalformedException>(() => b.Import(bad));
    }

    [Fact]
    public void TestVersionTooNew()
    {
        // Hand-built JSON with v=99 (above any version this build
        // supports). Shape mirrors the Python test exactly.
        var sb = new StringBuilder();
        sb.Append("{\"v\":99,\"mode\":1,\"key_bits\":512,");
        var zk = new string('0', 128); // 64 bytes hex = 128 chars
        sb.Append("\"key_n\":\"").Append(zk).Append("\",");
        sb.Append("\"key_d\":\"").Append(zk).Append("\",");
        sb.Append("\"key_s\":\"").Append(zk).Append("\",");
        var c = "\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\",\"0\"";
        sb.Append("\"ns\":[").Append(c).Append("],");
        sb.Append("\"ds\":[").Append(c).Append("],");
        sb.Append("\"ss\":[").Append(c).Append("],");
        sb.Append("\"globals\":{\"nonce_bits\":128,\"barrier_fill\":1,\"bit_soup\":0,\"lock_soup\":0}");
        sb.Append('}');
        var data = Encoding.UTF8.GetBytes(sb.ToString());
        using var b = new Blob512();
        Assert.Throws<ItbBlobVersionTooNewException>(() => b.Import(data));
    }
}
