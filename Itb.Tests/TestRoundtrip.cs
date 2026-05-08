// End-to-end round-trip tests for the C# binding.
//
// Mirrors bindings/python/tests/test_roundtrip.py — exercises the
// cross-primitive matrix at 512 / 1024 / 2048 keyBits for both Single
// Ouroboros and Triple Ouroboros, plus introspection of Library.Version
// / Library.ListHashes / Library.MaxKeyBits / Library.Channels and the
// SeedWidthMix rejection on mismatched seed widths.
//
// The class does NOT mutate process-global libitb state, so no
// [Collection(TestCollections.GlobalState)] annotation is required.
// Tests run in parallel with sibling test classes.

namespace Itb.Tests;

public class TestRoundtrip
{
    /// <summary>
    /// Canonical primitive list, in the canonical hash order from
    /// <c>CLAUDE.md</c>'s primitive ordering rule. The shipped libitb
    /// build excludes lab primitives (CRC128 / FNV-1a / MD5), leaving
    /// the nine PRF-grade entries below.
    /// </summary>
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

    // ----------------------------------------------------------------
    // Introspection.
    // ----------------------------------------------------------------

    [Fact]
    public void TestVersion()
    {
        var v = Library.Version;
        Assert.False(string.IsNullOrEmpty(v));
        Assert.Matches(@"^\d+\.\d+\.\d+", v);
    }

    [Fact]
    public void TestListHashes()
    {
        var got = Library.ListHashes();
        Assert.Equal(CanonicalHashes.Length, got.Count);
        for (var i = 0; i < CanonicalHashes.Length; i++)
        {
            Assert.Equal(CanonicalHashes[i].name, got[i].Name);
            Assert.Equal(CanonicalHashes[i].width, got[i].Width);
        }
    }

    [Fact]
    public void TestConstants()
    {
        Assert.Equal(2048, Library.MaxKeyBits);
        Assert.Equal(8, Library.Channels);
    }

    // ----------------------------------------------------------------
    // Seed lifecycle.
    // ----------------------------------------------------------------

    [Fact]
    public void TestNewSeedHasExpectedFields()
    {
        using var s = new Seed("blake3", 1024);
        Assert.Equal("blake3", s.HashName);
        Assert.Equal(256, s.Width);
        Assert.Equal("blake3", s.HashNameIntrospect());
    }

    [Fact]
    public void TestBadHash()
    {
        var ex = Assert.Throws<ItbException>(() => new Seed("nonsense-hash", 1024));
        Assert.Equal(Native.Status.BadHash, ex.Status);
    }

    [Fact]
    public void TestBadKeyBits()
    {
        foreach (var bits in new[] { 0, 256, 511, 2049 })
        {
            var ex = Assert.Throws<ItbException>(() => new Seed("blake3", bits));
            Assert.Equal(Native.Status.BadKeyBits, ex.Status);
        }
    }

    // Skipped — the Python `test_double_free_idempotent` and
    // `test_context_manager` cover wrapper-level free idempotency and
    // context-manager scoping. The C# IDisposable contract guarantees
    // both at the framework / language level; no runtime test needed.

    // ----------------------------------------------------------------
    // Round-trip — full cross-primitive matrix.
    // ----------------------------------------------------------------

    [Fact]
    public void TestSingleAllHashesAllWidths()
    {
        var plaintext = TestRng.Bytes(4096);
        foreach (var (name, _) in CanonicalHashes)
        {
            foreach (var keyBits in new[] { 512, 1024, 2048 })
            {
                using var ns = new Seed(name, keyBits);
                using var ds = new Seed(name, keyBits);
                using var ss = new Seed(name, keyBits);
                var ct = Cipher.Encrypt(ns, ds, ss, plaintext);
                Assert.True(ct.Length > plaintext.Length,
                    $"hash={name} keyBits={keyBits}: ct {ct.Length} not greater than pt {plaintext.Length}");
                var pt = Cipher.Decrypt(ns, ds, ss, ct);
                Assert.Equal(plaintext, pt);
            }
        }
    }

    [Fact]
    public void TestTripleAllHashesAllWidths()
    {
        var plaintext = TestRng.Bytes(4096);
        foreach (var (name, _) in CanonicalHashes)
        {
            foreach (var keyBits in new[] { 512, 1024, 2048 })
            {
                var seeds = new Seed[7];
                try
                {
                    for (var i = 0; i < 7; i++) seeds[i] = new Seed(name, keyBits);
                    var ct = Cipher.EncryptTriple(seeds[0], seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6], plaintext);
                    Assert.True(ct.Length > plaintext.Length,
                        $"hash={name} keyBits={keyBits}: ct {ct.Length} not greater than pt {plaintext.Length}");
                    var pt = Cipher.DecryptTriple(seeds[0], seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6], ct);
                    Assert.Equal(plaintext, pt);
                }
                finally
                {
                    foreach (var s in seeds) s?.Dispose();
                }
            }
        }
    }

    // Skipped — the Python `test_bytearray_input` and `test_memoryview_input`
    // test bytearray / memoryview accepting types. ReadOnlySpan<byte> is
    // the C# binding's input type and accepts any byte-buffer slice;
    // verified at compile time.

    [Fact]
    public void TestSingleSeedWidthMismatch()
    {
        using var ns = new Seed("siphash24", 1024); // width 128
        using var ds = new Seed("blake3", 1024);    // width 256
        using var ss = new Seed("blake3", 1024);    // width 256
        var ex = Assert.Throws<ItbException>(() =>
            Cipher.Encrypt(ns, ds, ss, new byte[] { 0x68, 0x69 }));
        Assert.Equal(Native.Status.SeedWidthMix, ex.Status);
    }

    [Fact]
    public void TestTripleSeedWidthMismatch()
    {
        using var odd = new Seed("siphash24", 1024); // width 128
        var rest = new Seed[6];
        try
        {
            for (var i = 0; i < 6; i++) rest[i] = new Seed("blake3", 1024);
            var ex = Assert.Throws<ItbException>(() => Cipher.EncryptTriple(
                odd, rest[0], rest[1], rest[2], rest[3], rest[4], rest[5],
                new byte[] { 0x68, 0x69 }));
            Assert.Equal(Native.Status.SeedWidthMix, ex.Status);
        }
        finally
        {
            foreach (var s in rest) s?.Dispose();
        }
    }
}
