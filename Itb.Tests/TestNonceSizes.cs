// Round-trip tests across all nonce-size configurations.
//
// Mirrors bindings/python/tests/test_nonce_sizes.py — ITB exposes a
// runtime-configurable nonce size (Library.NonceBits) accepting one of
// {128, 256, 512}. The on-the-wire chunk header therefore varies
// between 20, 36, and 68 bytes; every consumer that walks ciphertext
// on the byte level (chunk parsers, tampering tests, streaming
// decoders) must use Library.HeaderSize rather than a hardcoded
// constant.
//
// This file exhaustively covers the FFI surface under each nonce
// configuration: one-shot encrypt / decrypt (Single + Triple),
// authenticated encrypt / decrypt (Single + Triple) including tamper
// rejection at the dynamic header offset, and ParseChunkLen reporting
// the right chunk length.
//
// Tests in this file mutate Library.NonceBits, so the class is
// decorated with [Collection(TestCollections.GlobalState)] and every
// mutation is bracketed by GlobalStateSnapshot.Capture().

namespace Itb.Tests;

[Collection(TestCollections.GlobalState)]
public class TestNonceSizes
{
    private static readonly int[] NonceSizes = { 128, 256, 512 };

    // ----------------------------------------------------------------
    // HeaderSize tracks NonceBits.
    // ----------------------------------------------------------------

    [Fact]
    public void TestDefaultHeaderSizeIs20()
    {
        using var snap = GlobalStateSnapshot.Capture();
        Library.NonceBits = 128;
        Assert.Equal(20, Library.HeaderSize);
        Assert.Equal(128, Library.NonceBits);
    }

    [Fact]
    public void TestHeaderSizeDynamic()
    {
        foreach (var n in NonceSizes)
        {
            using var snap = GlobalStateSnapshot.Capture();
            Library.NonceBits = n;
            // Header layout = nonce-bits / 8 + 4 (chunk-length + tag).
            // 128 -> 20, 256 -> 36, 512 -> 68.
            Assert.Equal(n / 8 + 4, Library.HeaderSize);
        }
    }

    [Fact]
    public void TestHeaderSizesMatchSpec()
    {
        // Direct check against the spec ladder.
        var expected = new (int nonce, int header)[]
        {
            (128, 20),
            (256, 36),
            (512, 68),
        };
        foreach (var (nonce, header) in expected)
        {
            using var snap = GlobalStateSnapshot.Capture();
            Library.NonceBits = nonce;
            Assert.Equal(header, Library.HeaderSize);
        }
    }

    [Fact]
    public void TestNonceBitsValidation()
    {
        using var snap = GlobalStateSnapshot.Capture();
        foreach (var valid in NonceSizes)
        {
            Library.NonceBits = valid;
            Assert.Equal(valid, Library.NonceBits);
        }
        foreach (var bad in new[] { 0, 1, 192, 1024 })
        {
            var ex = Assert.Throws<ItbException>(() => Library.NonceBits = bad);
            Assert.Equal(Native.Status.BadInput, ex.Status);
        }
    }

    // ----------------------------------------------------------------
    // Single one-shot encrypt / decrypt over all three nonce sizes.
    // ----------------------------------------------------------------

    [Fact]
    public void TestSingleAcrossNonceSizes()
    {
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var hashName in new[] { "siphash24", "blake3", "blake2b512" })
            {
                using var snap = GlobalStateSnapshot.Capture();
                Library.NonceBits = n;
                var seeds = new Seed[3];
                try
                {
                    for (var i = 0; i < 3; i++) seeds[i] = new Seed(hashName, 1024);
                    var ct = Cipher.Encrypt(seeds[0], seeds[1], seeds[2], plaintext);
                    var pt = Cipher.Decrypt(seeds[0], seeds[1], seeds[2], ct);
                    Assert.Equal(plaintext, pt);

                    // ParseChunkLen must report the full chunk length.
                    var headerSpan = new ReadOnlySpan<byte>(ct, 0, Library.HeaderSize);
                    Assert.Equal(ct.Length, Library.ParseChunkLen(headerSpan));
                }
                finally
                {
                    foreach (var s in seeds) s?.Dispose();
                }
            }
        }
    }

    // ----------------------------------------------------------------
    // Triple one-shot (7-seed) encrypt / decrypt over all three nonces.
    // ----------------------------------------------------------------

    [Fact]
    public void TestTripleAcrossNonceSizes()
    {
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var hashName in new[] { "siphash24", "blake3", "blake2b512" })
            {
                using var snap = GlobalStateSnapshot.Capture();
                Library.NonceBits = n;
                var seeds = new Seed[7];
                try
                {
                    for (var i = 0; i < 7; i++) seeds[i] = new Seed(hashName, 1024);
                    var ct = Cipher.EncryptTriple(seeds[0],
                        seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6], plaintext);
                    var pt = Cipher.DecryptTriple(seeds[0],
                        seeds[1], seeds[2], seeds[3],
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

    // ----------------------------------------------------------------
    // Single + Auth round trip + tamper rejection at dynamic header.
    // ----------------------------------------------------------------

    [Fact]
    public void TestSingleAuthAcrossNonceSizes()
    {
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var macName in new[] { "kmac256", "hmac-sha256", "hmac-blake3" })
            {
                using var snap = GlobalStateSnapshot.Capture();
                Library.NonceBits = n;
                using var mac = new Mac(macName, TestRng.Bytes(32));
                var seeds = new Seed[3];
                try
                {
                    for (var i = 0; i < 3; i++) seeds[i] = new Seed("blake3", 1024);
                    var ct = Cipher.EncryptAuth(seeds[0], seeds[1], seeds[2], mac, plaintext);
                    var pt = Cipher.DecryptAuth(seeds[0], seeds[1], seeds[2], mac, ct);
                    Assert.Equal(plaintext, pt);

                    var tampered = (byte[])ct.Clone();
                    var h = Library.HeaderSize;
                    var end = Math.Min(h + 256, tampered.Length);
                    for (var i = h; i < end; i++) tampered[i] ^= 0x01;
                    var ex = Assert.Throws<ItbException>(() =>
                        Cipher.DecryptAuth(seeds[0], seeds[1], seeds[2], mac, tampered));
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
    // Triple + Auth round trip + tamper rejection at dynamic header.
    // ----------------------------------------------------------------

    [Fact]
    public void TestTripleAuthAcrossNonceSizes()
    {
        var plaintext = TestRng.Bytes(1024);
        foreach (var n in NonceSizes)
        {
            foreach (var macName in new[] { "kmac256", "hmac-sha256", "hmac-blake3" })
            {
                using var snap = GlobalStateSnapshot.Capture();
                Library.NonceBits = n;
                using var mac = new Mac(macName, TestRng.Bytes(32));
                var seeds = new Seed[7];
                try
                {
                    for (var i = 0; i < 7; i++) seeds[i] = new Seed("blake3", 1024);
                    var ct = Cipher.EncryptAuthTriple(seeds[0],
                        seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6], mac, plaintext);
                    var pt = Cipher.DecryptAuthTriple(seeds[0],
                        seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6], mac, ct);
                    Assert.Equal(plaintext, pt);

                    var tampered = (byte[])ct.Clone();
                    var h = Library.HeaderSize;
                    var end = Math.Min(h + 256, tampered.Length);
                    for (var i = h; i < end; i++) tampered[i] ^= 0x01;
                    var ex = Assert.Throws<ItbException>(() =>
                        Cipher.DecryptAuthTriple(seeds[0],
                            seeds[1], seeds[2], seeds[3],
                            seeds[4], seeds[5], seeds[6], mac, tampered));
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
    // BarrierFill validation — adjacent global, same Library.* surface.
    // ----------------------------------------------------------------

    [Fact]
    public void TestBarrierFillValidation()
    {
        using var snap = GlobalStateSnapshot.Capture();
        foreach (var valid in new[] { 1, 2, 4, 8, 16, 32 })
        {
            Library.BarrierFill = valid;
            Assert.Equal(valid, Library.BarrierFill);
        }
        foreach (var bad in new[] { 0, 3, 5, 7, 64 })
        {
            var ex = Assert.Throws<ItbException>(() => Library.BarrierFill = bad);
            Assert.Equal(Native.Status.BadInput, ex.Status);
        }
    }

    // ----------------------------------------------------------------
    // BitSoup / LockSoup / MaxWorkers round-trip — adjacent globals.
    // ----------------------------------------------------------------

    [Fact]
    public void TestBitSoupRoundtrip()
    {
        using var snap = GlobalStateSnapshot.Capture();
        Library.BitSoup = 1;
        Assert.Equal(1, Library.BitSoup);
        Library.BitSoup = 0;
        Assert.Equal(0, Library.BitSoup);
    }

    [Fact]
    public void TestLockSoupRoundtrip()
    {
        using var snap = GlobalStateSnapshot.Capture();
        Library.LockSoup = 1;
        Assert.Equal(1, Library.LockSoup);
    }

    [Fact]
    public void TestMaxWorkersRoundtrip()
    {
        using var snap = GlobalStateSnapshot.Capture();
        Library.MaxWorkers = 4;
        Assert.Equal(4, Library.MaxWorkers);
    }
}
