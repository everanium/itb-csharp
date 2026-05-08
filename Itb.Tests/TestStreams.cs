// Tests for the C# streaming wrappers (StreamEncryptor /
// StreamDecryptor / StreamEncryptorTriple / StreamDecryptorTriple +
// the StreamPipeline.EncryptStream / DecryptStream / *Triple
// convenience helpers).
//
// Mirrors bindings/python/tests/test_streams.py — every test uses
// MemoryStream as both input and output to exercise the file-like
// contract without touching disk. Multi-chunk inputs are constructed
// by calling Write() multiple times with sub-chunk slices, ensuring
// the encryptor's accumulator + flush logic processes more than one
// chunk per stream.
//
// Triple Ouroboros and non-default nonce-bits configurations are
// covered explicitly. Every test that mutates Library.NonceBits is
// bracketed by GlobalStateSnapshot.Capture(); the class is therefore
// decorated with [Collection(TestCollections.GlobalState)] to
// serialise with sibling global-mutating classes.

using System.IO;

namespace Itb.Tests;

[Collection(TestCollections.GlobalState)]
public class TestStreams
{
    /// <summary>
    /// Small chunk size to force multiple chunks for short inputs and
    /// exercise the accumulator-flush path. ITB still accepts these
    /// sizes; only the wire-format chunk count is amplified.
    /// </summary>
    private const int SmallChunk = 4096;

    private static Seed[] MakeSeeds(string name, int n)
    {
        var seeds = new Seed[n];
        for (var i = 0; i < n; i++) seeds[i] = new Seed(name, 1024);
        return seeds;
    }

    private static void DisposeAll(Seed[] seeds)
    {
        foreach (var s in seeds) s?.Dispose();
    }

    // ----------------------------------------------------------------
    // StreamEncryptor / StreamDecryptor — Single Ouroboros.
    // ----------------------------------------------------------------

    [Fact]
    public void TestSingleClassRoundtripDefaultNonce()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 5 + 17);
        var seeds = MakeSeeds("blake3", 3);
        try
        {
            var cbuf = new MemoryStream();
            using (var enc = new StreamEncryptor(seeds[0], seeds[1], seeds[2],
                cbuf, SmallChunk))
            {
                // Push data in three irregular slices, forcing the
                // accumulator path to handle partial chunks.
                enc.Write(plaintext.AsSpan(0, 1000));
                enc.Write(plaintext.AsSpan(1000, 4000));
                enc.Write(plaintext.AsSpan(5000, plaintext.Length - 5000));
            }
            var ct = cbuf.ToArray();

            var pbuf = new MemoryStream();
            using (var dec = new StreamDecryptor(seeds[0], seeds[1], seeds[2], pbuf))
            {
                // Feed ciphertext in 1-KB shards.
                for (var off = 0; off < ct.Length; off += 1024)
                {
                    var len = Math.Min(1024, ct.Length - off);
                    dec.Feed(ct.AsSpan(off, len));
                }
                dec.Close();
            }
            Assert.Equal(plaintext, pbuf.ToArray());
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestSingleClassRoundtripNonDefaultNonce()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 3 + 100);
        foreach (var n in new[] { 256, 512 })
        {
            using var snap = GlobalStateSnapshot.Capture();
            Library.NonceBits = n;
            var seeds = MakeSeeds("blake3", 3);
            try
            {
                var cbuf = new MemoryStream();
                using (var enc = new StreamEncryptor(seeds[0], seeds[1], seeds[2],
                    cbuf, SmallChunk))
                {
                    enc.Write(plaintext);
                }
                var pbuf = new MemoryStream();
                using (var dec = new StreamDecryptor(seeds[0], seeds[1], seeds[2], pbuf))
                {
                    dec.Feed(cbuf.ToArray());
                    dec.Close();
                }
                Assert.Equal(plaintext, pbuf.ToArray());
            }
            finally
            {
                DisposeAll(seeds);
            }
        }
    }

    [Fact]
    public void TestEncryptStreamDecryptStream()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 4);
        var seeds = MakeSeeds("blake3", 3);
        try
        {
            var fin = new MemoryStream(plaintext);
            var cbuf = new MemoryStream();
            StreamPipeline.EncryptStream(seeds[0], seeds[1], seeds[2],
                fin, cbuf, SmallChunk);

            var cin = new MemoryStream(cbuf.ToArray());
            var pbuf = new MemoryStream();
            StreamPipeline.DecryptStream(seeds[0], seeds[1], seeds[2], cin, pbuf);
            Assert.Equal(plaintext, pbuf.ToArray());
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestEncryptStreamAcrossNonceSizes()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 3 + 256);
        foreach (var n in new[] { 128, 256, 512 })
        {
            using var snap = GlobalStateSnapshot.Capture();
            Library.NonceBits = n;
            var seeds = MakeSeeds("blake3", 3);
            try
            {
                var fin = new MemoryStream(plaintext);
                var cbuf = new MemoryStream();
                StreamPipeline.EncryptStream(seeds[0], seeds[1], seeds[2],
                    fin, cbuf, SmallChunk);
                var pbuf = new MemoryStream();
                StreamPipeline.DecryptStream(seeds[0], seeds[1], seeds[2],
                    new MemoryStream(cbuf.ToArray()), pbuf);
                Assert.Equal(plaintext, pbuf.ToArray());
            }
            finally
            {
                DisposeAll(seeds);
            }
        }
    }

    // ----------------------------------------------------------------
    // StreamEncryptorTriple / StreamDecryptorTriple — Triple Ouroboros.
    // ----------------------------------------------------------------

    [Fact]
    public void TestTripleClassRoundtripDefaultNonce()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 4 + 33);
        var seeds = MakeSeeds("blake3", 7);
        try
        {
            var cbuf = new MemoryStream();
            using (var enc = new StreamEncryptorTriple(seeds[0],
                seeds[1], seeds[2], seeds[3],
                seeds[4], seeds[5], seeds[6],
                cbuf, SmallChunk))
            {
                enc.Write(plaintext.AsSpan(0, SmallChunk));
                enc.Write(plaintext.AsSpan(SmallChunk, 2 * SmallChunk));
                enc.Write(plaintext.AsSpan(3 * SmallChunk, plaintext.Length - 3 * SmallChunk));
            }
            var ct = cbuf.ToArray();

            var pbuf = new MemoryStream();
            using (var dec = new StreamDecryptorTriple(seeds[0],
                seeds[1], seeds[2], seeds[3],
                seeds[4], seeds[5], seeds[6], pbuf))
            {
                dec.Feed(ct);
                dec.Close();
            }
            Assert.Equal(plaintext, pbuf.ToArray());
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestTripleClassRoundtripNonDefaultNonce()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 3);
        foreach (var n in new[] { 256, 512 })
        {
            using var snap = GlobalStateSnapshot.Capture();
            Library.NonceBits = n;
            var seeds = MakeSeeds("blake3", 7);
            try
            {
                var cbuf = new MemoryStream();
                using (var enc = new StreamEncryptorTriple(seeds[0],
                    seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6],
                    cbuf, SmallChunk))
                {
                    enc.Write(plaintext);
                }
                var pbuf = new MemoryStream();
                using (var dec = new StreamDecryptorTriple(seeds[0],
                    seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6], pbuf))
                {
                    dec.Feed(cbuf.ToArray());
                    dec.Close();
                }
                Assert.Equal(plaintext, pbuf.ToArray());
            }
            finally
            {
                DisposeAll(seeds);
            }
        }
    }

    [Fact]
    public void TestEncryptStreamTripleDecryptStreamTriple()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 5 + 7);
        var seeds = MakeSeeds("blake3", 7);
        try
        {
            var fin = new MemoryStream(plaintext);
            var cbuf = new MemoryStream();
            StreamPipeline.EncryptStreamTriple(seeds[0],
                seeds[1], seeds[2], seeds[3],
                seeds[4], seeds[5], seeds[6],
                fin, cbuf, SmallChunk);
            var cin = new MemoryStream(cbuf.ToArray());
            var pbuf = new MemoryStream();
            StreamPipeline.DecryptStreamTriple(seeds[0],
                seeds[1], seeds[2], seeds[3],
                seeds[4], seeds[5], seeds[6], cin, pbuf);
            Assert.Equal(plaintext, pbuf.ToArray());
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestEncryptStreamTripleAcrossNonceSizes()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 3 + 100);
        foreach (var n in new[] { 128, 256, 512 })
        {
            using var snap = GlobalStateSnapshot.Capture();
            Library.NonceBits = n;
            var seeds = MakeSeeds("blake3", 7);
            try
            {
                var fin = new MemoryStream(plaintext);
                var cbuf = new MemoryStream();
                StreamPipeline.EncryptStreamTriple(seeds[0],
                    seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6],
                    fin, cbuf, SmallChunk);
                var pbuf = new MemoryStream();
                StreamPipeline.DecryptStreamTriple(seeds[0],
                    seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6],
                    new MemoryStream(cbuf.ToArray()), pbuf);
                Assert.Equal(plaintext, pbuf.ToArray());
            }
            finally
            {
                DisposeAll(seeds);
            }
        }
    }

    // ----------------------------------------------------------------
    // Stream error paths.
    // ----------------------------------------------------------------

    [Fact]
    public void TestWriteAfterCloseRaises()
    {
        var seeds = MakeSeeds("blake3", 3);
        try
        {
            var cbuf = new MemoryStream();
            var enc = new StreamEncryptor(seeds[0], seeds[1], seeds[2],
                cbuf, SmallChunk);
            enc.Write(new byte[] { 0x68, 0x65, 0x6c, 0x6c, 0x6f });
            enc.Close();
            var ex = Assert.Throws<ItbException>(() =>
                enc.Write(new byte[] { 0x77, 0x6f, 0x72, 0x6c, 0x64 }));
            Assert.Equal(Itb.Native.Status.EasyClosed, ex.Status);
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestPartialChunkAtCloseRaises()
    {
        var seeds = MakeSeeds("blake3", 3);
        try
        {
            var cbuf = new MemoryStream();
            using (var enc = new StreamEncryptor(seeds[0], seeds[1], seeds[2],
                cbuf, SmallChunk))
            {
                enc.Write(new byte[100].AsSpan());
            }
            var ct = cbuf.ToArray();

            var pbuf = new MemoryStream();
            var dec = new StreamDecryptor(seeds[0], seeds[1], seeds[2], pbuf);
            // Feed only the first 30 bytes — header complete (>= 20)
            // but body truncated. Close() must raise on the trailing
            // incomplete chunk.
            dec.Feed(ct.AsSpan(0, Math.Min(30, ct.Length)));
            Assert.Throws<InvalidOperationException>(() => dec.Close());
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    // ----------------------------------------------------------------
    // Chunk-size validation.
    // ----------------------------------------------------------------

    [Fact]
    public void TestStreamEncryptorRejectsNonPositiveChunkSize()
    {
        var seeds = MakeSeeds("blake3", 3);
        try
        {
            var cbuf = new MemoryStream();
            Assert.Throws<ItbException>(() =>
                new StreamEncryptor(seeds[0], seeds[1], seeds[2], cbuf, 0));
            Assert.Throws<ItbException>(() =>
                new StreamEncryptor(seeds[0], seeds[1], seeds[2], cbuf, -1));
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestStreamEncryptorTripleRejectsNonPositiveChunkSize()
    {
        var seeds = MakeSeeds("blake3", 7);
        try
        {
            var cbuf = new MemoryStream();
            Assert.Throws<ItbException>(() =>
                new StreamEncryptorTriple(seeds[0],
                    seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6], cbuf, 0));
            Assert.Throws<ItbException>(() =>
                new StreamEncryptorTriple(seeds[0],
                    seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6], cbuf, -1));
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestEncryptStreamRejectsNonPositiveChunkSize()
    {
        var seeds = MakeSeeds("blake3", 3);
        try
        {
            var fin = new MemoryStream();
            var fout = new MemoryStream();
            Assert.Throws<ItbException>(() =>
                StreamPipeline.EncryptStream(seeds[0], seeds[1], seeds[2],
                    fin, fout, 0));
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestDecryptStreamRejectsNonPositiveReadSize()
    {
        var seeds = MakeSeeds("blake3", 3);
        try
        {
            var fin = new MemoryStream();
            var fout = new MemoryStream();
            Assert.Throws<ItbException>(() =>
                StreamPipeline.DecryptStream(seeds[0], seeds[1], seeds[2],
                    fin, fout, 0));
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestEncryptStreamTripleRejectsNonPositiveChunkSize()
    {
        var seeds = MakeSeeds("blake3", 7);
        try
        {
            var fin = new MemoryStream();
            var fout = new MemoryStream();
            Assert.Throws<ItbException>(() =>
                StreamPipeline.EncryptStreamTriple(seeds[0],
                    seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6], fin, fout, 0));
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestDecryptStreamTripleRejectsNonPositiveReadSize()
    {
        var seeds = MakeSeeds("blake3", 7);
        try
        {
            var fin = new MemoryStream();
            var fout = new MemoryStream();
            Assert.Throws<ItbException>(() =>
                StreamPipeline.DecryptStreamTriple(seeds[0],
                    seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6], fin, fout, 0));
        }
        finally
        {
            DisposeAll(seeds);
        }
    }
}
