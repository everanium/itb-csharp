// Tests for the authenticated streaming wrappers (StreamEncryptorAuth /
// StreamDecryptorAuth + Triple Ouroboros counterparts + the
// StreamPipeline.EncryptStreamAuth / DecryptStreamAuth helpers).
//
// Coverage mirrors the cross-binding contract for Streaming AEAD:
//
//   - Round-trip per (Single + Triple) × (3 hash widths) ×
//     (3 MAC primitives).
//   - Reorder of two chunks → ItbException MacFailure.
//   - Truncate-tail → ItbStreamTruncatedException from Close().
//   - Cross-stream replay → ItbException MacFailure.
//   - Stream-prefix tamper → ItbException MacFailure.
//   - Empty stream + single-chunk stream round-trip.
//   - Write/Feed after Close → ItbException EasyClosed.
//   - Trailing bytes past the terminator → ItbStreamAfterFinalException.
//
// The 32-byte CSPRNG stream_id prefix is generated server-side per
// constructor; tests therefore use MemoryStream as both input and
// output so the wire transcript can be inspected directly.

using System.IO;

namespace Itb.Tests;

[Collection(TestCollections.GlobalState)]
public class StreamsAuthTests
{
    private const int SmallChunk = 4096;
    private const int StreamIdLen = 32;

    private static readonly string[] CanonicalMacs =
        new[] { "kmac256", "hmac-sha256", "hmac-blake3" };

    private static readonly (string name, int width)[] HashByWidth =
        new[]
        {
            ("siphash24", 128),
            ("blake3", 256),
            ("blake2b512", 512),
        };

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

    private static Mac NewMac(string name)
    {
        return new Mac(name, TestRng.Bytes(32));
    }

    /// <summary>
    /// Splits a Streaming AEAD wire transcript into the 32-byte
    /// stream_id prefix and the on-wire chunk byte slices.
    /// </summary>
    private static (byte[] prefix, List<byte[]> chunks) SplitChunks(byte[] ct)
    {
        var headerSize = Library.HeaderSize;
        var prefix = ct.AsSpan(0, StreamIdLen).ToArray();
        var chunks = new List<byte[]>();
        var off = StreamIdLen;
        while (off < ct.Length)
        {
            var hdr = ct.AsSpan(off, headerSize).ToArray();
            var cl = Library.ParseChunkLen(hdr);
            chunks.Add(ct.AsSpan(off, cl).ToArray());
            off += cl;
        }
        return (prefix, chunks);
    }

    // ----------------------------------------------------------------
    // Round-trip — Single Ouroboros + MAC.
    // ----------------------------------------------------------------

    [Fact]
    public void TestSingleClassRoundtripDefaultNonce()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 5 + 17);
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var cbuf = new MemoryStream();
            using (var enc = new StreamEncryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, cbuf, SmallChunk))
            {
                enc.Write(plaintext.AsSpan(0, 1000));
                enc.Write(plaintext.AsSpan(1000, 4000));
                enc.Write(plaintext.AsSpan(5000, plaintext.Length - 5000));
            }
            var ct = cbuf.ToArray();
            Assert.True(ct.Length >= StreamIdLen);

            var pbuf = new MemoryStream();
            using (var dec = new StreamDecryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, pbuf))
            {
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
    public void TestSingleAllMacAllWidth()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 2 + 33);
        foreach (var macName in CanonicalMacs)
        {
            foreach (var (hashName, _) in HashByWidth)
            {
                var seeds = MakeSeeds(hashName, 3);
                using var mac = NewMac(macName);
                try
                {
                    var cbuf = new MemoryStream();
                    using (var enc = new StreamEncryptorAuth(
                        seeds[0], seeds[1], seeds[2], mac, cbuf, SmallChunk))
                    {
                        enc.Write(plaintext.AsSpan());
                    }
                    var pbuf = new MemoryStream();
                    using (var dec = new StreamDecryptorAuth(
                        seeds[0], seeds[1], seeds[2], mac, pbuf))
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
    }

    [Fact]
    public void TestSingleNonDefaultNonce()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 3 + 100);
        foreach (var n in new[] { 256, 512 })
        {
            using var snap = GlobalStateSnapshot.Capture();
            Library.NonceBits = n;
            var seeds = MakeSeeds("blake3", 3);
            using var mac = NewMac("hmac-sha256");
            try
            {
                var cbuf = new MemoryStream();
                using (var enc = new StreamEncryptorAuth(
                    seeds[0], seeds[1], seeds[2], mac, cbuf, SmallChunk))
                {
                    enc.Write(plaintext.AsSpan());
                }
                var pbuf = new MemoryStream();
                using (var dec = new StreamDecryptorAuth(
                    seeds[0], seeds[1], seeds[2], mac, pbuf))
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

    // ----------------------------------------------------------------
    // Round-trip — Triple Ouroboros + MAC.
    // ----------------------------------------------------------------

    [Fact]
    public void TestTripleClassRoundtripDefaultNonce()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 4 + 33);
        var seeds = MakeSeeds("blake3", 7);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var cbuf = new MemoryStream();
            using (var enc = new StreamEncryptorAuthTriple(
                seeds[0], seeds[1], seeds[2], seeds[3],
                seeds[4], seeds[5], seeds[6], mac, cbuf, SmallChunk))
            {
                enc.Write(plaintext.AsSpan(0, SmallChunk));
                enc.Write(plaintext.AsSpan(SmallChunk, 2 * SmallChunk));
                enc.Write(plaintext.AsSpan(3 * SmallChunk, plaintext.Length - 3 * SmallChunk));
            }
            var pbuf = new MemoryStream();
            using (var dec = new StreamDecryptorAuthTriple(
                seeds[0], seeds[1], seeds[2], seeds[3],
                seeds[4], seeds[5], seeds[6], mac, pbuf))
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

    [Fact]
    public void TestTripleAllMacAllWidth()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 2 + 7);
        foreach (var macName in CanonicalMacs)
        {
            foreach (var (hashName, _) in HashByWidth)
            {
                var seeds = MakeSeeds(hashName, 7);
                using var mac = NewMac(macName);
                try
                {
                    var cbuf = new MemoryStream();
                    using (var enc = new StreamEncryptorAuthTriple(
                        seeds[0], seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6], mac, cbuf, SmallChunk))
                    {
                        enc.Write(plaintext.AsSpan());
                    }
                    var pbuf = new MemoryStream();
                    using (var dec = new StreamDecryptorAuthTriple(
                        seeds[0], seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6], mac, pbuf))
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
    }

    // ----------------------------------------------------------------
    // Pipeline functional helpers.
    // ----------------------------------------------------------------

    [Fact]
    public void TestPipelineEncryptDecryptRoundtrip()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 4);
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var cbuf = new MemoryStream();
            StreamPipeline.EncryptStreamAuth(
                seeds[0], seeds[1], seeds[2], mac,
                new MemoryStream(plaintext), cbuf, SmallChunk);

            var pbuf = new MemoryStream();
            StreamPipeline.DecryptStreamAuth(
                seeds[0], seeds[1], seeds[2], mac,
                new MemoryStream(cbuf.ToArray()), pbuf);
            Assert.Equal(plaintext, pbuf.ToArray());
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestPipelineTripleRoundtrip()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 5 + 7);
        var seeds = MakeSeeds("blake3", 7);
        using var mac = NewMac("hmac-sha256");
        try
        {
            var cbuf = new MemoryStream();
            StreamPipeline.EncryptStreamAuthTriple(
                seeds[0], seeds[1], seeds[2], seeds[3],
                seeds[4], seeds[5], seeds[6], mac,
                new MemoryStream(plaintext), cbuf, SmallChunk);

            var pbuf = new MemoryStream();
            StreamPipeline.DecryptStreamAuthTriple(
                seeds[0], seeds[1], seeds[2], seeds[3],
                seeds[4], seeds[5], seeds[6], mac,
                new MemoryStream(cbuf.ToArray()), pbuf);
            Assert.Equal(plaintext, pbuf.ToArray());
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    // ----------------------------------------------------------------
    // Edge cases.
    // ----------------------------------------------------------------

    [Fact]
    public void TestEmptyStream()
    {
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var cbuf = new MemoryStream();
            using (var enc = new StreamEncryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, cbuf, SmallChunk))
            {
                // No write — the close path emits the prefix + a
                // single terminating empty chunk.
            }
            var ct = cbuf.ToArray();
            Assert.True(ct.Length > StreamIdLen);

            var pbuf = new MemoryStream();
            using (var dec = new StreamDecryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, pbuf))
            {
                dec.Feed(ct);
                dec.Close();
            }
            Assert.Equal(Array.Empty<byte>(), pbuf.ToArray());
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestSingleChunkStream()
    {
        var plaintext = new byte[100];
        Array.Fill(plaintext, (byte)'x');
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var cbuf = new MemoryStream();
            using (var enc = new StreamEncryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, cbuf, SmallChunk))
            {
                enc.Write(plaintext.AsSpan());
            }
            var pbuf = new MemoryStream();
            using (var dec = new StreamDecryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, pbuf))
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

    // ----------------------------------------------------------------
    // Detection paths — five attack vectors closed by the
    // Streaming AEAD construction.
    // ----------------------------------------------------------------

    private byte[] ProduceCt(Seed[] seeds, Mac mac, byte[] plaintext)
    {
        var cbuf = new MemoryStream();
        using (var enc = new StreamEncryptorAuth(
            seeds[0], seeds[1], seeds[2], mac, cbuf, SmallChunk))
        {
            enc.Write(plaintext.AsSpan());
        }
        return cbuf.ToArray();
    }

    [Fact]
    public void TestChunkReorderDetected()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 2 + SmallChunk / 2);
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var ct = ProduceCt(seeds, mac, plaintext);
            var (prefix, chunks) = SplitChunks(ct);
            Assert.True(chunks.Count >= 3);
            // Swap chunks[0] <-> chunks[1] on wire.
            var tampered = new MemoryStream();
            tampered.Write(prefix, 0, prefix.Length);
            tampered.Write(chunks[1], 0, chunks[1].Length);
            tampered.Write(chunks[0], 0, chunks[0].Length);
            for (var i = 2; i < chunks.Count; i++)
            {
                tampered.Write(chunks[i], 0, chunks[i].Length);
            }

            var pbuf = new MemoryStream();
            var ex = Assert.Throws<ItbException>(() =>
            {
                using var dec = new StreamDecryptorAuth(
                    seeds[0], seeds[1], seeds[2], mac, pbuf);
                dec.Feed(tampered.ToArray());
                dec.Close();
            });
            Assert.Equal(StatusCode.MacFailure, ex.Status);
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestTruncateTailDetected()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 2 + SmallChunk / 2);
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var ct = ProduceCt(seeds, mac, plaintext);
            var (prefix, chunks) = SplitChunks(ct);
            Assert.True(chunks.Count >= 2);
            var truncated = new MemoryStream();
            truncated.Write(prefix, 0, prefix.Length);
            for (var i = 0; i < chunks.Count - 1; i++)
            {
                truncated.Write(chunks[i], 0, chunks[i].Length);
            }
            var pbuf = new MemoryStream();
            var dec = new StreamDecryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, pbuf);
            dec.Feed(truncated.ToArray());
            var ex = Assert.Throws<ItbStreamTruncatedException>(() => dec.Close());
            Assert.Equal(StatusCode.StreamTruncated, ex.Status);
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestAfterFinalDetected()
    {
        var plaintext = TestRng.Bytes(SmallChunk + 100);
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var ct = ProduceCt(seeds, mac, plaintext);
            var (prefix, chunks) = SplitChunks(ct);
            // Append a duplicate of the terminating chunk past the
            // original terminator.
            var afterFinal = new MemoryStream();
            afterFinal.Write(prefix, 0, prefix.Length);
            foreach (var c in chunks) afterFinal.Write(c, 0, c.Length);
            afterFinal.Write(chunks[^1], 0, chunks[^1].Length);

            var pbuf = new MemoryStream();
            var dec = new StreamDecryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, pbuf);
            var ex = Assert.Throws<ItbStreamAfterFinalException>(() =>
            {
                dec.Feed(afterFinal.ToArray());
            });
            Assert.Equal(StatusCode.StreamAfterFinal, ex.Status);
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestCrossStreamReplayDetected()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 2);
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            // Stream A and Stream B share PRF / MAC keys but get
            // distinct helper-generated stream_ids.
            var ctA = ProduceCt(seeds, mac, plaintext);
            var ctB = ProduceCt(seeds, mac, plaintext);
            var (pA, cA) = SplitChunks(ctA);
            var (pB, cB) = SplitChunks(ctB);
            Assert.NotEqual(pA, pB);
            // Splice chunk_0 of A into B's position 0 — same prefix
            // as B in the wire but different chunk-0 MAC.
            var tampered = new MemoryStream();
            tampered.Write(pB, 0, pB.Length);
            tampered.Write(cA[0], 0, cA[0].Length);
            for (var i = 1; i < cB.Count; i++)
            {
                tampered.Write(cB[i], 0, cB[i].Length);
            }
            var pbuf = new MemoryStream();
            var ex = Assert.Throws<ItbException>(() =>
            {
                using var dec = new StreamDecryptorAuth(
                    seeds[0], seeds[1], seeds[2], mac, pbuf);
                dec.Feed(tampered.ToArray());
                dec.Close();
            });
            Assert.Equal(StatusCode.MacFailure, ex.Status);
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestStreamPrefixTamperDetected()
    {
        var plaintext = TestRng.Bytes(SmallChunk + 200);
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var ct = ProduceCt(seeds, mac, plaintext);
            ct[0] ^= 0x80;
            var pbuf = new MemoryStream();
            var ex = Assert.Throws<ItbException>(() =>
            {
                using var dec = new StreamDecryptorAuth(
                    seeds[0], seeds[1], seeds[2], mac, pbuf);
                dec.Feed(ct);
                dec.Close();
            });
            Assert.Equal(StatusCode.MacFailure, ex.Status);
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    // ----------------------------------------------------------------
    // Closed-state preflight.
    // ----------------------------------------------------------------

    [Fact]
    public void TestWriteAfterCloseRaises()
    {
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var cbuf = new MemoryStream();
            var enc = new StreamEncryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, cbuf, SmallChunk);
            enc.Write(System.Text.Encoding.UTF8.GetBytes("hello"));
            enc.Close();
            var ex = Assert.Throws<ItbException>(() =>
                enc.Write(System.Text.Encoding.UTF8.GetBytes("world")));
            Assert.Equal(StatusCode.EasyClosed, ex.Status);
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestFeedAfterCloseRaises()
    {
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var cbuf = new MemoryStream();
            using (var enc = new StreamEncryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, cbuf, SmallChunk))
            {
                enc.Write(new byte[100]);
            }
            var pbuf = new MemoryStream();
            var dec = new StreamDecryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, pbuf);
            dec.Feed(cbuf.ToArray());
            dec.Close();
            var ex = Assert.Throws<ItbException>(() =>
                dec.Feed(new byte[1]));
            Assert.Equal(StatusCode.EasyClosed, ex.Status);
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestBadChunkSizeRejected()
    {
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var ex = Assert.Throws<ItbException>(() =>
                new StreamEncryptorAuth(
                    seeds[0], seeds[1], seeds[2], mac, new MemoryStream(),
                    chunkSize: 0));
            Assert.Equal(StatusCode.BadInput, ex.Status);
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    // ----------------------------------------------------------------
    // GC keep-alive — verify Seed / Mac wrappers stay alive past the
    // FFI call. Best-effort by invoking GC.Collect mid-feed; the
    // try / finally GC.KeepAlive bridges in the static helpers
    // protect every per-chunk handle dereference.
    // ----------------------------------------------------------------

    [Fact]
    public void TestSeedsAndMacRetainedThroughStreamLifetime()
    {
        var plaintext = TestRng.Bytes(SmallChunk + 1);
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var cbuf = new MemoryStream();
            var enc = new StreamEncryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, cbuf, SmallChunk);
            enc.Write(plaintext.AsSpan());
            // Force a GC between Write and Close — the encryptor
            // retains seeds + mac references on its private fields.
            GC.Collect();
            GC.WaitForPendingFinalizers();
            enc.Close();
            var pbuf = new MemoryStream();
            using (var dec = new StreamDecryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, pbuf))
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

    // ----------------------------------------------------------------
    // Per-byte chunk_size = 1 round-trip. Exercises the per-chunk
    // dispatch loop with the smallest possible plaintext granularity:
    // every plaintext byte triggers one full per-chunk MAC round-trip
    // and one container-cap encrypt/decrypt. Single-mode coverage on
    // one MAC primitive is sufficient — Triple is structurally
    // identical at the helper level.
    // ----------------------------------------------------------------

    [Fact]
    public void TestChunkSizeOneRoundtripSingle()
    {
        var plaintext = System.Text.Encoding.UTF8.GetBytes("chunk1by");  // 8 bytes
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var cbuf = new MemoryStream();
            using (var enc = new StreamEncryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, cbuf, chunkSize: 1))
            {
                enc.Write(plaintext);
            }
            var pbuf = new MemoryStream();
            using (var dec = new StreamDecryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, pbuf))
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

    // ----------------------------------------------------------------
    // Incomplete 32-byte stream-id prefix is a wire-level
    // malformation distinct from truncate-tail. Surfaces
    // ItbException with StatusCode.BadInput rather than
    // ItbStreamTruncatedException.
    // ----------------------------------------------------------------

    [Fact]
    public void TestIncompletePrefixRaisesBadInput()
    {
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var pbuf = new MemoryStream();
            var dec = new StreamDecryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, pbuf);
            dec.Feed(new byte[16]);  // 16 of 32 prefix bytes
            var ex = Assert.Throws<ItbException>(() => dec.Close());
            Assert.Equal(StatusCode.BadInput, ex.Status);
            Assert.IsNotType<ItbStreamTruncatedException>(ex);
        }
        finally
        {
            DisposeAll(seeds);
        }
    }

    [Fact]
    public void TestZeroBytePrefixRaisesBadInput()
    {
        var seeds = MakeSeeds("blake3", 3);
        using var mac = NewMac("hmac-blake3");
        try
        {
            var pbuf = new MemoryStream();
            var dec = new StreamDecryptorAuth(
                seeds[0], seeds[1], seeds[2], mac, pbuf);
            var ex = Assert.Throws<ItbException>(() => dec.Close());
            Assert.Equal(StatusCode.BadInput, ex.Status);
        }
        finally
        {
            DisposeAll(seeds);
        }
    }
}
