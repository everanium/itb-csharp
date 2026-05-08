// Streaming round-trip tests against the Encryptor surface.
//
// Mirrors bindings/python/tests/easy/test_streams.py. Two streaming
// patterns are exercised here:
//
//   1. The chunked Encryptor pattern — slice the plaintext into chunks
//      of the desired size, call Encryptor.Encrypt per chunk, walk the
//      concatenated chunk stream by reading enc.HeaderSize bytes,
//      calling enc.ParseChunkLen, and decrypting per-chunk. This is
//      what the Python source-of-truth file uses.
//
//   2. The class-based StreamEncryptor / StreamDecryptor (and Triple
//      Ouroboros counterparts) — the C# binding ships an explicit
//      Stream-style wrapper that takes Seed instances directly (NOT
//      Encryptor instances). The Encryptor is constructed only to
//      surface MacName / settings; freshly-built Seed handles drive
//      the stream wrappers. Tests cover the same matrix
//      (default + non-default nonce sizes, Single + Triple).
//
// The stream wrappers do NOT support an Auth path; tamper rejection is
// covered by TestEasyAuth on the Encryptor surface.

using Itb.Native;

namespace Itb.Tests;

[Collection(TestCollections.GlobalState)]
public sealed class TestEasyStreams
{
    private const int SmallChunk = 4096;

    /// <summary>
    /// Slices <paramref name="plaintext"/> into <paramref name="chunkSize"/>
    /// chunks and emits the concatenated ITB ciphertexts. Mirrors the
    /// Python <c>_stream_encrypt</c> helper that drives the
    /// Encryptor surface as a streaming primitive.
    /// </summary>
    private static byte[] StreamEncryptViaEncryptor(
        Encryptor enc, ReadOnlySpan<byte> plaintext, int chunkSize)
    {
        using var ms = new MemoryStream();
        var i = 0;
        while (i < plaintext.Length)
        {
            var end = Math.Min(i + chunkSize, plaintext.Length);
            var ct = enc.Encrypt(plaintext.Slice(i, end - i));
            ms.Write(ct, 0, ct.Length);
            i = end;
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Walks a concatenated ITB chunk stream and returns the recovered
    /// plaintext. Mirrors the Python <c>_stream_decrypt</c> helper.
    /// Throws <see cref="InvalidOperationException"/> when the trailing
    /// bytes do not form a complete chunk.
    /// </summary>
    private static byte[] StreamDecryptViaEncryptor(
        Encryptor enc, byte[] ciphertext)
    {
        using var output = new MemoryStream();
        var accumulator = new List<byte>();
        var feedOff = 0;
        var headerSize = enc.HeaderSize;

        while (feedOff < ciphertext.Length)
        {
            var end = Math.Min(feedOff + SmallChunk, ciphertext.Length);
            for (var i = feedOff; i < end; i++)
            {
                accumulator.Add(ciphertext[i]);
            }
            feedOff = end;
            // Drain any complete chunks already in the accumulator.
            while (true)
            {
                if (accumulator.Count < headerSize)
                {
                    break;
                }
                var hdr = new byte[headerSize];
                for (var k = 0; k < headerSize; k++)
                {
                    hdr[k] = accumulator[k];
                }
                var chunkLen = enc.ParseChunkLen(hdr);
                if (accumulator.Count < chunkLen)
                {
                    break;
                }
                var chunk = new byte[chunkLen];
                for (var k = 0; k < chunkLen; k++)
                {
                    chunk[k] = accumulator[k];
                }
                accumulator.RemoveRange(0, chunkLen);
                var pt = enc.Decrypt(chunk);
                output.Write(pt, 0, pt.Length);
            }
        }
        if (accumulator.Count > 0)
        {
            throw new InvalidOperationException(
                $"trailing {accumulator.Count} bytes do not form a complete chunk");
        }
        return output.ToArray();
    }

    /// <summary>
    /// Single Ouroboros chunked-Encryptor round-trip at the default
    /// nonce size. Plaintext spans multiple chunks plus a 17-byte
    /// trailing partial.
    /// </summary>
    [Fact]
    public void EncryptorChunkedRoundtripDefaultNonceSingle()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 5 + 17);
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        var ct = StreamEncryptViaEncryptor(enc, plaintext, SmallChunk);
        var pt = StreamDecryptViaEncryptor(enc, ct);
        Assert.Equal(plaintext, pt);
    }

    /// <summary>
    /// Single Ouroboros chunked-Encryptor round-trip at non-default
    /// nonce sizes (256 / 512). Per-instance setter ensures each
    /// chunk's wire header carries the right nonce length.
    /// </summary>
    [Fact]
    public void EncryptorChunkedRoundtripNonDefaultNonceSingle()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 3 + 100);
        foreach (var n in new[] { 256, 512 })
        {
            using var enc = new Encryptor("blake3", 1024, "kmac256");
            enc.SetNonceBits(n);
            var ct = StreamEncryptViaEncryptor(enc, plaintext, SmallChunk);
            var pt = StreamDecryptViaEncryptor(enc, ct);
            Assert.Equal(plaintext, pt);
        }
    }

    /// <summary>
    /// Triple Ouroboros chunked-Encryptor round-trip at the default
    /// nonce size.
    /// </summary>
    [Fact]
    public void EncryptorChunkedRoundtripDefaultNonceTriple()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 4 + 33);
        using var enc = new Encryptor("blake3", 1024, "kmac256", mode: "triple");
        var ct = StreamEncryptViaEncryptor(enc, plaintext, SmallChunk);
        var pt = StreamDecryptViaEncryptor(enc, ct);
        Assert.Equal(plaintext, pt);
    }

    /// <summary>
    /// Triple Ouroboros chunked-Encryptor round-trip at non-default
    /// nonce sizes.
    /// </summary>
    [Fact]
    public void EncryptorChunkedRoundtripNonDefaultNonceTriple()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 3);
        foreach (var n in new[] { 256, 512 })
        {
            using var enc = new Encryptor("blake3", 1024, "kmac256", mode: "triple");
            enc.SetNonceBits(n);
            var ct = StreamEncryptViaEncryptor(enc, plaintext, SmallChunk);
            var pt = StreamDecryptViaEncryptor(enc, ct);
            Assert.Equal(plaintext, pt);
        }
    }

    /// <summary>
    /// Feeding only a partial chunk to the streaming decoder surfaces
    /// an <see cref="InvalidOperationException"/> on close — same
    /// plausible-failure contract as the lower-level
    /// <see cref="StreamDecryptor"/>.
    /// </summary>
    [Fact]
    public void EncryptorChunkedPartialChunkRaises()
    {
        var plaintext = new byte[100];
        for (var i = 0; i < plaintext.Length; i++)
        {
            plaintext[i] = (byte)'x';
        }
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        var ct = StreamEncryptViaEncryptor(enc, plaintext, SmallChunk);
        // Feed only 30 bytes — header complete (>= 20) but body
        // truncated. The drain loop must reject the trailing
        // incomplete chunk on close.
        var truncated = new byte[30];
        Buffer.BlockCopy(ct, 0, truncated, 0, 30);
        Assert.Throws<InvalidOperationException>(() =>
            StreamDecryptViaEncryptor(enc, truncated));
    }

    /// <summary>
    /// <see cref="Encryptor.ParseChunkLen"/> on a buffer shorter than
    /// the header surfaces as <see cref="ItbException"/> with status
    /// <c>BadInput</c>.
    /// </summary>
    [Fact]
    public void EncryptorParseChunkLenShortBuffer()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        var buf = new byte[enc.HeaderSize - 1];
        var ex = Assert.Throws<ItbException>(() => enc.ParseChunkLen(buf));
        Assert.Equal(Status.BadInput, ex.Status);
    }

    /// <summary>
    /// <see cref="Encryptor.ParseChunkLen"/> on a header-size buffer of
    /// zeros (zero width / zero height) surfaces as
    /// <see cref="ItbException"/>.
    /// </summary>
    [Fact]
    public void EncryptorParseChunkLenZeroDim()
    {
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        var hdr = new byte[enc.HeaderSize];
        Assert.Throws<ItbException>(() => enc.ParseChunkLen(hdr));
    }

    // ----------------------------------------------------------------
    // Class-based StreamEncryptor / StreamDecryptor coverage.
    //
    // The class-based wrappers take Seed instances directly (not
    // Encryptor instances) — the Encryptor is constructed alongside
    // for its MacName / introspection surface, but the freshly-built
    // Seed handles drive the streaming wrappers.
    // ----------------------------------------------------------------

    /// <summary>
    /// <see cref="StreamEncryptor"/> + <see cref="StreamDecryptor"/>
    /// round-trip at the default nonce size. Plaintext spans multiple
    /// chunks plus a trailing partial.
    /// </summary>
    [Fact]
    public void StreamEncryptorRoundtripDefaultNonce()
    {
        using var snap = GlobalStateSnapshot.Capture();
        Library.NonceBits = 128;

        // The Encryptor instance is constructed for its settings
        // reference but NOT passed into the stream — verify the
        // expected MacName surface, then drive the stream with
        // freshly-built seeds.
        using var enc = new Encryptor("blake3", 1024, "kmac256");
        Assert.Equal("kmac256", enc.MacName);

        var plaintext = TestRng.Bytes(SmallChunk * 5 + 17);

        using var noise = new Seed("blake3", 1024);
        using var data = new Seed("blake3", 1024);
        using var start = new Seed("blake3", 1024);

        byte[] ciphertext;
        using (var cbuf = new MemoryStream())
        {
            using (var streamEnc = new StreamEncryptor(noise, data, start, cbuf, SmallChunk))
            {
                streamEnc.Write(plaintext);
            }
            ciphertext = cbuf.ToArray();
        }

        byte[] decrypted;
        using (var pbuf = new MemoryStream())
        {
            using (var streamDec = new StreamDecryptor(noise, data, start, pbuf))
            {
                streamDec.Feed(ciphertext);
                streamDec.Close();
            }
            decrypted = pbuf.ToArray();
        }
        Assert.Equal(plaintext, decrypted);
    }

    /// <summary>
    /// <see cref="StreamEncryptor"/> + <see cref="StreamDecryptor"/>
    /// round-trip at non-default nonce sizes. The nonce-bits are set
    /// process-globally before constructing the stream so the chunk
    /// header layout and the decryptor's snapshot agree.
    /// </summary>
    [Fact]
    public void StreamEncryptorRoundtripNonDefaultNonce()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 3 + 100);
        foreach (var n in new[] { 256, 512 })
        {
            using var snap = GlobalStateSnapshot.Capture();
            Library.NonceBits = n;

            using var enc = new Encryptor("blake3", 1024, "kmac256");
            Assert.Equal(n, enc.NonceBits);

            using var noise = new Seed("blake3", 1024);
            using var data = new Seed("blake3", 1024);
            using var start = new Seed("blake3", 1024);

            byte[] ciphertext;
            using (var cbuf = new MemoryStream())
            {
                using (var streamEnc = new StreamEncryptor(
                    noise, data, start, cbuf, SmallChunk))
                {
                    streamEnc.Write(plaintext);
                }
                ciphertext = cbuf.ToArray();
            }

            byte[] decrypted;
            using (var pbuf = new MemoryStream())
            {
                using (var streamDec = new StreamDecryptor(noise, data, start, pbuf))
                {
                    streamDec.Feed(ciphertext);
                    streamDec.Close();
                }
                decrypted = pbuf.ToArray();
            }
            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Triple Ouroboros stream round-trip via
    /// <see cref="StreamEncryptorTriple"/> +
    /// <see cref="StreamDecryptorTriple"/> at the default nonce size.
    /// </summary>
    [Fact]
    public void StreamEncryptorTripleRoundtripDefaultNonce()
    {
        using var snap = GlobalStateSnapshot.Capture();
        Library.NonceBits = 128;

        using var enc = new Encryptor("blake3", 1024, "kmac256", mode: "triple");
        Assert.Equal(3, enc.Mode);

        var plaintext = TestRng.Bytes(SmallChunk * 4 + 33);

        var seeds = new Seed[7];
        try
        {
            for (var i = 0; i < 7; i++)
            {
                seeds[i] = new Seed("blake3", 1024);
            }

            byte[] ciphertext;
            using (var cbuf = new MemoryStream())
            {
                using (var streamEnc = new StreamEncryptorTriple(
                    seeds[0], seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6],
                    cbuf, SmallChunk))
                {
                    streamEnc.Write(plaintext);
                }
                ciphertext = cbuf.ToArray();
            }

            byte[] decrypted;
            using (var pbuf = new MemoryStream())
            {
                using (var streamDec = new StreamDecryptorTriple(
                    seeds[0], seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6],
                    pbuf))
                {
                    streamDec.Feed(ciphertext);
                    streamDec.Close();
                }
                decrypted = pbuf.ToArray();
            }
            Assert.Equal(plaintext, decrypted);
        }
        finally
        {
            foreach (var s in seeds)
            {
                s?.Dispose();
            }
        }
    }

    /// <summary>
    /// Triple Ouroboros stream round-trip at non-default nonce sizes.
    /// </summary>
    [Fact]
    public void StreamEncryptorTripleRoundtripNonDefaultNonce()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 3);
        foreach (var n in new[] { 256, 512 })
        {
            using var snap = GlobalStateSnapshot.Capture();
            Library.NonceBits = n;

            var seeds = new Seed[7];
            try
            {
                for (var i = 0; i < 7; i++)
                {
                    seeds[i] = new Seed("blake3", 1024);
                }

                byte[] ciphertext;
                using (var cbuf = new MemoryStream())
                {
                    using (var streamEnc = new StreamEncryptorTriple(
                        seeds[0], seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6],
                        cbuf, SmallChunk))
                    {
                        streamEnc.Write(plaintext);
                    }
                    ciphertext = cbuf.ToArray();
                }

                byte[] decrypted;
                using (var pbuf = new MemoryStream())
                {
                    using (var streamDec = new StreamDecryptorTriple(
                        seeds[0], seeds[1], seeds[2], seeds[3],
                        seeds[4], seeds[5], seeds[6],
                        pbuf))
                    {
                        streamDec.Feed(ciphertext);
                        streamDec.Close();
                    }
                    decrypted = pbuf.ToArray();
                }
                Assert.Equal(plaintext, decrypted);
            }
            finally
            {
                foreach (var s in seeds)
                {
                    s?.Dispose();
                }
            }
        }
    }

    /// <summary>
    /// <see cref="StreamEncryptor"/> with a non-positive
    /// <c>chunkSize</c> argument is rejected at construction with
    /// <see cref="ItbException"/> carrying <see cref="StatusCode.BadInput"/>.
    /// </summary>
    [Fact]
    public void StreamEncryptorRejectsZeroChunkSize()
    {
        using var noise = new Seed("blake3", 1024);
        using var data = new Seed("blake3", 1024);
        using var start = new Seed("blake3", 1024);
        using var ms = new MemoryStream();
        Assert.Throws<ItbException>(() =>
            new StreamEncryptor(noise, data, start, ms, chunkSize: 0));
        Assert.Throws<ItbException>(() =>
            new StreamEncryptor(noise, data, start, ms, chunkSize: -1));
    }

    /// <summary>
    /// <see cref="StreamEncryptorTriple"/> with a non-positive
    /// <c>chunkSize</c> argument is rejected at construction.
    /// </summary>
    [Fact]
    public void StreamEncryptorTripleRejectsZeroChunkSize()
    {
        var seeds = new Seed[7];
        try
        {
            for (var i = 0; i < 7; i++)
            {
                seeds[i] = new Seed("blake3", 1024);
            }
            using var ms = new MemoryStream();
            Assert.Throws<ItbException>(() =>
                new StreamEncryptorTriple(
                    seeds[0], seeds[1], seeds[2], seeds[3],
                    seeds[4], seeds[5], seeds[6],
                    ms, chunkSize: 0));
        }
        finally
        {
            foreach (var s in seeds)
            {
                s?.Dispose();
            }
        }
    }

    /// <summary>
    /// <see cref="StreamDecryptor.Close"/> with leftover non-chunk
    /// bytes surfaces as <see cref="InvalidOperationException"/>.
    /// </summary>
    [Fact]
    public void StreamDecryptorRejectsTrailingPartial()
    {
        using var snap = GlobalStateSnapshot.Capture();
        Library.NonceBits = 128;

        using var noise = new Seed("blake3", 1024);
        using var data = new Seed("blake3", 1024);
        using var start = new Seed("blake3", 1024);

        // Encrypt a small payload, then truncate the ciphertext mid-body
        // (header complete, body short) and confirm Close raises.
        var plaintext = new byte[100];
        for (var i = 0; i < plaintext.Length; i++)
        {
            plaintext[i] = (byte)'x';
        }

        byte[] ciphertext;
        using (var cbuf = new MemoryStream())
        {
            using (var streamEnc = new StreamEncryptor(noise, data, start, cbuf, SmallChunk))
            {
                streamEnc.Write(plaintext);
            }
            ciphertext = cbuf.ToArray();
        }

        var truncated = new byte[30];
        Buffer.BlockCopy(ciphertext, 0, truncated, 0, 30);

        using var pbuf = new MemoryStream();
        var streamDec = new StreamDecryptor(noise, data, start, pbuf);
        streamDec.Feed(truncated);
        Assert.Throws<InvalidOperationException>(() => streamDec.Close());
    }

    /// <summary>
    /// <see cref="StreamPipeline.EncryptStream"/> +
    /// <see cref="StreamPipeline.DecryptStream"/> one-shot helpers
    /// round-trip a payload that spans multiple chunks plus a partial.
    /// </summary>
    [Fact]
    public void StreamPipelineSingleRoundtrip()
    {
        using var snap = GlobalStateSnapshot.Capture();
        Library.NonceBits = 128;

        using var noise = new Seed("blake3", 1024);
        using var data = new Seed("blake3", 1024);
        using var start = new Seed("blake3", 1024);

        var plaintext = TestRng.Bytes(SmallChunk * 2 + 257);
        byte[] ciphertext;
        using (var input = new MemoryStream(plaintext))
        using (var output = new MemoryStream())
        {
            StreamPipeline.EncryptStream(noise, data, start, input, output, SmallChunk);
            ciphertext = output.ToArray();
        }

        byte[] decrypted;
        using (var input = new MemoryStream(ciphertext))
        using (var output = new MemoryStream())
        {
            StreamPipeline.DecryptStream(noise, data, start, input, output);
            decrypted = output.ToArray();
        }
        Assert.Equal(plaintext, decrypted);
    }
}
