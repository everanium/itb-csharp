// Tests for the authenticated streaming methods on the high-level
// Encryptor (EncryptStreamAuth / DecryptStreamAuth).
//
// Drives the Easy Mode Streaming AEAD ABI export — one Encryptor
// instance covers the seed material, MAC closure, and per-instance
// configuration. Coverage parallels StreamsAuthTests at the
// per-encryptor entry point:
//
//   - Round-trip across the canonical MAC × hash-width matrix.
//   - Truncate-tail / cross-stream replay / prefix-tamper detection.
//   - Empty + single-chunk streams.
//   - Closed-state preflight after Close / Dispose.

using System.IO;

namespace Itb.Tests;

[Collection(TestCollections.GlobalState)]
public class EasyStreamsAuthTests
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

    private static (byte[] prefix, List<byte[]> chunks) SplitChunks(
        byte[] ct, int headerSize)
    {
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

    [Fact]
    public void TestDefaultConstructorRoundtrip()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 3 + 17);
        using var enc = new Encryptor("blake3", 1024, "hmac-blake3");
        var cbuf = new MemoryStream();
        enc.EncryptStreamAuth(new MemoryStream(plaintext), cbuf, SmallChunk);
        var ct = cbuf.ToArray();
        Assert.True(ct.Length > StreamIdLen);

        var pbuf = new MemoryStream();
        enc.DecryptStreamAuth(new MemoryStream(ct), pbuf, SmallChunk);
        Assert.Equal(plaintext, pbuf.ToArray());
    }

    [Fact]
    public void TestAllMacHashCombinationsSingle()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 2 + 9);
        foreach (var macName in CanonicalMacs)
        {
            foreach (var (hashName, _) in HashByWidth)
            {
                using var enc = new Encryptor(hashName, 1024, macName);
                var cbuf = new MemoryStream();
                enc.EncryptStreamAuth(new MemoryStream(plaintext), cbuf, SmallChunk);
                var pbuf = new MemoryStream();
                enc.DecryptStreamAuth(new MemoryStream(cbuf.ToArray()), pbuf, SmallChunk);
                Assert.Equal(plaintext, pbuf.ToArray());
            }
        }
    }

    [Fact]
    public void TestAllMacHashCombinationsTriple()
    {
        var plaintext = TestRng.Bytes(SmallChunk + 100);
        foreach (var macName in CanonicalMacs)
        {
            foreach (var (hashName, _) in HashByWidth)
            {
                using var enc = new Encryptor(hashName, 1024, macName, mode: "triple");
                var cbuf = new MemoryStream();
                enc.EncryptStreamAuth(new MemoryStream(plaintext), cbuf, SmallChunk);
                var pbuf = new MemoryStream();
                enc.DecryptStreamAuth(new MemoryStream(cbuf.ToArray()), pbuf, SmallChunk);
                Assert.Equal(plaintext, pbuf.ToArray());
            }
        }
    }

    [Fact]
    public void TestEmptyStream()
    {
        using var enc = new Encryptor("blake3", 1024, "hmac-blake3");
        var cbuf = new MemoryStream();
        enc.EncryptStreamAuth(new MemoryStream(Array.Empty<byte>()), cbuf, SmallChunk);
        var ct = cbuf.ToArray();
        Assert.True(ct.Length > StreamIdLen);

        var pbuf = new MemoryStream();
        enc.DecryptStreamAuth(new MemoryStream(ct), pbuf, SmallChunk);
        Assert.Equal(Array.Empty<byte>(), pbuf.ToArray());
    }

    [Fact]
    public void TestSingleChunkStream()
    {
        var plaintext = new byte[100];
        Array.Fill(plaintext, (byte)'x');
        using var enc = new Encryptor("blake3", 1024, "hmac-blake3");
        var cbuf = new MemoryStream();
        enc.EncryptStreamAuth(new MemoryStream(plaintext), cbuf, SmallChunk);
        var pbuf = new MemoryStream();
        enc.DecryptStreamAuth(new MemoryStream(cbuf.ToArray()), pbuf, SmallChunk);
        Assert.Equal(plaintext, pbuf.ToArray());
    }

    [Fact]
    public void TestTruncateTailDetected()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 2 + SmallChunk / 2);
        using var enc = new Encryptor("blake3", 1024, "hmac-blake3");
        var cbuf = new MemoryStream();
        enc.EncryptStreamAuth(new MemoryStream(plaintext), cbuf, SmallChunk);
        var ct = cbuf.ToArray();
        var (prefix, chunks) = SplitChunks(ct, enc.HeaderSize);
        Assert.True(chunks.Count >= 2);
        var truncated = new MemoryStream();
        truncated.Write(prefix, 0, prefix.Length);
        for (var i = 0; i < chunks.Count - 1; i++)
        {
            truncated.Write(chunks[i], 0, chunks[i].Length);
        }
        var pbuf = new MemoryStream();
        var ex = Assert.Throws<ItbStreamTruncatedException>(() =>
            enc.DecryptStreamAuth(new MemoryStream(truncated.ToArray()), pbuf, SmallChunk));
        Assert.Equal(StatusCode.StreamTruncated, ex.Status);
    }

    [Fact]
    public void TestAfterFinalDetected()
    {
        var plaintext = TestRng.Bytes(SmallChunk + 100);
        using var enc = new Encryptor("blake3", 1024, "hmac-blake3");
        var cbuf = new MemoryStream();
        enc.EncryptStreamAuth(new MemoryStream(plaintext), cbuf, SmallChunk);
        var ct = cbuf.ToArray();
        var (prefix, chunks) = SplitChunks(ct, enc.HeaderSize);
        var afterFinal = new MemoryStream();
        afterFinal.Write(prefix, 0, prefix.Length);
        foreach (var c in chunks) afterFinal.Write(c, 0, c.Length);
        afterFinal.Write(chunks[^1], 0, chunks[^1].Length);

        var pbuf = new MemoryStream();
        var ex = Assert.Throws<ItbStreamAfterFinalException>(() =>
            enc.DecryptStreamAuth(new MemoryStream(afterFinal.ToArray()), pbuf, SmallChunk));
        Assert.Equal(StatusCode.StreamAfterFinal, ex.Status);
    }

    [Fact]
    public void TestChunkReorderDetected()
    {
        var plaintext = TestRng.Bytes(SmallChunk * 2 + SmallChunk / 2);
        using var enc = new Encryptor("blake3", 1024, "hmac-blake3");
        var cbuf = new MemoryStream();
        enc.EncryptStreamAuth(new MemoryStream(plaintext), cbuf, SmallChunk);
        var ct = cbuf.ToArray();
        var (prefix, chunks) = SplitChunks(ct, enc.HeaderSize);
        Assert.True(chunks.Count >= 3);
        var tampered = new MemoryStream();
        tampered.Write(prefix, 0, prefix.Length);
        tampered.Write(chunks[1], 0, chunks[1].Length);
        tampered.Write(chunks[0], 0, chunks[0].Length);
        for (var i = 2; i < chunks.Count; i++) tampered.Write(chunks[i], 0, chunks[i].Length);

        var pbuf = new MemoryStream();
        var ex = Assert.Throws<ItbException>(() =>
            enc.DecryptStreamAuth(new MemoryStream(tampered.ToArray()), pbuf, SmallChunk));
        Assert.Equal(StatusCode.MacFailure, ex.Status);
    }

    [Fact]
    public void TestStreamPrefixTamperDetected()
    {
        var plaintext = TestRng.Bytes(SmallChunk + 200);
        using var enc = new Encryptor("blake3", 1024, "hmac-blake3");
        var cbuf = new MemoryStream();
        enc.EncryptStreamAuth(new MemoryStream(plaintext), cbuf, SmallChunk);
        var ct = cbuf.ToArray();
        ct[0] ^= 0x80;
        var pbuf = new MemoryStream();
        var ex = Assert.Throws<ItbException>(() =>
            enc.DecryptStreamAuth(new MemoryStream(ct), pbuf, SmallChunk));
        Assert.Equal(StatusCode.MacFailure, ex.Status);
    }

    // ----------------------------------------------------------------
    // Closed-state preflight.
    // ----------------------------------------------------------------

    [Fact]
    public void TestCallAfterCloseRaises()
    {
        var enc = new Encryptor("blake3", 1024, "hmac-blake3");
        enc.EncryptStreamAuth(
            new MemoryStream(System.Text.Encoding.UTF8.GetBytes("hello")),
            new MemoryStream(), SmallChunk);
        enc.Close();
        var ex = Assert.Throws<ItbException>(() =>
            enc.EncryptStreamAuth(
                new MemoryStream(System.Text.Encoding.UTF8.GetBytes("world")),
                new MemoryStream(), SmallChunk));
        Assert.Equal(StatusCode.EasyClosed, ex.Status);
    }

    [Fact]
    public void TestCallAfterDisposeRaises()
    {
        var enc = new Encryptor("blake3", 1024, "hmac-blake3");
        enc.EncryptStreamAuth(
            new MemoryStream(System.Text.Encoding.UTF8.GetBytes("hello")),
            new MemoryStream(), SmallChunk);
        enc.Dispose();
        var ex = Assert.Throws<ItbException>(() =>
            enc.DecryptStreamAuth(new MemoryStream(), new MemoryStream(), SmallChunk));
        Assert.Equal(StatusCode.EasyClosed, ex.Status);
    }

    [Fact]
    public void TestBadChunkSizeRejected()
    {
        using var enc = new Encryptor("blake3", 1024, "hmac-blake3");
        var ex = Assert.Throws<ItbException>(() =>
            enc.EncryptStreamAuth(new MemoryStream(new byte[1]), new MemoryStream(), chunkSize: -1));
        Assert.Equal(StatusCode.BadInput, ex.Status);
    }

    [Fact]
    public void TestBadReadSizeRejected()
    {
        using var enc = new Encryptor("blake3", 1024, "hmac-blake3");
        var ex = Assert.Throws<ItbException>(() =>
            enc.DecryptStreamAuth(new MemoryStream(new byte[1]), new MemoryStream(), readSize: -1));
        Assert.Equal(StatusCode.BadInput, ex.Status);
    }

    // ----------------------------------------------------------------
    // Subsequent calls — verify the encryptor is reusable.
    // ----------------------------------------------------------------

    [Fact]
    public void TestSubsequentCallsAfterStream()
    {
        using var enc = new Encryptor("blake3", 1024, "hmac-blake3");
        var cbuf = new MemoryStream();
        enc.EncryptStreamAuth(
            new MemoryStream(System.Text.Encoding.UTF8.GetBytes("first stream")),
            cbuf, SmallChunk);
        var cbuf2 = new MemoryStream();
        enc.EncryptStreamAuth(
            new MemoryStream(System.Text.Encoding.UTF8.GetBytes("second stream")),
            cbuf2, SmallChunk);
        var pbuf = new MemoryStream();
        enc.DecryptStreamAuth(new MemoryStream(cbuf2.ToArray()), pbuf, SmallChunk);
        Assert.Equal(System.Text.Encoding.UTF8.GetBytes("second stream"), pbuf.ToArray());
    }
}
