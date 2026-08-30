// Explicit Write / End / Read round trip with pathological batch
// sizes (17-byte feed, 23-byte drain) across multiple chunks.

namespace Itb.Tests;

public class StreamIncrementalTests
{
    [Fact]
    public void IncrementalTinyBatches()
    {
        // Small chunk size so the 64 KiB payload spans many chunks.
        var opts = new Opts().WithChunkSize(4096);
        using var sender = Pipeline.Init("streaming-aead-triple-mac-v1", opts);
        using var receiver = Pipeline.Open("streaming-aead-triple-mac-v1", sender.Blob, opts);

        var plain = new byte[65_536];
        for (int i = 0; i < plain.Length; i++)
        {
            plain[i] = (byte)(i % 241);
        }

        // Encrypt: 17-byte writes, then End + 23-byte drains.
        byte[] wire;
        using (var session = sender.BeginEncryptStream())
        {
            for (int off = 0; off < plain.Length; off += 17)
            {
                session.Write(plain.AsSpan(off, Math.Min(17, plain.Length - off)));
            }
            session.End();
            using var spool = new MemoryStream();
            var buf = new byte[23];
            while (true)
            {
                int n = session.Read(buf, out bool finished);
                spool.Write(buf, 0, n);
                if (finished)
                {
                    break;
                }
            }
            wire = spool.ToArray();
        }
        Assert.True(wire.Length > 0);

        // Decrypt with the same pathological batch sizes.
        byte[] back;
        using (var session = receiver.BeginDecryptStream())
        {
            for (int off = 0; off < wire.Length; off += 17)
            {
                session.Write(wire.AsSpan(off, Math.Min(17, wire.Length - off)));
            }
            session.End();
            using var spool = new MemoryStream();
            var buf = new byte[23];
            while (true)
            {
                int n = session.Read(buf, out bool finished);
                spool.Write(buf, 0, n);
                if (finished)
                {
                    break;
                }
            }
            back = spool.ToArray();
        }
        Assert.Equal(plain, back);
    }
}
