// Stream-pump throughput vs plaintext size (Streaming Non-AEAD
// profile) at 1 MiB / 16 MiB / 64 MiB.

using System.Security.Cryptography;

namespace Itb.Bench;

internal static class BenchStream
{
    internal static void Run()
    {
        using var pipe = Pipeline.Init(
            BenchUtil.ProfileName("streaming-noaead-triple-v1"), BenchUtil.BuildOpts());
        BenchUtil.Header();
        foreach (var size in BenchUtil.Sizes)
        {
            var plain = new byte[size];
            // CSPRNG-fill so plaintext content matches the root Go
            // bench (crypto/rand). Not in the timing loop.
            RandomNumberGenerator.Fill(plain);
            BenchUtil.Case("stream_pump", size, () =>
            {
                var wire = new MemoryStream(size + size / 4 + 131_072);
                pipe.EncryptStreamPump(new MemoryStream(plain, writable: false), wire);
            });
            // Pre-encrypt one wire outside the decrypt timing loop.
            var setupWire = new MemoryStream(size + size / 4 + 131_072);
            pipe.EncryptStreamPump(new MemoryStream(plain, writable: false), setupWire);
            var decWire = setupWire.ToArray();
            BenchUtil.Case("stream_pump-dec", size, () =>
            {
                var outbuf = new MemoryStream(size + 131_072);
                pipe.DecryptStreamPump(new MemoryStream(decWire, writable: false), outbuf);
            });
        }
    }
}
