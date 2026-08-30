// Whole-buffer Stream throughput vs plaintext size (Streaming
// Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Times
// EncryptStreamOneShot / DecryptStreamOneShot, the single FFI
// round-trip surface for callers holding the whole payload in
// memory.

using System.Security.Cryptography;

namespace Itb.Bench;

internal static class BenchStreamOneShot
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
            BenchUtil.Case("stream_one_shot", size, () =>
            {
                pipe.EncryptStreamOneShot(plain);
            });
            // Pre-encrypt one wire outside the decrypt timing loop.
            var decWire = pipe.EncryptStreamOneShot(plain);
            BenchUtil.Case("stream_one_shot-dec", size, () =>
            {
                pipe.DecryptStreamOneShot(decWire);
            });
        }
    }
}
