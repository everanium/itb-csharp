// EncryptMessage throughput vs plaintext size (Single Message
// profile) at 1 MiB / 16 MiB / 64 MiB.

using System.Security.Cryptography;

namespace Itb.Bench;

internal static class BenchMessage
{
    internal static void Run()
    {
        using var pipe = Pipeline.Init(
            BenchUtil.ProfileName("singlemsg-triple-nomac-v1"), BenchUtil.BuildOpts());
        BenchUtil.Header();
        foreach (var size in BenchUtil.Sizes)
        {
            var plain = new byte[size];
            // CSPRNG-fill so plaintext content matches the root Go
            // bench (crypto/rand). Not in the timing loop.
            RandomNumberGenerator.Fill(plain);
            BenchUtil.Case("message", size, () => pipe.EncryptMessage(plain));
            // Pre-encrypt one wire outside the decrypt timing loop.
            var decWire = pipe.EncryptMessage(plain);
            BenchUtil.Case("message-dec", size, () => pipe.DecryptMessage(decWire));
        }
    }
}
