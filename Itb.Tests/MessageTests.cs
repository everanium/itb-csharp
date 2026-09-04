// Single Message round trip across every shipped cipher profile at
// small (4 KiB) and medium (256 KiB) payloads. The blob-only profile
// has no cipher surface and is exercised in ErrorTests instead.

namespace Itb.Tests;

public class MessageTests
{
    /// <summary>Deterministic non-trivial payload (xorshift
    /// fill).</summary>
    internal static byte[] Payload(int n, ulong seed)
    {
        var buf = new byte[n];
        ulong x = seed | 1;
        for (int i = 0; i < n; i++)
        {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            buf[i] = (byte)x;
        }
        return buf;
    }

    [Fact]
    public void MessageRoundTripEveryProfile()
    {
        string[] profiles =
        [
            "streaming-aead-triple-mac-v1",
            "streaming-noaead-triple-v1",
            "singlemsg-triple-mac-v1",
            "singlemsg-triple-nomac-v1",
            "streaming-aead-triple-mac-mixed-v1",
            "streaming-noaead-triple-mixed-v1",
            "singlemsg-triple-mac-mixed-v1",
            "singlemsg-triple-nomac-mixed-v1",
        ];
        foreach (var profile in profiles)
        {
            using var sender = Pipeline.Init(profile);
            using var receiver = Pipeline.Load(sender.Save());
            foreach (var size in new[] { 4 * 1024, 256 * 1024 })
            {
                var plain = Payload(size, (ulong)size);
                var wire = sender.EncryptMessage(plain);
                var back = receiver.DecryptMessage(wire);
                Assert.Equal(plain, back);
            }
        }
    }
}
