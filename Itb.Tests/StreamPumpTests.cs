// Round trip through the stream pumps on a Streaming AEAD profile.

namespace Itb.Tests;

public class StreamPumpTests
{
    [Fact]
    public void PumpRoundTrip1MiB()
    {
        using var sender = Pipeline.Init("streaming-aead-triple-mac-v1");
        using var receiver = Pipeline.Open("streaming-aead-triple-mac-v1", sender.Blob);

        var plain = new byte[1 << 20];
        for (int i = 0; i < plain.Length; i++)
        {
            plain[i] = (byte)(i % 251);
        }

        using var wire = new MemoryStream();
        sender.EncryptStreamPump(new MemoryStream(plain, writable: false), wire);
        Assert.True(wire.Length > 0);

        using var back = new MemoryStream();
        receiver.DecryptStreamPump(new MemoryStream(wire.ToArray(), writable: false), back);
        Assert.Equal(plain, back.ToArray());
    }

    [Fact]
    public void PumpMatchesOneShot()
    {
        using var sender = Pipeline.Init("streaming-aead-triple-mac-v1");
        using var receiver = Pipeline.Open("streaming-aead-triple-mac-v1", sender.Blob);

        var plain = new byte[65_536];
        for (int i = 0; i < plain.Length; i++)
        {
            plain[i] = (byte)(i % 199);
        }
        var wire = sender.EncryptStreamOneShot(plain);

        using var back = new MemoryStream();
        receiver.DecryptStreamPump(new MemoryStream(wire, writable: false), back);
        Assert.Equal(plain, back.ToArray());

        var back2 = receiver.DecryptStreamOneShot(wire);
        Assert.Equal(plain, back2);
    }
}
