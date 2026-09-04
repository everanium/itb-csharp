// Init -> Save -> Load -> EncryptMessage -> DecryptMessage round trip.

using System.Text;

namespace Itb.Tests;

public class SmokeTests
{
    [Fact]
    public void SmokeRoundTrip()
    {
        using var sender = Pipeline.Init("singlemsg-triple-mac-v1");
        Assert.NotEmpty(sender.Save());

        using var receiver = Pipeline.Load(sender.Save());

        var plain = Encoding.UTF8.GetBytes("smoke round-trip payload");
        var wire = sender.EncryptMessage(plain);
        Assert.NotEqual(plain, wire);

        var back = receiver.DecryptMessage(wire);
        Assert.Equal(plain, back);
    }
}
