// Init -> Rekey -> Open receiver with the rotated blob -> round trip.

using System.Text;

namespace Itb.Tests;

public class RekeyTests
{
    [Fact]
    public void RekeyRoundTrip()
    {
        using var sender = Pipeline.Init("singlemsg-triple-mac-v1");
        var blobBefore = sender.Blob.ToArray();

        var perm = new byte[32];
        Array.Fill(perm, (byte)0x11);
        var wrap = new byte[32];
        Array.Fill(wrap, (byte)0x22);
        sender.Rekey(perm, wrap);
        Assert.False(sender.Blob.SequenceEqual(blobBefore));

        using var receiver = Pipeline.Open("singlemsg-triple-mac-v1", sender.Blob);
        var plain = Encoding.UTF8.GetBytes("post-rekey payload");
        var wire = sender.EncryptMessage(plain);
        Assert.Equal(plain, receiver.DecryptMessage(wire));
    }
}
