// Disposing an encrypt session mid-flight cleans up and leaves the
// Pipeline usable.

using System.Text;

namespace Itb.Tests;

public class StreamCancelTests
{
    [Fact]
    public void DisposeMidFlightThenReusePipeline()
    {
        using var sender = Pipeline.Init("streaming-aead-triple-mac-v1");

        using (var session = sender.BeginEncryptStream())
        {
            var block = new byte[100_000];
            Array.Fill(block, (byte)0xA5);
            session.Write(block);
            // Disposed here without End() — Dispose cancels and frees
            // the session; the test passing (process not hanging) is
            // the assertion.
        }

        // The Pipeline stays usable after the cancelled session.
        using var receiver = Pipeline.Open("streaming-aead-triple-mac-v1", sender.Blob);
        var plain = Encoding.UTF8.GetBytes("after cancel");
        var wire = sender.EncryptMessage(plain);
        Assert.Equal(plain, receiver.DecryptMessage(wire));
    }
}
