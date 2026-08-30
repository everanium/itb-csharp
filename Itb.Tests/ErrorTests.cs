// Error-mapping surface: opaque-string relay, closed Pipeline,
// duplicate profile registration (with an 8-entry innerHashes
// constellation).

using System.Text;

namespace Itb.Tests;

public class ErrorTests
{
    [Fact]
    public void UnknownProfileIsBadInputWithDiagnostic()
    {
        var ex = Assert.Throws<ItbException>(() => Pipeline.Init("no-such-profile"));
        Assert.Equal(Status.BadInput, ex.Status);
        Assert.False(string.IsNullOrEmpty(ex.Message));
    }

    [Fact]
    public void UnknownOptsKeyIsBadInput()
    {
        // Typoed key (lowercase s) — Go rejects unknown keys.
        var opts = new Opts().WithRaw("chunksize", "4096");
        var ex = Assert.Throws<ItbException>(
            () => Pipeline.Init("singlemsg-triple-mac-v1", opts));
        Assert.Equal(Status.BadInput, ex.Status);
    }

    [Fact]
    public void ClosedPipelineReportsTripleClosed()
    {
        using var pipe = Pipeline.Init("singlemsg-triple-mac-v1");
        pipe.Close();
        pipe.Close(); // idempotent
        var ex = Assert.Throws<ItbException>(
            () => pipe.EncryptMessage(Encoding.UTF8.GetBytes("payload")));
        Assert.Equal(Status.TripleClosed, ex.Status);
    }

    [Fact]
    public void RegisterProfileMixedThenDuplicate()
    {
        // 8-entry width-256 innerHashes constellation, layers off.
        var opts = new Opts()
            .WithRaw("mode", "singlemsg-nomac")
            .WithRaw("width", "256")
            .WithRaw(
                "innerHashes",
                "blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256")
            .WithRaw("keyBits", "1024")
            .WithRaw("parallaxOn", "false")
            .WithRaw("wrapperOn", "false");
        Pipeline.RegisterProfile("csharp-binding-test-mixed", opts);

        // The registered profile round-trips.
        using var sender = Pipeline.Init("csharp-binding-test-mixed");
        using var receiver = Pipeline.Open("csharp-binding-test-mixed", sender.Blob);
        var plain = Encoding.UTF8.GetBytes("custom profile");
        var wire = sender.EncryptMessage(plain);
        Assert.Equal(plain, receiver.DecryptMessage(wire));

        // Duplicate name is a distinct status.
        var ex = Assert.Throws<ItbException>(
            () => Pipeline.RegisterProfile("csharp-binding-test-mixed", opts));
        Assert.Equal(Status.ProfileExists, ex.Status);
    }

    [Fact]
    public void OpaquePrimitiveNameRelay()
    {
        // An unknown inner-hash name is relayed to Go and rejected
        // there — the binding performs no name validation of its own.
        var opts = new Opts().WithInnerHash("no-such-hash");
        var ex = Assert.Throws<ItbException>(
            () => Pipeline.Init("singlemsg-triple-mac-v1", opts));
        Assert.NotEqual(Status.Ok, ex.Status);
    }
}
