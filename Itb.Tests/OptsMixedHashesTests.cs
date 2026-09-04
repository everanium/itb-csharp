// Per-call constellation override via the typed WithInnerHashes
// helper: register a base width-512 profile, then Init / Open with
// an 8-entry width-512 alternate constellation and round-trip a
// Single Message.

using System.Text;

namespace Itb.Tests;

public class OptsMixedHashesTests
{
    [Fact]
    public void TypedInnerHashesOverridesTheProfileConstellation()
    {
        // Base profile is a shipped single-primitive width-512
        // Single Message profile; the per-call WithInnerHashes
        // override rebinds all 8 slots to an alternate width-512
        // constellation for one Pipeline pair without touching the
        // shipped registry.
        var over = new Opts().WithInnerHashes(
            "areion512", "blake2b512", "areion512", "blake2b512",
            "areion512", "blake2b512", "areion512", "blake2b512");
        using var sender = Pipeline.Init("singlemsg-triple-mac-v1", over);
        using var receiver = Pipeline.Load(sender.Save());
        var plain = Encoding.UTF8.GetBytes(
            "mixed-hashes typed override round trip");
        var wire = sender.EncryptMessage(plain);
        Assert.Equal(plain, receiver.DecryptMessage(wire));
    }
}
