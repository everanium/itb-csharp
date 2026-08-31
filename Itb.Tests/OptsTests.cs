// Query-string rendering of the Opts builder (no FFI involved).

namespace Itb.Tests;

public class OptsTests
{
    [Fact]
    public void TypedSettersRenderExpectedKeys()
    {
        var query = new Opts()
            .WithPermMaster(new byte[] { 0xab, 0x01 })
            .WithWrapMaster(new byte[] { 0xcd, 0xef })
            .WithParallax(true)
            .WithWrapper(false)
            .WithMaxWorkers(4)
            .WithNonceBits(512)
            .WithBarrierFill(4)
            .WithChunkSize(4096)
            .WithKeyBits(1024)
            .WithParallaxSegmentSize(65536)
            .WithMacName("hmac-blake3")
            .WithInnerHash("areion512")
            .WithOuterCipher("chacha20")
            .WithParallaxPalette("aescmac", "chacha20", "blake3")
            .Build();
        Assert.Equal(
            "pm=ab01&wm=cdef&withParallax=true&withWrapper=false&" +
            "maxWorkers=4&nonceBits=512&barrierFill=4&chunkSize=4096&" +
            "keyBits=1024&parallaxSegmentSize=65536&macName=hmac-blake3&" +
            "innerHash=areion512&outerCipher=chacha20&" +
            "parallaxPalette=aescmac,chacha20,blake3",
            query);
    }

    [Fact]
    public void RawEscapeHatchAndEncoding()
    {
        var query = new Opts().WithRaw("mode", "a b&c=d%").Build();
        Assert.Equal("mode=a%20b%26c%3Dd%25", query);
    }

    [Fact]
    public void EmptyBuilderRendersEmptyQuery()
    {
        Assert.Equal(string.Empty, new Opts().Build());
    }

    [Fact]
    public void TypedInnerHashesRendersInnerHashesKey()
    {
        // Typed setter for the per-call constellation override
        // (innerHashes) renders as the same query-string key that
        // the raw escape hatch produces.
        var query = new Opts()
            .WithInnerHashes(
                "blake3", "blake2s", "areion256", "blake2b256",
                "chacha20", "blake3", "blake2s", "areion256")
            .Build();
        Assert.Equal(
            "innerHashes=blake3,blake2s,areion256,blake2b256,chacha20," +
            "blake3,blake2s,areion256",
            query);
    }
}
