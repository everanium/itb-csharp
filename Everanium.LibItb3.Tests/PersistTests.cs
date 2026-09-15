// Session persistence surface: Save / Load, SaveF / LoadF, Inspect,
// Lookup / Profiles / Register round trip, MaxWorkers clamping.

using System.Text;

namespace Everanium.Itb3.Tests;

public class PersistTests
{
    private static readonly byte[] Plain = Encoding.UTF8.GetBytes("persisted session payload");

    [Fact]
    public void SaveThenLoadRoundTrip()
    {
        using var sender = Pipeline.Init("singlemsg-triple-mac-v1");
        var blob = sender.Save();
        Assert.NotEmpty(blob);
        Assert.Equal(blob, sender.Save());
        using var receiver = Pipeline.Load(blob);
        Assert.Equal(blob, receiver.Save());
        Assert.Equal(Plain, receiver.DecryptMessage(sender.EncryptMessage(Plain)));
    }

    [Fact]
    public void SaveFThenLoadFRoundTrip()
    {
        var dir = Directory.CreateTempSubdirectory("itb-csharp-");
        try
        {
            var file = Path.Combine(dir.FullName, "session.blob");
            using var sender = Pipeline.Init("streaming-aead-triple-mac-v1");
            sender.SaveF(file);
            Assert.Equal(sender.Save(), File.ReadAllBytes(file));
            using var receiver = Pipeline.LoadF(file);
            Assert.Equal(Plain, receiver.DecryptStreamOneShot(sender.EncryptStreamOneShot(Plain)));
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }

    [Fact]
    public void LoadWithMasterOverride()
    {
        var perm = new byte[32];
        Array.Fill(perm, (byte)0x33);
        var wrap = new byte[32];
        Array.Fill(wrap, (byte)0x44);
        using var sender = Pipeline.Init("singlemsg-triple-mac-v1");
        var blob = sender.Save();
        var rotated = sender.Rekey(perm, wrap);
        Assert.NotEqual(blob, rotated);
        Assert.Equal(rotated, sender.Save());
        using var receiver = Pipeline.Load(blob, perm, wrap);
        Assert.Equal(Plain, receiver.DecryptMessage(sender.EncryptMessage(Plain)));
    }

    [Fact]
    public void InspectReadsTheEmbeddedRecord()
    {
        using var pipe = Pipeline.Init("streaming-aead-triple-mac-v1");
        var prof = Pipeline.Inspect(pipe.Save());
        Assert.Equal("streaming-aead-triple-mac-v1", prof.Name);
        Assert.Equal("streaming-aead", prof.Mode);
        Assert.Equal(512, prof.Width);
        // The recipe fields match the registry entry; the two
        // inspection-only fields separate the two records.
        var recipe = prof.Clone();
        recipe.NonceBits = null;
        recipe.BarrierFill = null;
        Assert.Equal(Pipeline.Lookup("streaming-aead-triple-mac-v1"), recipe);
    }

    [Fact]
    public void InspectCarriesTheRuntimeGlobalsLookupDoesNot()
    {
        // Defaults: the blob records the compile-in nonce width and
        // barrier fill margin, and Inspect surfaces both.
        using (var pipe = Pipeline.Init("streaming-aead-triple-mac-v1"))
        {
            var prof = Pipeline.Inspect(pipe.Save());
            Assert.Equal(512, prof.NonceBits);
            Assert.Equal(1, prof.BarrierFill);
        }

        // Per-Pipeline overrides travel through the blob into Inspect.
        var opts = new Opts().WithNonceBits(256).WithBarrierFill(4);
        using (var pipe = Pipeline.Init("streaming-aead-triple-mac-v1", opts))
        {
            var prof = Pipeline.Inspect(pipe.Save());
            Assert.Equal(256, prof.NonceBits);
            Assert.Equal(4, prof.BarrierFill);
            Assert.Contains("\"nonce_bits\":256", prof.ToJson());
            Assert.Contains("\"barrier_fill\":4", prof.ToJson());
            // Clone round-trips the two fields rather than dropping them.
            Assert.Equal(256, prof.Clone().NonceBits);
            Assert.Equal(4, Profile.FromJson(prof.ToJson()).BarrierFill);
        }

        // The registry entry is the recipe alone — neither field is
        // part of it, so both read as absent rather than as zero.
        var registry = Pipeline.Lookup("streaming-aead-triple-mac-v1");
        Assert.Null(registry.NonceBits);
        Assert.Null(registry.BarrierFill);
        Assert.DoesNotContain("nonce_bits", registry.ToJson());
        Assert.DoesNotContain("barrier_fill", registry.ToJson());
    }

    [Fact]
    public void ProfilesListsTheCatalogue()
    {
        var names = Pipeline.Profiles();
        Assert.Contains("singlemsg-triple-mac-v1", names);
        Assert.Contains("streaming-aead-triple-mac-v1", names);
    }

    [Fact]
    public void RegisterCopyOfShippedProfile()
    {
        var copy = Pipeline.Lookup("singlemsg-triple-nomac-v1");
        copy.Name = "";
        Pipeline.Register("csharp-binding-test-copy", copy);
        var back = Pipeline.Lookup("csharp-binding-test-copy");
        Assert.Equal("csharp-binding-test-copy", back.Name);
        Assert.Equal(copy.Mode, back.Mode);
        Assert.Contains("csharp-binding-test-copy", Pipeline.Profiles());
        using var sender = Pipeline.Init("csharp-binding-test-copy");
        using var receiver = Pipeline.Load(sender.Save());
        Assert.Equal(Plain, receiver.DecryptMessage(sender.EncryptMessage(Plain)));
    }

    [Fact]
    public void ProfileJsonCodecRoundTrips()
    {
        var p = Pipeline.Lookup("streaming-aead-triple-mac-mixed-v1");
        Assert.Equal(8, p.Hashes.Length);
        Assert.Equal(p, Profile.FromJson(p.ToJson()));
    }

    [Fact]
    public void MaxWorkersClamps()
    {
        using var pipe = Pipeline.Init("singlemsg-triple-mac-v1", new Opts().WithMaxWorkers(-1));
        pipe.MaxWorkers(2);
        pipe.MaxWorkers(-1);
        pipe.MaxWorkers(1000);
        Assert.Equal(Plain, pipe.DecryptMessage(pipe.EncryptMessage(Plain)));
    }
}
