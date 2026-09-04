// Session persistence surface: Save / Load, SaveF / LoadF, Inspect,
// Lookup / Profiles / Register round trip, MaxWorkers clamping.

using System.Text;

namespace Itb.Tests;

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
        Assert.Equal(Pipeline.Lookup("streaming-aead-triple-mac-v1"), prof);
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
