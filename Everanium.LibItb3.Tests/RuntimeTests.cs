// Runtime diagnostics surface: GOMAXPROCS query / set / restore, the
// heap-profile writer, the pool-counter snapshot and its slot layout,
// the hash-registry enumeration and the auto DRBG tier report.

namespace Everanium.Itb3.Tests;

public class RuntimeTests
{
    [Fact]
    public void GomaxprocsQuerySetRestore()
    {
        int orig = Runtime.SetGOMAXPROCS(0);
        Assert.True(orig > 0);
        Assert.Equal(orig, Runtime.SetGOMAXPROCS(-3));
        Assert.Equal(orig, Runtime.SetGOMAXPROCS(orig + 1));
        Assert.Equal(orig + 1, Runtime.SetGOMAXPROCS(0));
        Assert.Equal(orig + 1, Runtime.SetGOMAXPROCS(orig));
    }

    [Fact]
    public void HeapProfileWrittenAndEmptyPathRejected()
    {
        string dir = Path.Combine(
            Path.GetTempPath(),
            $"itb-loop-test-heap-{Environment.ProcessId}");
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "heap.prof");
        Runtime.WriteHeapProfile(path);
        Assert.True(new FileInfo(path).Length > 0);
        Directory.Delete(dir, recursive: true);

        // The empty path falls back to ITB_MEMPROFILE inside libitb3;
        // with the variable clear there is nothing to fall back to.
        Environment.SetEnvironmentVariable("ITB_MEMPROFILE", null);
        var ex = Assert.Throws<ItbException>(() => Runtime.WriteHeapProfile(""));
        Assert.Equal(Status.BadInput, ex.Status);
    }

    [Fact]
    public void PoolStatsLayout()
    {
        int len = Runtime.PoolStatsLen();
        Assert.True(len >= 9);
        long[] v = Runtime.PoolStats();
        Assert.Equal(len, v.Length);
        long tiers = v[0];
        Assert.True(tiers > 0);
        Assert.Equal(1 + 5 * tiers + 8, len);
    }

    [Fact]
    public void HashNamesCanonical()
    {
        string[] names = Pipeline.HashNames();
        Assert.Equal("aesitb128", names[0]);
        Assert.Contains("areion512", names);
    }

    [Fact]
    public void DrbgAutoTierIsAFillCipher()
    {
        Assert.Contains(Runtime.DrbgAutoTier(), new[] { "aes-256-ctr", "chacha20" });
    }
}
