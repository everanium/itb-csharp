// Tests for the low-level Seed.AttachLockSeed mutator.
//
// Mirrors bindings/python/tests/test_attach_lock_seed.py — covers the
// happy-path round trip with the bit-permutation overlay engaged, the
// cross-process persistence path (export components + hash key,
// rebuild via Seed.FromComponents, reattach a fresh lockSeed), and
// the three misuse-rejection paths (self-attach, post-encrypt switch,
// width mismatch) plus the overlay-off panic guard.
//
// Tests in this file mutate Library.BitSoup / Library.LockSoup, so
// the class is decorated with [Collection(TestCollections.GlobalState)]
// and every mutation is bracketed by GlobalStateSnapshot.Capture() to
// keep later tests insulated from leftover state.

namespace Itb.Tests;

[Collection(TestCollections.GlobalState)]
public class TestAttachLockSeed
{
    /// <summary>
    /// Sets <c>Library.LockSoup = 1</c> for the body. Restores both
    /// flags on exit. Mirrors <c>lock_soup_on</c> from
    /// <c>test_attach_lock_seed.py</c>.
    /// </summary>
    private static void WithLockSoupOn(Action body)
    {
        using var snap = GlobalStateSnapshot.Capture();
        Library.LockSoup = 1;
        body();
    }

    [Fact]
    public void TestRoundtrip()
    {
        WithLockSoupOn(() =>
        {
            var plaintext = new byte[]
            {
                0x61, 0x74, 0x74, 0x61, 0x63, 0x68, 0x5f, 0x6c, 0x6f, 0x63, 0x6b,
                0x5f, 0x73, 0x65, 0x65, 0x64, 0x20, 0x72, 0x6f, 0x75, 0x6e, 0x64,
                0x74, 0x72, 0x69, 0x70, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
            };
            using var ns = new Seed("blake3", 1024);
            using var ds = new Seed("blake3", 1024);
            using var ss = new Seed("blake3", 1024);
            using var ls = new Seed("blake3", 1024);
            ns.AttachLockSeed(ls);
            var ct = Cipher.Encrypt(ns, ds, ss, plaintext);
            var pt = Cipher.Decrypt(ns, ds, ss, ct);
            Assert.Equal(plaintext, pt);
        });
    }

    [Fact]
    public void TestPersistence()
    {
        WithLockSoupOn(() =>
        {
            var plaintext = TestRng.Bytes(64);

            // Day 1 — sender.
            ulong[] nsComps, dsComps, ssComps, lsComps;
            byte[] nsKey, dsKey, ssKey, lsKey;
            byte[] ct;
            using (var ns = new Seed("blake3", 1024))
            using (var ds = new Seed("blake3", 1024))
            using (var ss = new Seed("blake3", 1024))
            using (var ls = new Seed("blake3", 1024))
            {
                ns.AttachLockSeed(ls);
                nsComps = ns.GetComponents();
                dsComps = ds.GetComponents();
                ssComps = ss.GetComponents();
                lsComps = ls.GetComponents();
                nsKey = ns.GetHashKey();
                dsKey = ds.GetHashKey();
                ssKey = ss.GetHashKey();
                lsKey = ls.GetHashKey();
                ct = Cipher.Encrypt(ns, ds, ss, plaintext);
            }

            // Day 2 — receiver.
            using var ns2 = Seed.FromComponents("blake3", nsComps, nsKey);
            using var ds2 = Seed.FromComponents("blake3", dsComps, dsKey);
            using var ss2 = Seed.FromComponents("blake3", ssComps, ssKey);
            using var ls2 = Seed.FromComponents("blake3", lsComps, lsKey);
            ns2.AttachLockSeed(ls2);
            var pt = Cipher.Decrypt(ns2, ds2, ss2, ct);
            Assert.Equal(plaintext, pt);
        });
    }

    [Fact]
    public void TestSelfAttachRejected()
    {
        using var ns = new Seed("blake3", 1024);
        var ex = Assert.Throws<ItbException>(() => ns.AttachLockSeed(ns));
        Assert.Equal(Native.Status.BadInput, ex.Status);
    }

    [Fact]
    public void TestWidthMismatchRejected()
    {
        using var ns256 = new Seed("blake3", 1024);    // width 256
        using var ls128 = new Seed("siphash24", 1024); // width 128
        var ex = Assert.Throws<ItbException>(() => ns256.AttachLockSeed(ls128));
        Assert.Equal(Native.Status.SeedWidthMix, ex.Status);
    }

    [Fact]
    public void TestPostEncryptAttachRejected()
    {
        WithLockSoupOn(() =>
        {
            using var ns = new Seed("blake3", 1024);
            using var ds = new Seed("blake3", 1024);
            using var ss = new Seed("blake3", 1024);
            using var ls = new Seed("blake3", 1024);
            ns.AttachLockSeed(ls);
            // Encrypt once — locks future AttachLockSeed calls on ns.
            Cipher.Encrypt(ns, ds, ss, new byte[]
            {
                0x70, 0x72, 0x65, 0x2d, 0x73, 0x77, 0x69, 0x74, 0x63, 0x68,
            });
            using var ls2 = new Seed("blake3", 1024);
            var ex = Assert.Throws<ItbException>(() => ns.AttachLockSeed(ls2));
            Assert.Equal(Native.Status.BadInput, ex.Status);
        });
    }

    // Skipped — the Python `test_type_check` covers the TypeError path
    // when a non-Seed instance is passed. C# rejects this at compile
    // time via the typed `Seed lockSeed` parameter; runtime test
    // unnecessary.

    [Fact]
    public void TestOverlayOffPanicsOnEncrypt()
    {
        // Without either BitSoup or LockSoup engaged, the build-PRF
        // guard inside the Go-side dispatch panics on encrypt-time,
        // surfacing as ItbException. Regression-pin for the
        // overlay-off action-at-a-distance bug — the silent no-op is
        // replaced by a loud failure.
        using var snap = GlobalStateSnapshot.Capture();
        Library.BitSoup = 0;
        Library.LockSoup = 0;
        using var ns = new Seed("blake3", 1024);
        using var ds = new Seed("blake3", 1024);
        using var ss = new Seed("blake3", 1024);
        using var ls = new Seed("blake3", 1024);
        ns.AttachLockSeed(ls);
        Assert.Throws<ItbException>(() =>
            Cipher.Encrypt(ns, ds, ss, new byte[]
            {
                0x6f, 0x76, 0x65, 0x72, 0x6c, 0x61, 0x79, 0x20, 0x6f, 0x66, 0x66,
            }));
    }
}
