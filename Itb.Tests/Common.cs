// Shared test infrastructure: a CollectionDefinition that disables
// xunit's per-class parallelisation across every test that touches
// process-global libitb state (BitSoup / LockSoup / NonceBits /
// MaxWorkers / BarrierFill), plus small helpers for test material
// generation.
//
// Tests that mutate libitb's process-global config MUST decorate the
// class with [Collection(TestCollections.GlobalState)] — that flag
// serialises them with every other class in the same collection.
// Test classes that do NOT touch globals run in parallel and need no
// collection attribute.
//
// In addition to the collection annotation, every test that mutates a
// global MUST save / restore the original value via try / finally so
// later tests see a clean process-global state. The collection-level
// serialisation prevents inter-class race; the save / restore prevents
// intra-class state leakage.

using System.Security.Cryptography;

namespace Itb.Tests;

/// <summary>
/// Names for xunit collections used to serialise tests that mutate
/// libitb's process-global configuration.
/// </summary>
public static class TestCollections
{
    public const string GlobalState = "ItbGlobalState";

    /// <summary>
    /// Serialisation token for tests that assert on
    /// <see cref="ItbEasyMismatchException.Field"/>.
    /// <c>ITB_Easy_LastMismatchField</c> is a process-wide atomic
    /// (documented in <see cref="ItbException"/>'s file header) — two
    /// import calls that fail concurrently on different fields can
    /// cross their published field-name strings between the two
    /// exceptions. Test classes that read <c>.Field</c> opt in via
    /// <c>[Collection(TestCollections.MismatchField)]</c> so the read
    /// returns the value libitb published for the test's own failing
    /// call, not for a sibling test's. The collection is independent
    /// of <see cref="GlobalState"/> so field-asserting tests do not
    /// serialise against the unrelated process-global state setters.
    /// </summary>
    public const string MismatchField = "ItbMismatchField";
}

/// <summary>
/// Empty marker class that carries the
/// <see cref="CollectionDefinitionAttribute"/>. Test classes opt in via
/// <c>[Collection(TestCollections.GlobalState)]</c>.
/// </summary>
[CollectionDefinition(TestCollections.GlobalState, DisableParallelization = true)]
public sealed class GlobalStateCollection
{
}

/// <summary>
/// Empty marker class for the <see cref="TestCollections.MismatchField"/>
/// serialisation token. See <see cref="TestCollections.MismatchField"/>
/// for the rationale.
/// </summary>
[CollectionDefinition(TestCollections.MismatchField, DisableParallelization = true)]
public sealed class MismatchFieldCollection
{
}

/// <summary>
/// Test-material generator. Mirrors the Python suite's reliance on
/// <c>secrets.token_bytes</c> — uses .NET's CSPRNG-backed
/// <see cref="RandomNumberGenerator"/> directly. No new package
/// dependency is introduced.
/// </summary>
public static class TestRng
{
    public static byte[] Bytes(int length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }
        if (length == 0)
        {
            return Array.Empty<byte>();
        }
        var buf = new byte[length];
        RandomNumberGenerator.Fill(buf);
        return buf;
    }

    public static ulong[] U64s(int length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }
        if (length == 0)
        {
            return Array.Empty<ulong>();
        }
        var bytes = new byte[length * 8];
        RandomNumberGenerator.Fill(bytes);
        var result = new ulong[length];
        for (var i = 0; i < length; i++)
        {
            result[i] =
                (ulong)bytes[i * 8 + 0]
                | ((ulong)bytes[i * 8 + 1] << 8)
                | ((ulong)bytes[i * 8 + 2] << 16)
                | ((ulong)bytes[i * 8 + 3] << 24)
                | ((ulong)bytes[i * 8 + 4] << 32)
                | ((ulong)bytes[i * 8 + 5] << 40)
                | ((ulong)bytes[i * 8 + 6] << 48)
                | ((ulong)bytes[i * 8 + 7] << 56);
        }
        return result;
    }
}

/// <summary>
/// Helpers for snapshotting and restoring libitb's process-global
/// configuration around a test that mutates one or more globals. Use
/// in tandem with <see cref="GlobalStateCollection"/> to keep
/// process-wide state clean across the suite.
/// </summary>
public readonly struct GlobalStateSnapshot : IDisposable
{
    private readonly int _bitSoup;
    private readonly int _lockSoup;
    private readonly int _maxWorkers;
    private readonly int _nonceBits;
    private readonly int _barrierFill;

    public static GlobalStateSnapshot Capture()
    {
        return new GlobalStateSnapshot(
            Library.BitSoup,
            Library.LockSoup,
            Library.MaxWorkers,
            Library.NonceBits,
            Library.BarrierFill);
    }

    private GlobalStateSnapshot(int bitSoup, int lockSoup, int maxWorkers, int nonceBits, int barrierFill)
    {
        _bitSoup = bitSoup;
        _lockSoup = lockSoup;
        _maxWorkers = maxWorkers;
        _nonceBits = nonceBits;
        _barrierFill = barrierFill;
    }

    public void Dispose()
    {
        Library.BitSoup = _bitSoup;
        Library.LockSoup = _lockSoup;
        Library.MaxWorkers = _maxWorkers;
        Library.NonceBits = _nonceBits;
        Library.BarrierFill = _barrierFill;
    }
}
