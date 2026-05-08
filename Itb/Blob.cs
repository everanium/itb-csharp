// Native-Blob wrapper over the libitb C ABI.
//
// Mirrors the github.com/everanium/itb Blob128 / Blob256 / Blob512 Go
// types: a width-specific container that packs the low-level encryptor
// material (per-seed hash key + components + optional dedicated
// lockSeed + optional MAC key + name) plus the captured process-wide
// configuration into one self-describing JSON blob. Intended for the
// low-level encrypt / decrypt path where each seed slot may carry a
// different primitive — the high-level <see cref="Encryptor"/> wraps a
// narrower one-primitive-per-encryptor surface.
//
// The blob is mode-discriminated: <see cref="Blob128.Export"/> /
// <see cref="Blob256.Export"/> / <see cref="Blob512.Export"/> pack Single
// Ouroboros material, the <c>ExportTriple</c> counterparts pack Triple
// Ouroboros material; <see cref="Blob128.Import"/> and
// <see cref="Blob128.ImportTriple"/> are the corresponding receivers.
// A blob built under one mode rejects the wrong importer with
// <see cref="ItbBlobModeMismatchException"/>.
//
// Globals (NonceBits / BarrierFill / BitSoup / LockSoup) are captured
// into the blob at export time and applied process-wide on import via
// the existing <see cref="Library.NonceBits"/> / <see cref="Library.BarrierFill"/>
// / <see cref="Library.BitSoup"/> / <see cref="Library.LockSoup"/> setters.
// The worker count and the global LockSeed flag are not serialised —
// the former is a deployment knob, the latter is irrelevant on the
// native path which consults <see cref="Seed.AttachLockSeed"/> directly.

using Itb.Native;

namespace Itb;

/// <summary>
/// Slot identifiers for the Blob's per-seed material — must mirror the
/// <c>BlobSlot*</c> constants in <c>cmd/cshared/internal/capi/blob_handles.go</c>.
/// </summary>
public enum BlobSlot
{
    /// <summary>Noise seed (Single Ouroboros).</summary>
    N = 0,
    /// <summary>Data seed (Single Ouroboros).</summary>
    D = 1,
    /// <summary>Start seed (Single Ouroboros).</summary>
    S = 2,
    /// <summary>Dedicated lockSeed.</summary>
    L = 3,
    /// <summary>Triple Ouroboros — data seed 1.</summary>
    D1 = 4,
    /// <summary>Triple Ouroboros — data seed 2.</summary>
    D2 = 5,
    /// <summary>Triple Ouroboros — data seed 3.</summary>
    D3 = 6,
    /// <summary>Triple Ouroboros — start seed 1.</summary>
    S1 = 7,
    /// <summary>Triple Ouroboros — start seed 2.</summary>
    S2 = 8,
    /// <summary>Triple Ouroboros — start seed 3.</summary>
    S3 = 9,
}

/// <summary>
/// Bitmask flags for the Blob export options argument. Mirrors
/// <c>BlobOpt*</c> in <c>blob_handles.go</c>.
/// </summary>
[Flags]
public enum BlobExportOpts
{
    /// <summary>No optional sections — only the mandatory n / d / s
    /// (Single) or n / d1..3 / s1..3 (Triple) seed material is
    /// emitted.</summary>
    None = 0,
    /// <summary>Emit the <see cref="BlobSlot.L"/> slot's lockSeed
    /// material (KeyL plus components) into the blob.</summary>
    LockSeed = 1 << 0,
    /// <summary>Emit the MAC key and MAC name into the blob. Both must
    /// be non-empty on the handle.</summary>
    Mac = 1 << 1,
}

/// <summary>
/// Internal helper providing the shared pinning / probe-allocate-call
/// implementation for every <c>Blob*</c> width-typed wrapper.
/// </summary>
internal static unsafe class BlobOps
{
    internal static int GetWidth(nuint handle)
    {
        var w = ItbNative.ITB_Blob_Width(handle, out var st);
        ItbException.Check(st);
        return w;
    }

    internal static int GetMode(nuint handle)
    {
        var m = ItbNative.ITB_Blob_Mode(handle, out var st);
        ItbException.Check(st);
        return m;
    }

    internal static void SetKey(nuint handle, int slot, ReadOnlySpan<byte> key)
    {
        int rc;
        fixed (byte* p = key)
        {
            rc = ItbNative.ITB_Blob_SetKey(handle, slot, p, (nuint)key.Length);
        }
        ItbException.Check(rc);
    }

    internal static void SetComponents(nuint handle, int slot, ReadOnlySpan<ulong> components)
    {
        int rc;
        fixed (ulong* p = components)
        {
            rc = ItbNative.ITB_Blob_SetComponents(handle, slot, p, (nuint)components.Length);
        }
        ItbException.Check(rc);
    }

    internal static void SetMacKey(nuint handle, ReadOnlySpan<byte> key)
    {
        int rc;
        fixed (byte* p = key)
        {
            rc = ItbNative.ITB_Blob_SetMACKey(handle, p, (nuint)key.Length);
        }
        ItbException.Check(rc);
    }

    internal static void SetMacName(nuint handle, string? name)
    {
        // Empty / null -> clears the field (pass NULL pointer + 0 length).
        if (string.IsNullOrEmpty(name))
        {
            ItbException.Check(ItbNative.ITB_Blob_SetMACName(handle, null, 0));
            return;
        }
        var utf8 = System.Text.Encoding.UTF8.GetBytes(name);
        int rc;
        fixed (byte* p = utf8)
        {
            rc = ItbNative.ITB_Blob_SetMACName(handle, p, (nuint)utf8.Length);
        }
        ItbException.Check(rc);
    }

    internal static byte[] GetKey(nuint handle, int slot)
    {
        // Probe-then-retry. Probe with cap=0 returns BufferTooSmall (or
        // OK + outLen == 0 for an unset / empty slot).
        int rc = ItbNative.ITB_Blob_GetKey(handle, slot, null, 0, out var outLen);
        if (rc == Status.Ok && outLen == 0)
        {
            return Array.Empty<byte>();
        }
        if (rc != Status.BufferTooSmall)
        {
            throw ItbException.FromStatus(rc);
        }
        var n = outLen;
        var buf = new byte[(int)n];
        int rc2;
        nuint outLen2;
        fixed (byte* p = buf)
        {
            rc2 = ItbNative.ITB_Blob_GetKey(handle, slot, p, n, out outLen2);
        }
        ItbException.Check(rc2);
        if ((int)outLen2 < buf.Length)
        {
            Array.Resize(ref buf, (int)outLen2);
        }
        return buf;
    }

    internal static ulong[] GetComponents(nuint handle, int slot)
    {
        int rc = ItbNative.ITB_Blob_GetComponents(handle, slot, null, 0, out var outCount);
        if (rc == Status.Ok && outCount == 0)
        {
            return Array.Empty<ulong>();
        }
        if (rc != Status.BufferTooSmall)
        {
            throw ItbException.FromStatus(rc);
        }
        var n = outCount;
        var buf = new ulong[(int)n];
        int rc2;
        nuint outCount2;
        fixed (ulong* p = buf)
        {
            rc2 = ItbNative.ITB_Blob_GetComponents(handle, slot, p, n, out outCount2);
        }
        ItbException.Check(rc2);
        if ((int)outCount2 < buf.Length)
        {
            Array.Resize(ref buf, (int)outCount2);
        }
        return buf;
    }

    internal static byte[] GetMacKey(nuint handle)
    {
        int rc = ItbNative.ITB_Blob_GetMACKey(handle, null, 0, out var outLen);
        if (rc == Status.Ok && outLen == 0)
        {
            return Array.Empty<byte>();
        }
        if (rc != Status.BufferTooSmall)
        {
            throw ItbException.FromStatus(rc);
        }
        var n = outLen;
        var buf = new byte[(int)n];
        int rc2;
        nuint outLen2;
        fixed (byte* p = buf)
        {
            rc2 = ItbNative.ITB_Blob_GetMACKey(handle, p, n, out outLen2);
        }
        ItbException.Check(rc2);
        if ((int)outLen2 < buf.Length)
        {
            Array.Resize(ref buf, (int)outLen2);
        }
        return buf;
    }

    internal static string GetMacName(nuint handle)
    {
        // GetMACName is a NUL-terminated string accessor; outLen counts
        // the trailing NUL. The probe path returns OK + outLen <= 1 for
        // an unset name; defer to ReadString.Read for the canonical
        // probe-allocate-strip-NUL pattern.
        return ReadString.Read((byte* buf, nuint cap, out nuint outLen) =>
            ItbNative.ITB_Blob_GetMACName(handle, buf, cap, out outLen));
    }

    internal static byte[] Export(nuint handle, BlobExportOpts opts, bool triple)
    {
        var optsMask = (int)opts;
        nuint outLen;
        int rc;
        if (triple)
        {
            rc = ItbNative.ITB_Blob_Export3(handle, optsMask, null, 0, out outLen);
        }
        else
        {
            rc = ItbNative.ITB_Blob_Export(handle, optsMask, null, 0, out outLen);
        }
        if (rc == Status.Ok && outLen == 0)
        {
            return Array.Empty<byte>();
        }
        if (rc != Status.BufferTooSmall)
        {
            throw ItbException.FromStatus(rc);
        }
        var cap = outLen;
        var buf = new byte[(int)cap];
        int rc2;
        nuint outLen2;
        fixed (byte* p = buf)
        {
            rc2 = triple
                ? ItbNative.ITB_Blob_Export3(handle, optsMask, p, cap, out outLen2)
                : ItbNative.ITB_Blob_Export(handle, optsMask, p, cap, out outLen2);
        }
        ItbException.Check(rc2);
        if ((int)outLen2 < buf.Length)
        {
            Array.Resize(ref buf, (int)outLen2);
        }
        return buf;
    }

    internal static void Import(nuint handle, ReadOnlySpan<byte> blob, bool triple)
    {
        int rc;
        fixed (byte* p = blob)
        {
            rc = triple
                ? ItbNative.ITB_Blob_Import3(handle, p, (nuint)blob.Length)
                : ItbNative.ITB_Blob_Import(handle, p, (nuint)blob.Length);
        }
        ItbException.Check(rc);
    }
}

/// <summary>
/// 128-bit width Blob — covers <c>siphash24</c> and <c>aescmac</c>
/// primitives. Hash key length is variable: empty for SipHash-2-4 (no
/// internal fixed key), 16 bytes for AES-CMAC. The 128-bit width is
/// reserved for testing and below-spec stress controls; for production
/// traffic prefer <see cref="Blob256"/> or <see cref="Blob512"/>.
/// </summary>
public sealed class Blob128 : IDisposable
{
    private nuint _handle;

    /// <summary>Constructs a fresh 128-bit width Blob handle.</summary>
    public Blob128()
    {
        var rc = ItbNative.ITB_Blob128_New(out var handle);
        ItbException.Check(rc);
        _handle = handle;
    }

    /// <summary>The opaque libitb handle id (uintptr). Useful for
    /// diagnostics; consumers should not rely on its numerical
    /// value.</summary>
    internal nuint Handle => _handle;

    /// <summary>The native hash width — 128 for this type. Pinned at
    /// construction time and stable for the lifetime of the
    /// handle.</summary>
    public int Width
    {
        get
        {
            ThrowIfDisposed();
            return BlobOps.GetWidth(_handle);
        }
    }

    /// <summary>The blob mode discriminator — <c>0</c> = unset (freshly
    /// constructed handle), <c>1</c> = Single Ouroboros, <c>3</c> =
    /// Triple Ouroboros. Updated by <see cref="Import"/> /
    /// <see cref="ImportTriple"/> from the parsed blob's mode
    /// field.</summary>
    public int Mode
    {
        get
        {
            ThrowIfDisposed();
            return BlobOps.GetMode(_handle);
        }
    }

    /// <summary>
    /// Stores the hash key bytes for the given slot. The 128-bit width
    /// accepts variable lengths: empty span for <c>siphash24</c> (no
    /// internal fixed key) or 16 bytes for <c>aescmac</c>.
    /// </summary>
    public void SetKey(BlobSlot slot, ReadOnlySpan<byte> key)
    {
        ThrowIfDisposed();
        BlobOps.SetKey(_handle, (int)slot, key);
    }

    /// <summary>
    /// Stores the seed components (slice of unsigned 64-bit integers)
    /// for the given slot. Component count must satisfy the
    /// 8..MaxKeyBits/64 multiple-of-8 invariants — same rules as
    /// <see cref="Seed.FromComponents"/>. Validation is deferred to
    /// <see cref="Export"/> / <see cref="Import"/> time.
    /// </summary>
    public void SetComponents(BlobSlot slot, ReadOnlySpan<ulong> components)
    {
        ThrowIfDisposed();
        BlobOps.SetComponents(_handle, (int)slot, components);
    }

    /// <summary>
    /// Stores the optional MAC key bytes. Pass an empty span to clear a
    /// previously-set key. The MAC section is only emitted by
    /// <see cref="Export"/> / <see cref="ExportTriple"/> when
    /// <see cref="BlobExportOpts.Mac"/> is set AND the MAC key on the
    /// handle is non-empty.
    /// </summary>
    public void SetMacKey(ReadOnlySpan<byte> key)
    {
        ThrowIfDisposed();
        BlobOps.SetMacKey(_handle, key);
    }

    /// <summary>
    /// Stores the optional MAC name on the handle (e.g.
    /// <c>"hmac-blake3"</c>, <c>"kmac256"</c>). Pass <c>null</c> or an
    /// empty string to clear a previously-set name.
    /// </summary>
    public void SetMacName(string? name)
    {
        ThrowIfDisposed();
        BlobOps.SetMacName(_handle, name);
    }

    /// <summary>
    /// Returns a fresh copy of the hash key bytes from the given slot.
    /// Returns an empty array for an unset slot or for SipHash-2-4's
    /// no-internal-key path (callers distinguish by <c>Length == 0</c>
    /// and the slot they queried).
    /// </summary>
    public byte[] GetKey(BlobSlot slot)
    {
        ThrowIfDisposed();
        return BlobOps.GetKey(_handle, (int)slot);
    }

    /// <summary>
    /// Returns the seed components stored at the given slot. Returns an
    /// empty array for an unset slot.
    /// </summary>
    public ulong[] GetComponents(BlobSlot slot)
    {
        ThrowIfDisposed();
        return BlobOps.GetComponents(_handle, (int)slot);
    }

    /// <summary>
    /// Returns a fresh copy of the MAC key bytes from the handle, or an
    /// empty array if no MAC key is associated.
    /// </summary>
    public byte[] GetMacKey()
    {
        ThrowIfDisposed();
        return BlobOps.GetMacKey(_handle);
    }

    /// <summary>
    /// Returns the MAC name from the handle, or an empty string if no
    /// MAC name is associated.
    /// </summary>
    public string GetMacName()
    {
        ThrowIfDisposed();
        var result = BlobOps.GetMacName(_handle);
        GC.KeepAlive(this);
        return result;
    }

    /// <summary>
    /// Serialises the handle's Single Ouroboros state into a JSON blob.
    /// The optional <see cref="BlobExportOpts.LockSeed"/> and
    /// <see cref="BlobExportOpts.Mac"/> flags opt the matching sections
    /// in: with <c>LockSeed</c> the <see cref="BlobSlot.L"/> slot's KeyL
    /// plus components are emitted; with <c>Mac</c> the MAC key plus
    /// name are emitted (both must be non-empty on the handle).
    /// </summary>
    public byte[] Export(BlobExportOpts opts = BlobExportOpts.None)
    {
        ThrowIfDisposed();
        return BlobOps.Export(_handle, opts, triple: false);
    }

    /// <summary>
    /// Serialises the handle's Triple Ouroboros state into a JSON blob.
    /// See <see cref="Export"/> for the <see cref="BlobExportOpts"/>
    /// flag semantics.
    /// </summary>
    public byte[] ExportTriple(BlobExportOpts opts = BlobExportOpts.None)
    {
        ThrowIfDisposed();
        return BlobOps.Export(_handle, opts, triple: true);
    }

    /// <summary>
    /// Parses a Single Ouroboros JSON blob, populates the handle's
    /// slots, and applies the captured globals via the process-wide
    /// setters.
    /// </summary>
    /// <remarks>
    /// Throws <see cref="ItbBlobModeMismatchException"/> when the blob
    /// is Triple-mode, <see cref="ItbBlobMalformedException"/> on parse
    /// or shape failure, <see cref="ItbBlobVersionTooNewException"/> on
    /// a version field higher than this build supports.
    /// </remarks>
    public void Import(ReadOnlySpan<byte> blob)
    {
        ThrowIfDisposed();
        BlobOps.Import(_handle, blob, triple: false);
    }

    /// <summary>
    /// Triple Ouroboros counterpart of <see cref="Import"/>. Same error
    /// contract.
    /// </summary>
    public void ImportTriple(ReadOnlySpan<byte> blob)
    {
        ThrowIfDisposed();
        BlobOps.Import(_handle, blob, triple: true);
    }

    private void ThrowIfDisposed()
    {
        if (_handle == 0)
        {
            throw new ObjectDisposedException(nameof(Blob128));
        }
    }

    /// <summary>Releases the underlying libitb handle. Idempotent.</summary>
    public void Dispose()
    {
        if (_handle != 0)
        {
            ItbNative.ITB_Blob_Free(_handle);
            _handle = 0;
        }
        GC.SuppressFinalize(this);
    }

    ~Blob128()
    {
        if (_handle != 0)
        {
            ItbNative.ITB_Blob_Free(_handle);
            _handle = 0;
        }
    }
}

/// <summary>
/// 256-bit width Blob — covers <c>areion256</c>, <c>blake2s</c>,
/// <c>blake2b256</c>, <c>blake3</c>, <c>chacha20</c> primitives. Hash
/// key length is fixed at 32 bytes.
/// </summary>
public sealed class Blob256 : IDisposable
{
    private nuint _handle;

    /// <summary>Constructs a fresh 256-bit width Blob handle.</summary>
    public Blob256()
    {
        var rc = ItbNative.ITB_Blob256_New(out var handle);
        ItbException.Check(rc);
        _handle = handle;
    }

    /// <summary>The opaque libitb handle id (uintptr).</summary>
    internal nuint Handle => _handle;

    /// <summary>The native hash width — 256 for this type.</summary>
    public int Width
    {
        get
        {
            ThrowIfDisposed();
            return BlobOps.GetWidth(_handle);
        }
    }

    /// <summary>The blob mode discriminator — <c>0</c> = unset,
    /// <c>1</c> = Single Ouroboros, <c>3</c> = Triple Ouroboros.</summary>
    public int Mode
    {
        get
        {
            ThrowIfDisposed();
            return BlobOps.GetMode(_handle);
        }
    }

    /// <summary>
    /// Stores the hash key bytes for the given slot. The 256-bit width
    /// requires exactly 32 bytes.
    /// </summary>
    public void SetKey(BlobSlot slot, ReadOnlySpan<byte> key)
    {
        ThrowIfDisposed();
        BlobOps.SetKey(_handle, (int)slot, key);
    }

    /// <summary>
    /// Stores the seed components for the given slot. See
    /// <see cref="Blob128.SetComponents"/> for the multiple-of-8
    /// invariants.
    /// </summary>
    public void SetComponents(BlobSlot slot, ReadOnlySpan<ulong> components)
    {
        ThrowIfDisposed();
        BlobOps.SetComponents(_handle, (int)slot, components);
    }

    /// <summary>Stores the optional MAC key bytes.</summary>
    public void SetMacKey(ReadOnlySpan<byte> key)
    {
        ThrowIfDisposed();
        BlobOps.SetMacKey(_handle, key);
    }

    /// <summary>Stores the optional MAC name on the handle.</summary>
    public void SetMacName(string? name)
    {
        ThrowIfDisposed();
        BlobOps.SetMacName(_handle, name);
    }

    /// <summary>Returns a fresh copy of the hash key bytes from the
    /// given slot.</summary>
    public byte[] GetKey(BlobSlot slot)
    {
        ThrowIfDisposed();
        return BlobOps.GetKey(_handle, (int)slot);
    }

    /// <summary>Returns the seed components stored at the given
    /// slot.</summary>
    public ulong[] GetComponents(BlobSlot slot)
    {
        ThrowIfDisposed();
        return BlobOps.GetComponents(_handle, (int)slot);
    }

    /// <summary>Returns the MAC key bytes from the handle, or an empty
    /// array if no MAC key is associated.</summary>
    public byte[] GetMacKey()
    {
        ThrowIfDisposed();
        return BlobOps.GetMacKey(_handle);
    }

    /// <summary>Returns the MAC name from the handle, or an empty
    /// string if no MAC name is associated.</summary>
    public string GetMacName()
    {
        ThrowIfDisposed();
        var result = BlobOps.GetMacName(_handle);
        GC.KeepAlive(this);
        return result;
    }

    /// <summary>Serialises the handle's Single Ouroboros state into a
    /// JSON blob.</summary>
    public byte[] Export(BlobExportOpts opts = BlobExportOpts.None)
    {
        ThrowIfDisposed();
        return BlobOps.Export(_handle, opts, triple: false);
    }

    /// <summary>Serialises the handle's Triple Ouroboros state into a
    /// JSON blob.</summary>
    public byte[] ExportTriple(BlobExportOpts opts = BlobExportOpts.None)
    {
        ThrowIfDisposed();
        return BlobOps.Export(_handle, opts, triple: true);
    }

    /// <summary>Parses a Single Ouroboros JSON blob and populates the
    /// handle.</summary>
    public void Import(ReadOnlySpan<byte> blob)
    {
        ThrowIfDisposed();
        BlobOps.Import(_handle, blob, triple: false);
    }

    /// <summary>Parses a Triple Ouroboros JSON blob and populates the
    /// handle.</summary>
    public void ImportTriple(ReadOnlySpan<byte> blob)
    {
        ThrowIfDisposed();
        BlobOps.Import(_handle, blob, triple: true);
    }

    private void ThrowIfDisposed()
    {
        if (_handle == 0)
        {
            throw new ObjectDisposedException(nameof(Blob256));
        }
    }

    /// <summary>Releases the underlying libitb handle. Idempotent.</summary>
    public void Dispose()
    {
        if (_handle != 0)
        {
            ItbNative.ITB_Blob_Free(_handle);
            _handle = 0;
        }
        GC.SuppressFinalize(this);
    }

    ~Blob256()
    {
        if (_handle != 0)
        {
            ItbNative.ITB_Blob_Free(_handle);
            _handle = 0;
        }
    }
}

/// <summary>
/// 512-bit width Blob — covers <c>areion512</c> (via the SoEM-512
/// construction) and <c>blake2b512</c> primitives. Hash key length is
/// fixed at 64 bytes.
/// </summary>
public sealed class Blob512 : IDisposable
{
    private nuint _handle;

    /// <summary>Constructs a fresh 512-bit width Blob handle.</summary>
    public Blob512()
    {
        var rc = ItbNative.ITB_Blob512_New(out var handle);
        ItbException.Check(rc);
        _handle = handle;
    }

    /// <summary>The opaque libitb handle id (uintptr).</summary>
    internal nuint Handle => _handle;

    /// <summary>The native hash width — 512 for this type.</summary>
    public int Width
    {
        get
        {
            ThrowIfDisposed();
            return BlobOps.GetWidth(_handle);
        }
    }

    /// <summary>The blob mode discriminator — <c>0</c> = unset,
    /// <c>1</c> = Single Ouroboros, <c>3</c> = Triple Ouroboros.</summary>
    public int Mode
    {
        get
        {
            ThrowIfDisposed();
            return BlobOps.GetMode(_handle);
        }
    }

    /// <summary>
    /// Stores the hash key bytes for the given slot. The 512-bit width
    /// requires exactly 64 bytes.
    /// </summary>
    public void SetKey(BlobSlot slot, ReadOnlySpan<byte> key)
    {
        ThrowIfDisposed();
        BlobOps.SetKey(_handle, (int)slot, key);
    }

    /// <summary>
    /// Stores the seed components for the given slot. See
    /// <see cref="Blob128.SetComponents"/> for the multiple-of-8
    /// invariants.
    /// </summary>
    public void SetComponents(BlobSlot slot, ReadOnlySpan<ulong> components)
    {
        ThrowIfDisposed();
        BlobOps.SetComponents(_handle, (int)slot, components);
    }

    /// <summary>Stores the optional MAC key bytes.</summary>
    public void SetMacKey(ReadOnlySpan<byte> key)
    {
        ThrowIfDisposed();
        BlobOps.SetMacKey(_handle, key);
    }

    /// <summary>Stores the optional MAC name on the handle.</summary>
    public void SetMacName(string? name)
    {
        ThrowIfDisposed();
        BlobOps.SetMacName(_handle, name);
    }

    /// <summary>Returns a fresh copy of the hash key bytes from the
    /// given slot.</summary>
    public byte[] GetKey(BlobSlot slot)
    {
        ThrowIfDisposed();
        return BlobOps.GetKey(_handle, (int)slot);
    }

    /// <summary>Returns the seed components stored at the given
    /// slot.</summary>
    public ulong[] GetComponents(BlobSlot slot)
    {
        ThrowIfDisposed();
        return BlobOps.GetComponents(_handle, (int)slot);
    }

    /// <summary>Returns the MAC key bytes from the handle, or an empty
    /// array if no MAC key is associated.</summary>
    public byte[] GetMacKey()
    {
        ThrowIfDisposed();
        return BlobOps.GetMacKey(_handle);
    }

    /// <summary>Returns the MAC name from the handle, or an empty
    /// string if no MAC name is associated.</summary>
    public string GetMacName()
    {
        ThrowIfDisposed();
        var result = BlobOps.GetMacName(_handle);
        GC.KeepAlive(this);
        return result;
    }

    /// <summary>Serialises the handle's Single Ouroboros state into a
    /// JSON blob.</summary>
    public byte[] Export(BlobExportOpts opts = BlobExportOpts.None)
    {
        ThrowIfDisposed();
        return BlobOps.Export(_handle, opts, triple: false);
    }

    /// <summary>Serialises the handle's Triple Ouroboros state into a
    /// JSON blob.</summary>
    public byte[] ExportTriple(BlobExportOpts opts = BlobExportOpts.None)
    {
        ThrowIfDisposed();
        return BlobOps.Export(_handle, opts, triple: true);
    }

    /// <summary>Parses a Single Ouroboros JSON blob and populates the
    /// handle.</summary>
    public void Import(ReadOnlySpan<byte> blob)
    {
        ThrowIfDisposed();
        BlobOps.Import(_handle, blob, triple: false);
    }

    /// <summary>Parses a Triple Ouroboros JSON blob and populates the
    /// handle.</summary>
    public void ImportTriple(ReadOnlySpan<byte> blob)
    {
        ThrowIfDisposed();
        BlobOps.Import(_handle, blob, triple: true);
    }

    private void ThrowIfDisposed()
    {
        if (_handle == 0)
        {
            throw new ObjectDisposedException(nameof(Blob512));
        }
    }

    /// <summary>Releases the underlying libitb handle. Idempotent.</summary>
    public void Dispose()
    {
        if (_handle != 0)
        {
            ItbNative.ITB_Blob_Free(_handle);
            _handle = 0;
        }
        GC.SuppressFinalize(this);
    }

    ~Blob512()
    {
        if (_handle != 0)
        {
            ItbNative.ITB_Blob_Free(_handle);
            _handle = 0;
        }
    }
}
