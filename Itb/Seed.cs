// ITB seed handle.
//
// Provides a thin Disposable wrapper over ITB_NewSeed /
// ITB_FreeSeed plus introspection accessors (Width, HashName,
// GetHashKey, GetComponents) and the deterministic-rebuild path
// FromComponents.

using Itb.Native;

namespace Itb;

/// <summary>
/// A handle to one ITB seed.
/// </summary>
/// <remarks>
/// <para>Construct via the <see cref="Seed(string, int)"/> constructor
/// for a CSPRNG-keyed seed or <see cref="FromComponents"/> for a
/// deterministic rebuild from caller-supplied uint64 components and an
/// optional fixed hash key.</para>
/// <para>All three seeds passed to <see cref="Cipher.Encrypt"/> /
/// <see cref="Cipher.Decrypt"/> must share the same hash name (or at
/// least the same native hash width); mixing widths surfaces as
/// <see cref="ItbException"/> with status <c>SeedWidthMix</c>.</para>
/// </remarks>
public sealed class Seed : IDisposable
{
    private nuint _handle;
    private readonly string _hashName;

    /// <summary>
    /// Constructs a fresh seed with CSPRNG-generated keying material.
    /// </summary>
    /// <param name="hashName">A canonical hash name from
    /// <see cref="Library.ListHashes"/> (e.g. <c>"blake3"</c>,
    /// <c>"areion256"</c>).</param>
    /// <param name="keyBits">The ITB key width in bits — 512, 1024,
    /// or 2048 (multiple of 64).</param>
    public Seed(string hashName, int keyBits)
    {
        ArgumentNullException.ThrowIfNull(hashName);
        var rc = ItbNative.ITB_NewSeed(hashName, keyBits, out var handle);
        ItbException.Check(rc);
        _handle = handle;
        _hashName = hashName;
    }

    private Seed(nuint handle, string hashName)
    {
        _handle = handle;
        _hashName = hashName;
    }

    /// <summary>
    /// Builds a seed deterministically from caller-supplied uint64
    /// components and an optional fixed hash key.
    /// </summary>
    /// <remarks>
    /// Use this on the persistence-restore path (encrypt today,
    /// decrypt tomorrow); pass an empty span for <paramref name="hashKey"/>
    /// to request a CSPRNG-generated key (still useful when only the
    /// components need to be deterministic).
    /// <para><paramref name="components"/> length must be 8..32 (multiple
    /// of 8). <paramref name="hashKey"/> length, when non-empty, must
    /// match the primitive's native fixed-key size: 16 (<c>aescmac</c>),
    /// 32 (<c>areion256</c> / <c>blake2{s,b256}</c> / <c>blake3</c> /
    /// <c>chacha20</c>), 64 (<c>areion512</c> / <c>blake2b512</c>).
    /// Pass an empty span for <c>siphash24</c> (no internal fixed
    /// key).</para>
    /// </remarks>
    public static unsafe Seed FromComponents(
        string hashName,
        ReadOnlySpan<ulong> components,
        ReadOnlySpan<byte> hashKey)
    {
        ArgumentNullException.ThrowIfNull(hashName);
        nuint handle;
        int rc;
        fixed (ulong* compsPtr = components)
        fixed (byte* keyPtr = hashKey)
        {
            rc = ItbNative.ITB_NewSeedFromComponents(
                hashName,
                compsPtr,
                components.Length,
                keyPtr,
                hashKey.Length,
                out handle);
        }
        ItbException.Check(rc);
        return new Seed(handle, hashName);
    }

    /// <summary>The raw libitb handle. Used internally by the low-level
    /// <see cref="Cipher"/> entry points.</summary>
    internal nuint Handle => _handle;

    /// <summary>The canonical hash name this seed was constructed
    /// with.</summary>
    public string HashName => _hashName;

    /// <summary>The seed's native hash width in bits (128 / 256 /
    /// 512).</summary>
    public int Width
    {
        get
        {
            ThrowIfDisposed();
            var w = ItbNative.ITB_SeedWidth(_handle, out var st);
            ItbException.Check(st);
            return w;
        }
    }

    /// <summary>
    /// Returns the canonical hash name reported by libitb (round-trip
    /// of the constructor argument).
    /// </summary>
    public unsafe string HashNameIntrospect()
    {
        ThrowIfDisposed();
        var handle = _handle;
        var result = ReadString.Read((byte* buf, nuint cap, out nuint outLen) =>
            ItbNative.ITB_SeedHashName(handle, buf, cap, out outLen));
        GC.KeepAlive(this);
        return result;
    }

    /// <summary>
    /// Returns the fixed key the underlying hash closure is bound to
    /// (16 / 32 / 64 bytes depending on the primitive). Save these
    /// bytes alongside <see cref="GetComponents"/> for cross-process
    /// persistence — the pair fully reconstructs the seed via
    /// <see cref="FromComponents"/>.
    /// </summary>
    /// <remarks>
    /// <c>siphash24</c> returns an empty array since SipHash-2-4 has
    /// no internal fixed key (its keying material is the seed
    /// components themselves).
    /// </remarks>
    public unsafe byte[] GetHashKey()
    {
        ThrowIfDisposed();
        // Two-call pattern: first probe length (cap=0), then allocate.
        var rc = ItbNative.ITB_GetSeedHashKey(_handle, null, 0, out var outLen);
        // Probing returns BufferTooSmall when the key is non-empty
        // (no buffer to write into); empty key is OK.
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
            rc2 = ItbNative.ITB_GetSeedHashKey(_handle, p, cap, out outLen2);
        }
        ItbException.Check(rc2);
        if ((int)outLen2 < buf.Length)
        {
            Array.Resize(ref buf, (int)outLen2);
        }
        return buf;
    }

    /// <summary>
    /// Returns the seed's underlying uint64 components (8..32 elements).
    /// Save these alongside <see cref="GetHashKey"/> for cross-process
    /// persistence — the pair fully reconstructs the seed via
    /// <see cref="FromComponents"/>.
    /// </summary>
    public unsafe ulong[] GetComponents()
    {
        ThrowIfDisposed();
        var rc = ItbNative.ITB_GetSeedComponents(_handle, null, 0, out var outLen);
        if (rc != Status.BufferTooSmall)
        {
            throw ItbException.FromStatus(rc);
        }
        var n = outLen;
        var buf = new ulong[n];
        int rc2;
        int outLen2;
        fixed (ulong* p = buf)
        {
            rc2 = ItbNative.ITB_GetSeedComponents(_handle, p, n, out outLen2);
        }
        ItbException.Check(rc2);
        if (outLen2 < buf.Length)
        {
            Array.Resize(ref buf, outLen2);
        }
        return buf;
    }

    /// <summary>
    /// Wires a dedicated lockSeed onto this noise seed. The per-chunk
    /// PRF closure for the bit-permutation overlay captures BOTH the
    /// lockSeed's components AND its hash function — keying-material
    /// isolation plus algorithm diversity (the lockSeed primitive may
    /// legitimately differ from the noise-seed primitive within the
    /// same native hash width) for defence-in-depth on the overlay
    /// channel. Both seeds must share the same native hash width.
    /// </summary>
    /// <remarks>
    /// <para>The dedicated lockSeed has no observable effect on the
    /// wire output unless the bit-permutation overlay is engaged via
    /// <c>Library.BitSoup = 1</c> or <c>Library.LockSoup = 1</c> before
    /// the first encrypt / decrypt call. The Go-side build-PRF guard
    /// panics on encrypt-time when an attach is present without either
    /// flag, surfacing as <see cref="ItbException"/>.</para>
    /// <para>Misuse paths surface as <see cref="ItbException"/> with
    /// status <c>BadInput</c>: self-attach (passing the same seed
    /// twice), component-array aliasing (two distinct Seed handles
    /// whose components share the same backing array — only reachable
    /// via raw FFI), and post-encrypt switching (calling
    /// <see cref="AttachLockSeed"/> on a noise seed that has already
    /// produced ciphertext). Width mismatch surfaces with status
    /// <c>SeedWidthMix</c>.</para>
    /// <para>The dedicated lockSeed remains owned by the caller —
    /// attach only records the pointer on the noise seed, so keep the
    /// lockSeed alive for the lifetime of the noise seed (do not
    /// dispose the lockSeed before encrypt finishes).</para>
    /// </remarks>
    public void AttachLockSeed(Seed lockSeed)
    {
        ArgumentNullException.ThrowIfNull(lockSeed);
        ThrowIfDisposed();
        lockSeed.ThrowIfDisposed();
        var rc = ItbNative.ITB_AttachLockSeed(_handle, lockSeed._handle);
        // Keep both handles rooted past the FFI call so the JIT cannot
        // mark them dead after handle-field extraction and let the
        // finalizer race ITB_AttachLockSeed.
        GC.KeepAlive(this);
        GC.KeepAlive(lockSeed);
        ItbException.Check(rc);
    }

    private void ThrowIfDisposed()
    {
        if (_handle == 0)
        {
            throw new ObjectDisposedException(nameof(Seed));
        }
    }

    /// <summary>Releases the underlying libitb handle. Idempotent.</summary>
    public void Dispose()
    {
        if (_handle != 0)
        {
            ItbNative.ITB_FreeSeed(_handle);
            _handle = 0;
        }
        GC.SuppressFinalize(this);
    }

    ~Seed()
    {
        if (_handle != 0)
        {
            ItbNative.ITB_FreeSeed(_handle);
            _handle = 0;
        }
    }
}
