// High-level Encryptor wrapper over the libitb C ABI.
//
// Mirrors the github.com/everanium/itb/easy Go sub-package: one
// constructor call replaces the lower-level seven-line setup ceremony
// (hash factory, three or seven seeds, MAC closure, container-config
// wiring) and returns an Encryptor instance that owns its own
// per-instance configuration. Two encryptors with different settings
// can be used in parallel without cross-contamination of the
// process-wide ITB configuration.
//
// API shape combines RAII (via IDisposable), structured throw on
// failure, and an output-buffer cache for the cipher methods. The
// typed-mismatch behaviour surfaces STATUS_EASY_MISMATCH from
// ITB_Easy_Import as ItbEasyMismatchException carrying the offending
// JSON field name on its .Field property. The dispatch is automatic
// via ItbException.Check; no manual translation is required.

using System.Text;
using Itb.Native;

namespace Itb;

/// <summary>
/// Snapshot of an exported state blob's bound configuration —
/// returned by <see cref="Encryptor.PeekConfig"/> for compatibility
/// inspection prior to construction of a matching encryptor.
/// </summary>
/// <param name="Primitive">Canonical hash primitive name carried in
/// the blob (the noiseSeed slot's primitive for Mixed-mode
/// encryptors).</param>
/// <param name="KeyBits">ITB key width in bits (512 / 1024 / 2048).</param>
/// <param name="Mode">1 (Single Ouroboros, 3 seeds) or 3 (Triple
/// Ouroboros, 7 seeds).</param>
/// <param name="MacName">Canonical MAC primitive name carried in
/// the blob.</param>
public readonly record struct EncryptorConfig(string Primitive, int KeyBits, int Mode, string MacName);

/// <summary>
/// High-level Encryptor over the libitb C ABI.
/// </summary>
/// <remarks>
/// <para>Construction is the heavy step — generates fresh PRF keys,
/// fresh seed components, and a fresh MAC key from <c>/dev/urandom</c>.
/// Reusing one <see cref="Encryptor"/> instance across many encrypt /
/// decrypt calls amortises the cost across the lifetime of a session.</para>
///
/// <para><b>Default MAC.</b> The constructor's <c>mac</c> parameter
/// defaults to <c>null</c> at the binding boundary; that <c>null</c> is
/// translated to <c>"hmac-blake3"</c> before the
/// <c>ITB_Easy_New</c> / <c>ITB_Easy_NewMixed</c> /
/// <c>ITB_Easy_NewMixed3</c> call rather than forwarding NULL through
/// to libitb's own default. HMAC-BLAKE3 measures the lightest MAC
/// overhead in the Easy Mode bench surface (~9 % vs HMAC-SHA256's
/// ~15 % vs KMAC-256's ~44 %); routing the default through it gives
/// the "constructor without explicit MAC" path the lowest cost.</para>
///
/// <para><b>Auto-coupling.</b> Three rules govern the
/// BitSoup / LockSoup / LockSeed overlay (Go-side
/// itb/easy/config.go + itb/bitsoup.go) and propagate through this
/// binding without filtering. (1) <b>Setter-level: LockSoup → BitSoup</b>
/// (always, both modes). <see cref="SetLockSoup"/>(non-zero) sets
/// <c>cfg.BitSoup = 1</c>; <see cref="SetLockSeed"/>(1) sets
/// <c>cfg.LockSoup = 1 + cfg.BitSoup = 1</c> (the dedicated lockSeed
/// has no wire effect without the overlay engaged, so both flags
/// are forced on). (2) <b>Mode-dependent dispatch: Single Ouroboros
/// activates the overlay if either flag is set.</b> In mode = 1, the
/// Go-side <c>splitForSingle</c> engages the lock-soup overlay if
/// EITHER <c>cfg.BitSoup == 1</c> OR <c>cfg.LockSoup == 1</c>;
/// practical effect — calling <see cref="SetBitSoup"/>(1) alone
/// activates the overlay at encrypt time even though
/// <c>cfg.LockSoup</c> stays 0. In Triple Ouroboros (mode = 3),
/// bit-soup and lock-soup are independently meaningful — bit-soup
/// alone splits payload bits without the PRF-keyed permutation
/// overlay. (3) <b>Off-direction coercion while LockSeed active.</b>
/// While <c>cfg.LockSeed == 1</c>,
/// <see cref="SetBitSoup"/>(0) and
/// <see cref="SetLockSoup"/>(0) are silently coerced to 1 to keep
/// the overlay engaged on the dedicated lockSeed channel; drop the
/// lockSeed via <see cref="SetLockSeed"/>(0) first to fully
/// disengage. <see cref="Seed.AttachLockSeed"/> at the low-level
/// Seed surface does NOT auto-couple — it records the pointer at
/// the seed level and the caller engages the overlay manually via
/// <see cref="Library.BitSoup"/> / <see cref="Library.LockSoup"/>.
/// </para>
///
/// <para><b>Output-buffer cache.</b> The cipher methods reuse a
/// per-encryptor <see cref="byte"/>[] to skip the per-call probe
/// round-trip; the buffer grows on demand (initial allocation is
/// <c>max(131072, payload * 5 / 4 + 131072)</c> — the 1.25×
/// multiplier plus a 128 KiB headroom that absorbs the residual
/// expansion from non-default barrier-fill values up to 32, where
/// the absolute ratio reaches ~1.346 around the 1 MiB payload
/// region) and survives between calls. <see cref="Close"/> / <see cref="Dispose"/> / the finalizer
/// wipe its bytes before release so the most recent ciphertext or
/// plaintext does not linger in heap memory after the working set has
/// been zeroed on the Go side.</para>
///
/// <para><b>Lifecycle.</b> Use <see cref="Dispose"/> via
/// <c>using var enc = new Encryptor(...)</c> for explicit zeroisation
/// at scope exit, or call <see cref="Close"/> manually. The finalizer
/// is best-effort — relying on it under a heap-scan threat model is
/// inadequate.</para>
///
/// <para><b>Thread-safety contract.</b> Cipher methods
/// (<see cref="Encrypt"/> / <see cref="Decrypt"/> /
/// <see cref="EncryptAuth"/> / <see cref="DecryptAuth"/>) write into
/// the per-instance output-buffer cache and are <b>not safe</b> to
/// invoke concurrently against the same encryptor. Sharing one
/// <see cref="Encryptor"/> across threads requires external
/// synchronisation. Per-instance configuration setters
/// (<see cref="SetNonceBits"/> / <see cref="SetBarrierFill"/> /
/// <see cref="SetBitSoup"/> / <see cref="SetLockSoup"/> /
/// <see cref="SetLockSeed"/> / <see cref="SetChunkSize"/>) and
/// state-serialisation methods (<see cref="Export"/> /
/// <see cref="Import"/>) likewise require external synchronisation
/// when called against the same encryptor from multiple threads.
/// Distinct <see cref="Encryptor"/> handles, each owned by one
/// thread, run independently against the libitb worker pool.</para>
/// </remarks>
public sealed class Encryptor : IDisposable
{
    private nuint _handle;

    /// <summary>
    /// Per-encryptor output buffer cache. Grows on demand;
    /// <see cref="Close"/> / <see cref="Dispose"/> / finalizer wipe
    /// it before drop.
    /// </summary>
    private byte[] _outputBuffer;

    /// <summary>
    /// Tracks the closed / disposed state independently of the
    /// handle field so the preflight in <see cref="ThrowIfClosed"/>
    /// can surface <see cref="Native.Status.EasyClosed"/> after
    /// <see cref="Close"/> / <see cref="Dispose"/> without relying on
    /// the libitb-side handle-id lookup (which would surface
    /// <see cref="Native.Status.BadHandle"/> once <see cref="Dispose"/>
    /// has cleared the handle slot).
    /// </summary>
    private bool _closed;

    private const string DefaultMac = "hmac-blake3";

    // ----------------------------------------------------------------
    // Construction
    // ----------------------------------------------------------------

    /// <summary>
    /// Constructs a fresh encryptor under one canonical primitive
    /// across all seed slots.
    /// </summary>
    /// <param name="primitive">A canonical hash name from
    /// <see cref="Library.ListHashes"/> — one of <c>areion256</c>,
    /// <c>areion512</c>, <c>siphash24</c>, <c>aescmac</c>,
    /// <c>blake2b256</c>, <c>blake2b512</c>, <c>blake2s</c>,
    /// <c>blake3</c>, <c>chacha20</c>.</param>
    /// <param name="keyBits">ITB key width in bits — 512, 1024, or
    /// 2048; must be a multiple of the primitive's native hash
    /// width.</param>
    /// <param name="mac">Canonical MAC name from
    /// <see cref="Library.ListMacs"/>. <c>null</c> selects
    /// <c>"hmac-blake3"</c> at the binding boundary; pass an explicit
    /// name to override.</param>
    /// <param name="mode"><c>"single"</c> for Single Ouroboros (3
    /// seeds — noise / data / start) or <c>"triple"</c> for Triple
    /// Ouroboros (7 seeds — noise + 3 pairs of data / start). Other
    /// values surface as <see cref="ItbException"/> with status
    /// <c>BadInput</c>.</param>
    public Encryptor(string primitive, int keyBits, string? mac = null, string mode = "single")
    {
        ArgumentNullException.ThrowIfNull(primitive);
        ArgumentNullException.ThrowIfNull(mode);
        var modeValue = ParseMode(mode);
        var macName = mac ?? DefaultMac;
        var rc = ItbNative.ITB_Easy_New(primitive, keyBits, macName, modeValue, out var handle);
        ItbException.Check(rc);
        _handle = handle;
        _outputBuffer = Array.Empty<byte>();
        _closed = false;
    }

    private Encryptor(nuint handle)
    {
        _handle = handle;
        _outputBuffer = Array.Empty<byte>();
        _closed = false;
    }

    /// <summary>
    /// Constructs a Single Ouroboros encryptor with per-slot PRF
    /// primitive selection. The <paramref name="primN"/> /
    /// <paramref name="primD"/> / <paramref name="primS"/> arguments
    /// cover the noise / data / start slots respectively;
    /// <paramref name="primL"/> (default <c>null</c>) is the optional
    /// dedicated lockSeed primitive — when supplied, a 4th seed slot
    /// is allocated under that primitive and Bit Soup + Lock Soup
    /// are auto-coupled on this encryptor.
    /// </summary>
    /// <remarks>
    /// All four primitive names must resolve to the same native hash
    /// width via the libitb registry; mixed widths surface as
    /// <see cref="ItbException"/> carrying the panic message captured
    /// in <c>ITB_LastError</c>.
    /// </remarks>
    public static Encryptor Mixed(
        string primN,
        string primD,
        string primS,
        string? primL,
        int keyBits,
        string? mac = null)
    {
        ArgumentNullException.ThrowIfNull(primN);
        ArgumentNullException.ThrowIfNull(primD);
        ArgumentNullException.ThrowIfNull(primS);
        var macName = mac ?? DefaultMac;
        var lockPrim = string.IsNullOrEmpty(primL) ? null : primL;
        var rc = ItbNative.ITB_Easy_NewMixed(
            primN, primD, primS, lockPrim, keyBits, macName, out var handle);
        ItbException.Check(rc);
        return new Encryptor(handle);
    }

    /// <summary>
    /// Triple Ouroboros counterpart of <see cref="Mixed"/>. Accepts
    /// seven per-slot primitive names (noise + 3 data + 3 start)
    /// plus the optional <paramref name="primL"/> lockSeed
    /// primitive. See <see cref="Mixed"/> for the construction
    /// contract.
    /// </summary>
    public static Encryptor Mixed3(
        string primN,
        string primD1,
        string primD2,
        string primD3,
        string primS1,
        string primS2,
        string primS3,
        string? primL,
        int keyBits,
        string? mac = null)
    {
        ArgumentNullException.ThrowIfNull(primN);
        ArgumentNullException.ThrowIfNull(primD1);
        ArgumentNullException.ThrowIfNull(primD2);
        ArgumentNullException.ThrowIfNull(primD3);
        ArgumentNullException.ThrowIfNull(primS1);
        ArgumentNullException.ThrowIfNull(primS2);
        ArgumentNullException.ThrowIfNull(primS3);
        var macName = mac ?? DefaultMac;
        var lockPrim = string.IsNullOrEmpty(primL) ? null : primL;
        var rc = ItbNative.ITB_Easy_NewMixed3(
            primN, primD1, primD2, primD3, primS1, primS2, primS3,
            lockPrim, keyBits, macName, out var handle);
        ItbException.Check(rc);
        return new Encryptor(handle);
    }

    private static int ParseMode(string mode)
    {
        return mode switch
        {
            "single" => 1,
            "triple" => 3,
            _ => throw new ItbException(
                Status.BadInput,
                $"mode must be \"single\" or \"triple\", got \"{mode}\""),
        };
    }

    // ----------------------------------------------------------------
    // Read-only field accessors
    // ----------------------------------------------------------------

    /// <summary>The raw libitb handle — exposed for diagnostics and
    /// internal interop with sibling classes (Streams, Blob).
    /// Bindings should not rely on its numerical value.</summary>
    internal nuint Handle => _handle;

    /// <summary>The canonical primitive name bound to seed slot 0
    /// (the noiseSeed slot). For Mixed-mode encryptors this returns
    /// the noise-slot primitive specifically; use
    /// <see cref="PrimitiveAt"/> to enumerate per-slot primitives.</summary>
    public unsafe string Primitive
    {
        get
        {
            ThrowIfClosed();
            var handle = _handle;
            var result = ReadString.Read((byte* buf, nuint cap, out nuint outLen) =>
                ItbNative.ITB_Easy_Primitive(handle, buf, cap, out outLen));
            GC.KeepAlive(this);
            return result;
        }
    }

    /// <summary>The ITB key width in bits.</summary>
    public int KeyBits
    {
        get
        {
            ThrowIfClosed();
            var v = ItbNative.ITB_Easy_KeyBits(_handle, out var st);
            ItbException.Check(st);
            return v;
        }
    }

    /// <summary>1 (Single Ouroboros) or 3 (Triple Ouroboros).</summary>
    public int Mode
    {
        get
        {
            ThrowIfClosed();
            var v = ItbNative.ITB_Easy_Mode(_handle, out var st);
            ItbException.Check(st);
            return v;
        }
    }

    /// <summary>The canonical MAC name bound at construction.</summary>
    public unsafe string MacName
    {
        get
        {
            ThrowIfClosed();
            var handle = _handle;
            var result = ReadString.Read((byte* buf, nuint cap, out nuint outLen) =>
                ItbNative.ITB_Easy_MACName(handle, buf, cap, out outLen));
            GC.KeepAlive(this);
            return result;
        }
    }

    /// <summary>
    /// Number of seed slots — 3 (Single without LockSeed),
    /// 4 (Single with LockSeed), 7 (Triple without LockSeed),
    /// 8 (Triple with LockSeed).
    /// </summary>
    public int SeedCount
    {
        get
        {
            ThrowIfClosed();
            var v = ItbNative.ITB_Easy_SeedCount(_handle, out var st);
            ItbException.Check(st);
            return v;
        }
    }

    /// <summary>
    /// Nonce size in bits configured for this encryptor — either the
    /// value from the most recent <see cref="SetNonceBits"/> call, or
    /// the process-wide <see cref="Library.NonceBits"/> reading at
    /// construction time when no per-instance override has been
    /// issued. Reads the live <c>cfg.NonceBits</c> via
    /// <c>ITB_Easy_NonceBits</c> so a setter call on the Go side is
    /// reflected immediately.
    /// </summary>
    public int NonceBits
    {
        get
        {
            ThrowIfClosed();
            var v = ItbNative.ITB_Easy_NonceBits(_handle, out var st);
            ItbException.Check(st);
            return v;
        }
    }

    /// <summary>
    /// Per-instance ciphertext-chunk header size in bytes (nonce +
    /// 2-byte width + 2-byte height). Tracks this encryptor's own
    /// <see cref="NonceBits"/>, NOT the process-wide
    /// <see cref="Library.HeaderSize"/> reading — important when the
    /// encryptor has called <see cref="SetNonceBits"/> to override
    /// the default.
    /// </summary>
    public int HeaderSize
    {
        get
        {
            ThrowIfClosed();
            var v = ItbNative.ITB_Easy_HeaderSize(_handle, out var st);
            ItbException.Check(st);
            return v;
        }
    }

    /// <summary>
    /// <c>true</c> when this encryptor was constructed via
    /// <see cref="Mixed"/> or <see cref="Mixed3"/> (per-slot
    /// primitive selection); <c>false</c> for single-primitive
    /// encryptors built via the regular <see cref="Encryptor(string, int, string?, string)"/>
    /// constructor.
    /// </summary>
    public bool IsMixed
    {
        get
        {
            ThrowIfClosed();
            var v = ItbNative.ITB_Easy_IsMixed(_handle, out var st);
            ItbException.Check(st);
            return v != 0;
        }
    }

    /// <summary>
    /// <c>true</c> when the encryptor's primitive uses fixed PRF keys
    /// per seed slot (every shipped primitive except
    /// <c>siphash24</c>).
    /// </summary>
    public bool HasPRFKeys
    {
        get
        {
            ThrowIfClosed();
            var v = ItbNative.ITB_Easy_HasPRFKeys(_handle, out var st);
            ItbException.Check(st);
            return v != 0;
        }
    }

    /// <summary>
    /// Returns the canonical hash primitive name bound to one seed
    /// slot. Slot ordering is canonical — 0 = noiseSeed, then
    /// dataSeed{,1..3}, then startSeed{,1..3}, with the optional
    /// dedicated lockSeed at the trailing slot. For single-primitive
    /// encryptors every slot returns the same <see cref="Primitive"/>
    /// value; for encryptors built via <see cref="Mixed"/> /
    /// <see cref="Mixed3"/> each slot returns its
    /// independently-chosen primitive name.
    /// </summary>
    public unsafe string PrimitiveAt(int slot)
    {
        ThrowIfClosed();
        var handle = _handle;
        var s = slot;
        var result = ReadString.Read((byte* buf, nuint cap, out nuint outLen) =>
            ItbNative.ITB_Easy_PrimitiveAt(handle, s, buf, cap, out outLen));
        GC.KeepAlive(this);
        return result;
    }

    // ----------------------------------------------------------------
    // Material getters (defensive copies)
    // ----------------------------------------------------------------

    /// <summary>
    /// Returns the fixed PRF key bytes for one seed slot (defensive
    /// copy). Surfaces <see cref="ItbException"/> with status
    /// <c>BadInput</c> when the primitive has no fixed PRF keys
    /// (<c>siphash24</c> — caller should consult
    /// <see cref="HasPRFKeys"/> first) or when <paramref name="slot"/>
    /// is out of range.
    /// </summary>
    public unsafe byte[] PRFKey(int slot)
    {
        ThrowIfClosed();
        // Probe pattern: zero-length key returns Status.Ok + outLen=0
        // (siphash24); non-zero length returns Status.BufferTooSmall
        // with outLen carrying the required size. Status.BadInput is
        // reserved for out-of-range slot or no-fixed-key primitive.
        var rc = ItbNative.ITB_Easy_PRFKey(_handle, slot, null, 0, out var outLen);
        if (rc == Status.Ok && outLen == 0)
        {
            return Array.Empty<byte>();
        }
        if (rc != Status.BufferTooSmall)
        {
            throw ItbException.FromStatus(rc);
        }
        var buf = new byte[(int)outLen];
        int rc2;
        nuint outLen2;
        fixed (byte* p = buf)
        {
            rc2 = ItbNative.ITB_Easy_PRFKey(_handle, slot, p, outLen, out outLen2);
        }
        ItbException.Check(rc2);
        if ((int)outLen2 < buf.Length)
        {
            Array.Resize(ref buf, (int)outLen2);
        }
        return buf;
    }

    /// <summary>
    /// Returns a defensive copy of the encryptor's bound MAC fixed
    /// key. Save these bytes alongside the seed material for
    /// cross-process restore via <see cref="Export"/> /
    /// <see cref="Import"/>.
    /// </summary>
    public unsafe byte[] MacKey()
    {
        ThrowIfClosed();
        var rc = ItbNative.ITB_Easy_MACKey(_handle, null, 0, out var outLen);
        if (rc == Status.Ok && outLen == 0)
        {
            return Array.Empty<byte>();
        }
        if (rc != Status.BufferTooSmall)
        {
            throw ItbException.FromStatus(rc);
        }
        var buf = new byte[(int)outLen];
        int rc2;
        nuint outLen2;
        fixed (byte* p = buf)
        {
            rc2 = ItbNative.ITB_Easy_MACKey(_handle, p, outLen, out outLen2);
        }
        ItbException.Check(rc2);
        if ((int)outLen2 < buf.Length)
        {
            Array.Resize(ref buf, (int)outLen2);
        }
        return buf;
    }

    /// <summary>
    /// Returns the uint64 components of one seed slot (defensive
    /// copy). Slot index follows the canonical ordering:
    /// Single = <c>[noise, data, start]</c>; Triple Ouroboros =
    /// <c>[noise, data1, data2, data3, start1, start2, start3]</c>;
    /// the dedicated lockSeed slot, when present, is appended at the
    /// trailing index. Consult <see cref="SeedCount"/> for the valid
    /// slot range under the active mode + lockSeed configuration.
    /// </summary>
    public unsafe ulong[] SeedComponents(int slot)
    {
        ThrowIfClosed();
        // Probe call: out=NULL / capCount=0 returns BufferTooSmall
        // with the required size in outLen. BadInput here would
        // signal an out-of-range slot.
        var rc = ItbNative.ITB_Easy_SeedComponents(_handle, slot, null, 0, out var outLen);
        if (rc == Status.Ok)
        {
            return Array.Empty<ulong>();
        }
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
            rc2 = ItbNative.ITB_Easy_SeedComponents(_handle, slot, p, n, out outLen2);
        }
        ItbException.Check(rc2);
        if (outLen2 < buf.Length)
        {
            Array.Resize(ref buf, outLen2);
        }
        return buf;
    }

    // ----------------------------------------------------------------
    // Stream-frame helpers
    // ----------------------------------------------------------------

    /// <summary>
    /// Per-instance counterpart of <see cref="Library.ParseChunkLen"/>.
    /// Inspects a chunk header (the fixed-size <c>[nonce(N) ||
    /// width(2) || height(2)]</c> prefix where N comes from this
    /// encryptor's <see cref="NonceBits"/>) and returns the total
    /// chunk length on the wire.
    /// </summary>
    /// <remarks>
    /// Use this when walking a concatenated chunk stream produced by
    /// this encryptor: read <see cref="HeaderSize"/> bytes from the
    /// wire, call <c>enc.ParseChunkLen(buf[..enc.HeaderSize])</c>,
    /// read the remaining <c>chunk_len - header_size</c> bytes, and
    /// feed the full chunk to <see cref="Decrypt"/> /
    /// <see cref="DecryptAuth"/>.
    /// <para>The buffer must contain at least <see cref="HeaderSize"/>
    /// bytes; only the header is consulted, the body bytes do not
    /// need to be present. Surfaces <see cref="ItbException"/> with
    /// status <c>BadInput</c> on too-short buffer, zero dimensions,
    /// or width × height overflow against the container pixel cap.</para>
    /// </remarks>
    public unsafe int ParseChunkLen(ReadOnlySpan<byte> header)
    {
        ThrowIfClosed();
        nuint outChunkLen;
        int rc;
        fixed (byte* p = header)
        {
            rc = ItbNative.ITB_Easy_ParseChunkLen(_handle, p, (nuint)header.Length, out outChunkLen);
        }
        ItbException.Check(rc);
        return (int)outChunkLen;
    }

    // ----------------------------------------------------------------
    // Cipher entry points
    // ----------------------------------------------------------------

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using the encryptor's
    /// configured primitive / key bits / mode and per-instance Config
    /// snapshot. Plain mode — does not attach a MAC tag; for
    /// authenticated encryption use <see cref="EncryptAuth"/>.
    /// </summary>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        return CipherCall(CipherOp.Encrypt, plaintext);
    }

    /// <summary>
    /// Decrypts ciphertext produced by <see cref="Encrypt"/> under
    /// the same encryptor configuration.
    /// </summary>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext)
    {
        return CipherCall(CipherOp.Decrypt, ciphertext);
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> and attaches a MAC tag
    /// using the encryptor's bound MAC closure.
    /// </summary>
    public byte[] EncryptAuth(ReadOnlySpan<byte> plaintext)
    {
        return CipherCall(CipherOp.EncryptAuth, plaintext);
    }

    /// <summary>
    /// Verifies and decrypts ciphertext produced by
    /// <see cref="EncryptAuth"/>. Surfaces <see cref="ItbException"/>
    /// with status <c>MacFailure</c> on tampered ciphertext or wrong
    /// MAC key.
    /// </summary>
    public byte[] DecryptAuth(ReadOnlySpan<byte> ciphertext)
    {
        return CipherCall(CipherOp.DecryptAuth, ciphertext);
    }

    private enum CipherOp
    {
        Encrypt,
        Decrypt,
        EncryptAuth,
        DecryptAuth,
    }

    /// <summary>
    /// Direct-call buffer-convention dispatcher with a per-encryptor
    /// output cache. Skips the size-probe round-trip the lower-level
    /// FFI helpers use: pre-allocates output capacity from a 1.25×
    /// upper bound (the empirical ITB ciphertext-expansion factor
    /// measured at ≤ 1.155 across every primitive / mode / nonce /
    /// payload-size combination) and falls through to an explicit
    /// grow-and-retry only on the rare under-shoot. Reuses the buffer
    /// across calls; <see cref="Close"/> / <see cref="Dispose"/> wipe
    /// it before drop.
    ///
    /// The current <c>Easy_Encrypt</c> / <c>Easy_Decrypt</c> C ABI
    /// does the full crypto on every call regardless of out-buffer
    /// capacity (it computes the result internally, then returns
    /// <c>BUFFER_TOO_SMALL</c> without exposing the work) — so the
    /// pre-allocation here avoids paying for a duplicate encrypt /
    /// decrypt on each managed-side call.
    /// </summary>
    private unsafe byte[] CipherCall(CipherOp op, ReadOnlySpan<byte> payload)
    {
        ThrowIfClosed();
        var payloadLen = payload.Length;
        // 1.25× + 128 KiB headroom comfortably exceeds the worst-case
        // expansion observed across the primitive / mode / nonce-bits
        // / barrier-fill matrix; bf=32 with payloads near 1 MiB pushes
        // the absolute ratio to ~1.346, leaving roughly 100 KiB of
        // residual margin over the 1.25× term that the constant pad
        // must absorb. The 128 KiB pad covers that worst case (and
        // the ratio tapers below 1.25× + small-K beyond a few MiB as
        // the bf-induced sqrt-shaped border overhead becomes
        // asymptotically negligible). Floor at 128 KiB so the very-
        // small payload case still gets a usable buffer that handles
        // the Triple + auth-MAC + bf=32 short-payload expansion
        // (~35 KiB at ptlen=1).
        var cap = Math.Max(131072, payloadLen * 5 / 4 + 131072);
        EnsureCapacity(cap);

        nuint outLen;
        int rc;
        fixed (byte* inPtr = payload)
        fixed (byte* outPtr = _outputBuffer)
        {
            rc = InvokeCipher(op, inPtr, (nuint)payloadLen, outPtr, (nuint)_outputBuffer.Length, out outLen);
        }

        if (rc == Status.BufferTooSmall)
        {
            // Pre-allocation was too tight (extremely rare given the
            // 1.25× safety margin) — grow exactly to the required
            // size and retry. The first call already paid for the
            // underlying crypto via the current C ABI's
            // full-encrypt-on-every-call contract, so the retry runs
            // the work again; this is strictly the fallback path and
            // not the hot loop.
            var need = (int)outLen;
            EnsureCapacity(need);
            fixed (byte* inPtr = payload)
            fixed (byte* outPtr = _outputBuffer)
            {
                rc = InvokeCipher(op, inPtr, (nuint)payloadLen, outPtr, (nuint)_outputBuffer.Length, out outLen);
            }
        }

        ItbException.Check(rc);

        var n = (int)outLen;
        var result = new byte[n];
        Buffer.BlockCopy(_outputBuffer, 0, result, 0, n);
        return result;
    }

    private unsafe int InvokeCipher(
        CipherOp op,
        byte* inPtr,
        nuint inLen,
        byte* outPtr,
        nuint outCap,
        out nuint outLen)
    {
        return op switch
        {
            CipherOp.Encrypt =>
                ItbNative.ITB_Easy_Encrypt(_handle, inPtr, inLen, outPtr, outCap, out outLen),
            CipherOp.Decrypt =>
                ItbNative.ITB_Easy_Decrypt(_handle, inPtr, inLen, outPtr, outCap, out outLen),
            CipherOp.EncryptAuth =>
                ItbNative.ITB_Easy_EncryptAuth(_handle, inPtr, inLen, outPtr, outCap, out outLen),
            CipherOp.DecryptAuth =>
                ItbNative.ITB_Easy_DecryptAuth(_handle, inPtr, inLen, outPtr, outCap, out outLen),
            _ => throw new ArgumentOutOfRangeException(nameof(op)),
        };
    }

    private void EnsureCapacity(int needed)
    {
        if (_outputBuffer.Length < needed)
        {
            // Wipe the previous buffer before dropping the reference so
            // residual ciphertext / plaintext cannot linger in heap
            // garbage between cipher calls. The wipe-on-grow contract
            // pairs with the wipe-on-Dispose contract documented on the
            // class.
            if (_outputBuffer.Length > 0)
            {
                Array.Clear(_outputBuffer, 0, _outputBuffer.Length);
            }
            _outputBuffer = new byte[needed];
        }
    }

    // ----------------------------------------------------------------
    // Per-instance configuration setters
    // ----------------------------------------------------------------

    /// <summary>
    /// Override the nonce size for this encryptor's subsequent
    /// encrypt / decrypt calls. Valid values: 128, 256, 512.
    /// Mutates only this encryptor's Config copy; process-wide
    /// <see cref="Library.NonceBits"/> is unaffected.
    /// </summary>
    public void SetNonceBits(int n)
    {
        ThrowIfClosed();
        ItbException.Check(ItbNative.ITB_Easy_SetNonceBits(_handle, n));
    }

    /// <summary>
    /// Override the CSPRNG barrier-fill margin for this encryptor.
    /// Valid values: 1, 2, 4, 8, 16, 32. Asymmetric — the receiver
    /// does not need the same value as the sender.
    /// </summary>
    public void SetBarrierFill(int n)
    {
        ThrowIfClosed();
        ItbException.Check(ItbNative.ITB_Easy_SetBarrierFill(_handle, n));
    }

    /// <summary>
    /// 0 = byte-level split (default); non-zero = bit-level Bit Soup
    /// split. <b>Mode-dependent overlay engagement:</b> in Single
    /// Ouroboros (mode = 1), enabling bit-soup activates the
    /// lock-soup overlay at encrypt time even though
    /// <c>cfg.LockSoup</c> stays 0; in Triple Ouroboros (mode = 3),
    /// bit-soup operates independently of lock-soup.
    /// </summary>
    public void SetBitSoup(int mode)
    {
        ThrowIfClosed();
        ItbException.Check(ItbNative.ITB_Easy_SetBitSoup(_handle, mode));
    }

    /// <summary>
    /// 0 = off (default); non-zero = on. Auto-couples
    /// <c>BitSoup=1</c> on this encryptor (always, both modes — Lock
    /// Soup layers on top of bit soup).
    /// </summary>
    public void SetLockSoup(int mode)
    {
        ThrowIfClosed();
        ItbException.Check(ItbNative.ITB_Easy_SetLockSoup(_handle, mode));
    }

    /// <summary>
    /// 0 = off; 1 = on. When engaged, allocates a dedicated lockSeed
    /// and routes the bit-permutation overlay through it; this
    /// auto-couples <c>LockSoup=1 + BitSoup=1</c> on this encryptor
    /// (always, both Single and Triple Ouroboros modes).
    /// </summary>
    /// <remarks>
    /// Calling after the first encrypt surfaces
    /// <see cref="ItbException"/> with status
    /// <c>EasyLockSeedAfterEncrypt</c>.
    /// </remarks>
    public void SetLockSeed(int mode)
    {
        ThrowIfClosed();
        ItbException.Check(ItbNative.ITB_Easy_SetLockSeed(_handle, mode));
    }

    /// <summary>
    /// Per-instance streaming chunk-size override (0 = auto-detect
    /// via <c>itb.ChunkSize</c> on the Go side). Capped at 64 MiB on
    /// the encrypt path and 80 MiB on the decrypt path.
    /// </summary>
    public void SetChunkSize(int n)
    {
        ThrowIfClosed();
        ItbException.Check(ItbNative.ITB_Easy_SetChunkSize(_handle, n));
    }

    // ----------------------------------------------------------------
    // State serialization
    // ----------------------------------------------------------------

    /// <summary>
    /// Serialises the encryptor's full state (PRF keys, seed
    /// components, MAC key, dedicated lockSeed material when active)
    /// as a JSON blob. The caller saves the bytes as it sees fit
    /// (disk, KMS, wire) and later passes them back to
    /// <see cref="Import"/> on a fresh encryptor to reconstruct the
    /// exact state.
    /// </summary>
    /// <remarks>
    /// Per-instance configuration knobs (NonceBits, BarrierFill,
    /// BitSoup, LockSoup, ChunkSize) are NOT carried in the v1 blob
    /// — both sides communicate them via deployment config. LockSeed
    /// is carried because activating it changes the structural seed
    /// count.
    /// </remarks>
    public unsafe byte[] Export()
    {
        ThrowIfClosed();
        var rc = ItbNative.ITB_Easy_Export(_handle, null, 0, out var outLen);
        if (rc == Status.Ok)
        {
            return Array.Empty<byte>();
        }
        if (rc != Status.BufferTooSmall)
        {
            throw ItbException.FromStatus(rc);
        }
        var need = outLen;
        var buf = new byte[(int)need];
        int rc2;
        nuint outLen2;
        fixed (byte* p = buf)
        {
            rc2 = ItbNative.ITB_Easy_Export(_handle, p, need, out outLen2);
        }
        ItbException.Check(rc2);
        if ((int)outLen2 < buf.Length)
        {
            Array.Resize(ref buf, (int)outLen2);
        }
        return buf;
    }

    // ----------------------------------------------------------------
    // Streaming AEAD entry points
    // ----------------------------------------------------------------

    /// <summary>
    /// Reads plaintext from <paramref name="input"/> until end of
    /// stream, encrypts each chunk under the Streaming AEAD
    /// construction bound to this encryptor's seeds + MAC closure,
    /// and writes the concatenated <c>stream_id || chunk_0 || chunk_1 || ...</c>
    /// transcript to <paramref name="output"/>. Neither stream is
    /// disposed by this method.
    /// </summary>
    /// <remarks>
    /// <para><paramref name="chunkSize"/> defaults to
    /// <see cref="StreamDefaults.DefaultChunkSize"/> (16 MiB) when
    /// not supplied; it must be positive. The 32-byte CSPRNG
    /// <c>stream_id</c> prefix is generated server-side per call;
    /// the running cumulative pixel offset and the terminating
    /// chunk's <c>final_flag = true</c> are managed
    /// internally.</para>
    /// <para>Empty stream is permitted — emits the 32-byte prefix
    /// followed by a single terminating chunk carrying zero
    /// plaintext bytes.</para>
    /// </remarks>
    public unsafe void EncryptStreamAuth(
        Stream input, Stream output,
        int chunkSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ThrowIfClosed();
        if (chunkSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "chunkSize must be positive");
        }
        try
        {
            var streamId = StreamAuthInternal.GenerateStreamId();
            output.Write(streamId, 0, streamId.Length);
            var headerSz = HeaderSize;
            ulong cumPixels = 0;
            // Contiguous staging buffer — fills directly from input.
            // Reads into staging[filled..]; on each iteration peek 1
            // byte ahead (via Stream.ReadByte) to determine whether the
            // current chunk is final. The peeked byte (if any) carries
            // over into the next iteration as staging[0].
            var staging = new byte[chunkSize];
            var filled = 0;
            var eof = false;
            while (!eof)
            {
                while (filled < chunkSize)
                {
                    var n = input.Read(staging, filled, chunkSize - filled);
                    if (n == 0)
                    {
                        eof = true;
                        break;
                    }
                    filled += n;
                }
                if (eof && filled == 0)
                {
                    // Empty stream — emit a single 0-byte terminating chunk.
                    // Routes through the per-encryptor _outputBuffer cache
                    // (Bonus 1 in .NEXTBIND.md §7.1) so the streaming
                    // hot loop amortises allocation across every chunk
                    // just like Encryptor.CipherCall does.
                    var (ctBuf0, ctLen0) = StreamAuthEasy.Emit(_handle,
                        staging, 0, streamId, cumPixels, true,
                        ref _outputBuffer);
                    output.Write(ctBuf0, 0, ctLen0);
                    break;
                }
                // Peek 1 byte to determine whether this is the final chunk.
                var probe = input.ReadByte();
                var isFinal = probe < 0;
                // Routes through the per-encryptor _outputBuffer cache
                // (Bonus 1 in .NEXTBIND.md §7.1) — same scope as the
                // Single Message CipherCall path, reused across every chunk.
                var (ctBuf, ctLen) = StreamAuthEasy.Emit(_handle,
                    staging, filled, streamId, cumPixels, isFinal,
                    ref _outputBuffer);
                output.Write(ctBuf, 0, ctLen);
                if (ctLen >= headerSz)
                {
                    var w = StreamAuthInternal.ReadBe16(ctBuf, headerSz - 4);
                    var h = StreamAuthInternal.ReadBe16(ctBuf, headerSz - 2);
                    cumPixels += (ulong)w * (ulong)h;
                }
                // Wipe the staging plaintext residue before the next chunk.
                Array.Clear(staging, 0, filled);
                if (isFinal)
                {
                    break;
                }
                // Carry the probed byte into the next iteration.
                staging[0] = (byte)probe;
                filled = 1;
            }
            Array.Clear(staging, 0, staging.Length);
        }
        finally
        {
            GC.KeepAlive(this);
        }
    }

    /// <summary>
    /// Reads a Streaming AEAD transcript from <paramref name="input"/>
    /// until end of stream and writes the recovered plaintext to
    /// <paramref name="output"/>. Surfaces
    /// <see cref="ItbStreamTruncatedException"/> when the input
    /// exhausts without a terminating chunk,
    /// <see cref="ItbStreamAfterFinalException"/> when bytes follow
    /// the terminator, and <see cref="ItbException"/> with status
    /// <see cref="StatusCode.MacFailure"/> on any per-chunk MAC
    /// mismatch.
    /// </summary>
    public unsafe void DecryptStreamAuth(
        Stream input, Stream output,
        int readSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ThrowIfClosed();
        if (readSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "readSize must be positive");
        }
        try
        {
            var headerSz = HeaderSize;
            // Contiguous accumulator — accum[accumStart..accumEnd) holds
            // the unparsed wire bytes belonging to chunks not yet
            // consumed. Slides via a head index (accumStart) instead of
            // List<byte>.RemoveRange; compacts when the head crosses
            // half-way through the buffer to bound memory.
            var accum = new byte[Math.Max(readSize * 2, 1 << 20)];
            var accumStart = 0;
            var accumEnd = 0;
            var sidHave = 0;
            var streamId = new byte[StreamAuthInternal.StreamIdLen];
            ulong cumPixels = 0;
            var seenFinal = false;
            var readBuf = new byte[readSize];
            while (true)
            {
                var n = input.Read(readBuf, 0, readBuf.Length);
                if (n == 0)
                {
                    if (sidHave < StreamAuthInternal.StreamIdLen)
                    {
                        throw new ItbStreamTruncatedException(
                            StatusCode.StreamTruncated,
                            "auth stream: prefix never observed");
                    }
                    while (!seenFinal && (accumEnd - accumStart) >= headerSz)
                    {
                        var cl = ParseChunkLen(
                            new ReadOnlySpan<byte>(accum, accumStart, headerSz));
                        if ((accumEnd - accumStart) < cl)
                        {
                            break;
                        }
                        var w = StreamAuthInternal.ReadBe16(accum, accumStart + headerSz - 4);
                        var h = StreamAuthInternal.ReadBe16(accum, accumStart + headerSz - 2);
                        var pixels = (ulong)w * (ulong)h;
                        var chunk = new byte[cl];
                        Buffer.BlockCopy(accum, accumStart, chunk, 0, cl);
                        accumStart += cl;
                        // Routes through the per-encryptor _outputBuffer
                        // cache (Bonus 1 in .NEXTBIND.md §7.1) — same
                        // scope as the Single Message CipherCall path,
                        // reused across every chunk.
                        var (ptBuf, ptLen, ff) = StreamAuthEasy.Consume(
                            _handle, chunk, chunk.Length, streamId, cumPixels,
                            ref _outputBuffer);
                        output.Write(ptBuf, 0, ptLen);
                        Array.Clear(ptBuf, 0, ptLen);
                        cumPixels += pixels;
                        if (ff)
                        {
                            seenFinal = true;
                        }
                    }
                    if (!seenFinal)
                    {
                        throw new ItbStreamTruncatedException(
                            StatusCode.StreamTruncated,
                            "auth stream: terminator never observed");
                    }
                    if ((accumEnd - accumStart) > 0)
                    {
                        throw new ItbStreamAfterFinalException(
                            StatusCode.StreamAfterFinal,
                            "auth stream: trailing bytes after terminator");
                    }
                    Array.Clear(readBuf, 0, readBuf.Length);
                    Array.Clear(accum, 0, accum.Length);
                    return;
                }
                var off = 0;
                if (sidHave < StreamAuthInternal.StreamIdLen)
                {
                    var need = StreamAuthInternal.StreamIdLen - sidHave;
                    var take = Math.Min(need, n);
                    Buffer.BlockCopy(readBuf, 0, streamId, sidHave, take);
                    sidHave += take;
                    off = take;
                }
                if (off < n)
                {
                    var add = n - off;
                    // Compact if there isn't enough tail space to absorb
                    // `add` bytes; grow if the live region itself is
                    // larger than the current capacity.
                    if (accumEnd + add > accum.Length)
                    {
                        var live = accumEnd - accumStart;
                        if (live + add > accum.Length)
                        {
                            var newCap = accum.Length;
                            while (newCap < live + add) { newCap *= 2; }
                            var grown = new byte[newCap];
                            if (live > 0)
                            {
                                Buffer.BlockCopy(accum, accumStart, grown, 0, live);
                            }
                            Array.Clear(accum, 0, accum.Length);
                            accum = grown;
                        }
                        else if (accumStart > 0)
                        {
                            if (live > 0)
                            {
                                Buffer.BlockCopy(accum, accumStart, accum, 0, live);
                            }
                            // Wipe the now-stale tail region.
                            Array.Clear(accum, live, accum.Length - live);
                        }
                        accumStart = 0;
                        accumEnd = live;
                    }
                    Buffer.BlockCopy(readBuf, off, accum, accumEnd, add);
                    accumEnd += add;
                }
                if (sidHave < StreamAuthInternal.StreamIdLen)
                {
                    continue;
                }
                while (true)
                {
                    if (seenFinal)
                    {
                        if ((accumEnd - accumStart) > 0)
                        {
                            throw new ItbStreamAfterFinalException(
                                StatusCode.StreamAfterFinal,
                                "auth stream: trailing bytes after terminator");
                        }
                        break;
                    }
                    if ((accumEnd - accumStart) < headerSz)
                    {
                        break;
                    }
                    var cl = ParseChunkLen(
                        new ReadOnlySpan<byte>(accum, accumStart, headerSz));
                    if ((accumEnd - accumStart) < cl)
                    {
                        break;
                    }
                    var w = StreamAuthInternal.ReadBe16(accum, accumStart + headerSz - 4);
                    var h = StreamAuthInternal.ReadBe16(accum, accumStart + headerSz - 2);
                    var pixels = (ulong)w * (ulong)h;
                    var chunk = new byte[cl];
                    Buffer.BlockCopy(accum, accumStart, chunk, 0, cl);
                    accumStart += cl;
                    // Compact when the head drifts past half the buffer
                    // — keeps the live region near offset 0 so
                    // subsequent reads can append without growing.
                    if (accumStart > accum.Length / 2)
                    {
                        var live = accumEnd - accumStart;
                        if (live > 0)
                        {
                            Buffer.BlockCopy(accum, accumStart, accum, 0, live);
                        }
                        Array.Clear(accum, live, accum.Length - live);
                        accumStart = 0;
                        accumEnd = live;
                    }
                    // Routes through the per-encryptor _outputBuffer
                    // cache (Bonus 1 in .NEXTBIND.md §7.1) — same scope
                    // as the Single Message CipherCall path, reused across
                    // every chunk.
                    var (ptBuf, ptLen, ff) = StreamAuthEasy.Consume(
                        _handle, chunk, chunk.Length, streamId, cumPixels,
                        ref _outputBuffer);
                    output.Write(ptBuf, 0, ptLen);
                    Array.Clear(ptBuf, 0, ptLen);
                    cumPixels += pixels;
                    if (ff)
                    {
                        seenFinal = true;
                    }
                }
            }
        }
        finally
        {
            GC.KeepAlive(this);
        }
    }

    /// <summary>
    /// Replaces the encryptor's PRF keys, seed components, MAC key,
    /// and (optionally) dedicated lockSeed material with the values
    /// carried in a JSON <paramref name="blob"/> produced by a prior
    /// <see cref="Export"/> call.
    /// </summary>
    /// <remarks>
    /// On any failure the encryptor's pre-import state is unchanged
    /// (the underlying Go-side <c>Encryptor.Import</c> is
    /// transactional). Mismatch on primitive / key bits / mode / mac
    /// surfaces as <see cref="ItbEasyMismatchException"/> carrying
    /// the offending JSON field name on its
    /// <see cref="ItbEasyMismatchException.Field"/> property.
    /// </remarks>
    public unsafe void Import(ReadOnlySpan<byte> blob)
    {
        ThrowIfClosed();
        int rc;
        fixed (byte* p = blob)
        {
            rc = ItbNative.ITB_Easy_Import(_handle, p, (nuint)blob.Length);
        }
        ItbException.Check(rc);
    }

    /// <summary>
    /// Parses a state blob's metadata <c>(Primitive, KeyBits, Mode,
    /// MacName)</c> without performing full validation, allowing a
    /// caller to inspect a saved blob before constructing a matching
    /// encryptor.
    /// </summary>
    /// <remarks>
    /// Surfaces <see cref="ItbException"/> with status
    /// <c>EasyMalformed</c> on JSON parse failure / kind mismatch /
    /// too-new version / unknown mode value.
    /// </remarks>
    public static unsafe EncryptorConfig PeekConfig(ReadOnlySpan<byte> blob)
    {
        // Probe both string sizes first.
        nuint primLen;
        nuint macLen;
        int kbOut;
        int modeOut;
        int rc;
        fixed (byte* blobPtr = blob)
        {
            rc = ItbNative.ITB_Easy_PeekConfig(
                blobPtr, (nuint)blob.Length,
                null, 0, out primLen,
                out kbOut, out modeOut,
                null, 0, out macLen);
        }
        if (rc != Status.Ok && rc != Status.BufferTooSmall)
        {
            throw ItbException.FromStatus(rc);
        }

        var primCap = primLen;
        var macCap = macLen;
        var primBuf = new byte[(int)primCap];
        var macBuf = new byte[(int)macCap];
        int rc2;
        nuint primLen2;
        nuint macLen2;
        int kbOut2;
        int modeOut2;
        fixed (byte* blobPtr = blob)
        fixed (byte* primPtr = primBuf)
        fixed (byte* macPtr = macBuf)
        {
            rc2 = ItbNative.ITB_Easy_PeekConfig(
                blobPtr, (nuint)blob.Length,
                primPtr, primCap, out primLen2,
                out kbOut2, out modeOut2,
                macPtr, macCap, out macLen2);
        }
        ItbException.Check(rc2);

        var primN = primLen2 > 0 ? (int)primLen2 - 1 : 0;
        var macN = macLen2 > 0 ? (int)macLen2 - 1 : 0;
        var primitive = Encoding.UTF8.GetString(primBuf, 0, primN);
        var macName = Encoding.UTF8.GetString(macBuf, 0, macN);
        return new EncryptorConfig(primitive, kbOut2, modeOut2, macName);
    }

    // ----------------------------------------------------------------
    // Lifecycle
    // ----------------------------------------------------------------

    /// <summary>
    /// Zeroes the encryptor's PRF keys, MAC key, and seed components,
    /// and marks the encryptor as closed. Idempotent — multiple
    /// <see cref="Close"/> calls return without error. Also wipes the
    /// per-encryptor output buffer cache so the most recent
    /// ciphertext or plaintext does not linger in heap memory after
    /// the encryptor's working set has been zeroed on the Go side.
    /// </summary>
    /// <remarks>
    /// <see cref="Close"/> does NOT release the underlying libitb
    /// handle slot; it only zeros the working set. Use
    /// <see cref="Dispose"/> for full handle release. After
    /// <see cref="Close"/> the handle remains valid but every
    /// subsequent libitb call surfaces <see cref="ItbException"/>
    /// with status <c>EasyClosed</c>.
    /// </remarks>
    public void Close()
    {
        // Wipe the cached output buffer regardless of close state —
        // repeated close calls keep the cache wiped without racing
        // the Go-side close.
        WipeOutputBuffer();
        if (_closed || _handle == 0)
        {
            // Idempotent — already closed.
            _closed = true;
            return;
        }
        var rc = ItbNative.ITB_Easy_Close(_handle);
        _closed = true;
        // Close is documented as idempotent on the Go side; treat
        // any non-OK return after close as a bug.
        ItbException.Check(rc);
    }

    /// <summary>
    /// Releases the underlying libitb handle. Wipes the per-encryptor
    /// output buffer cache before the call so the most recent
    /// ciphertext or plaintext does not linger in heap memory.
    /// Idempotent — calling <see cref="Dispose"/> on an already-disposed
    /// encryptor returns silently. Subsequent method calls on the
    /// instance throw <see cref="ItbException"/> with status
    /// <see cref="Native.Status.EasyClosed"/>.
    /// </summary>
    public void Dispose()
    {
        WipeOutputBuffer();
        var h = _handle;
        _handle = 0;
        _closed = true;
        if (h != 0)
        {
            ItbNative.ITB_Easy_Free(h);
        }
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Best-effort handle release for the missed-Dispose path. Errors
    /// during finalization are swallowed because there is no path to
    /// surface them and process-shutdown ordering can be
    /// unpredictable.
    /// </summary>
    ~Encryptor()
    {
        if (_handle != 0)
        {
            try
            {
                WipeOutputBuffer();
                ItbNative.ITB_Easy_Free(_handle);
            }
            catch
            {
                // Swallow — finalizer cannot surface failures.
            }
            _handle = 0;
        }
        _closed = true;
    }

    private void WipeOutputBuffer()
    {
        if (_outputBuffer.Length > 0)
        {
            Array.Clear(_outputBuffer, 0, _outputBuffer.Length);
        }
    }

    /// <summary>
    /// Preflight rejection for closed / disposed encryptors. Throws
    /// <see cref="ItbException"/> with status
    /// <see cref="Native.Status.EasyClosed"/> before any libitb FFI
    /// call so callers see the canonical "encryptor has been closed"
    /// code regardless of whether the underlying handle slot has
    /// merely been zeroed (post-<see cref="Close"/>) or has been
    /// released back to libitb (post-<see cref="Dispose"/>).
    /// </summary>
    private void ThrowIfClosed()
    {
        if (_closed || _handle == 0)
        {
            throw new ItbException(
                Native.Status.EasyClosed, "encryptor has been closed");
        }
    }
}
