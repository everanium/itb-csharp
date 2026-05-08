// Library-level read-only metadata, registry enumerators, mutable
// process-global configuration, and the stream-frame parsing helper.
//
// All members are static. The class exposes the libitb free-function
// surface that is not tied to a specific seed / MAC / encryptor
// instance: hash + MAC catalogs, version, the global Set / Get
// configuration knobs, and the ParseChunkLen helper used by streaming
// consumers.

using Itb.Native;

namespace Itb;

/// <summary>
/// Metadata about a hash primitive that ITB exposes (one entry per
/// shipping primitive in libitb's hash registry).
/// </summary>
public readonly record struct HashInfo(string Name, int Width);

/// <summary>
/// Metadata about a MAC primitive that ITB exposes for authenticated
/// modes (one entry per shipping MAC in libitb's MAC registry).
/// </summary>
public readonly record struct MacInfo(string Name, int KeySize, int TagSize, int MinKeyBytes);

/// <summary>
/// Library-level metadata, registry enumerators, mutable process-global
/// configuration, and the stream-frame parsing helper.
/// </summary>
public static class Library
{
    /// <summary>libitb version string (e.g. "0.1.0").</summary>
    public static unsafe string Version =>
        ReadString.Read(ItbNative.ITB_Version);

    /// <summary>
    /// Reads <c>ITB_LastError</c> for the most recent non-OK status
    /// returned on this thread. Empty string when no error has been
    /// recorded. The textual message follows C errno discipline: it
    /// is published through a process-wide atomic, so a sibling
    /// thread that calls into libitb between the failing call and
    /// this read can overwrite the message. The structural status
    /// code on the failing call is unaffected — only the textual
    /// message is racy. <see cref="ItbException"/> already attaches
    /// this string to its <see cref="Exception.Message"/> at throw
    /// time; this static accessor is exposed for callers that want
    /// to read the diagnostic independently of the exception path.
    /// </summary>
    public static unsafe string LastError =>
        ReadString.Read(ItbNative.ITB_LastError);

    /// <summary>
    /// Reads the offending JSON field name from the most recent
    /// <c>ITB_Easy_Import</c> call that returned
    /// <see cref="StatusCode.EasyMismatch"/> on this thread. Empty
    /// string when the most recent failure was not a mismatch.
    /// <see cref="Encryptor.Import"/> already attaches this name to
    /// the raised <see cref="ItbEasyMismatchException.Field"/>
    /// property; this static accessor is exposed for callers that
    /// need to read the field independently of the error path.
    /// </summary>
    public static unsafe string LastMismatchField =>
        ReadString.Read(ItbNative.ITB_Easy_LastMismatchField);

    /// <summary>Maximum hash-key width supported by libitb, in bits.
    /// 2048 in the shipping build; check at runtime to validate
    /// caller-supplied <c>keyBits</c> arguments.</summary>
    public static int MaxKeyBits => ItbNative.ITB_MaxKeyBits();

    /// <summary>Number of parallel processing channels libitb runs at
    /// the chunk-encrypt level. 8 in the shipping build.</summary>
    public static int Channels => ItbNative.ITB_Channels();

    /// <summary>Bytes per chunk header in the on-the-wire stream
    /// frame. 20 by default, 36 under <see cref="NonceBits"/> = 256,
    /// 68 under <see cref="NonceBits"/> = 512. Stream consumers read
    /// this many bytes off the framing before feeding them into
    /// <see cref="ParseChunkLen"/>.</summary>
    public static int HeaderSize => ItbNative.ITB_HeaderSize();

    /// <summary>Enumerates every hash primitive shipped in this libitb
    /// build, paired with its width in bits.</summary>
    public static unsafe IReadOnlyList<HashInfo> ListHashes()
    {
        var n = ItbNative.ITB_HashCount();
        var result = new List<HashInfo>(n);
        for (var i = 0; i < n; i++)
        {
            var idx = i;
            var name = ReadString.Read((byte* buf, nuint cap, out nuint outLen) =>
                ItbNative.ITB_HashName(idx, buf, cap, out outLen));
            var width = ItbNative.ITB_HashWidth(i);
            result.Add(new HashInfo(name, width));
        }
        return result;
    }

    /// <summary>Enumerates every MAC primitive shipped in this libitb
    /// build, paired with its canonical key size, tag size, and
    /// minimum-key requirement (all in bytes).</summary>
    public static unsafe IReadOnlyList<MacInfo> ListMacs()
    {
        var n = ItbNative.ITB_MACCount();
        var result = new List<MacInfo>(n);
        for (var i = 0; i < n; i++)
        {
            var idx = i;
            var name = ReadString.Read((byte* buf, nuint cap, out nuint outLen) =>
                ItbNative.ITB_MACName(idx, buf, cap, out outLen));
            var keySize = ItbNative.ITB_MACKeySize(i);
            var tagSize = ItbNative.ITB_MACTagSize(i);
            var minKeyBytes = ItbNative.ITB_MACMinKeyBytes(i);
            result.Add(new MacInfo(name, keySize, tagSize, minKeyBytes));
        }
        return result;
    }

    /// <summary>
    /// Parses the chunk-length field out of the stream header. Returns
    /// the chunk's plaintext length in bytes; the caller reads
    /// (<see cref="HeaderSize"/> + return-value) bytes for the next
    /// frame. The buffer must contain at least <see cref="HeaderSize"/>
    /// bytes.
    /// </summary>
    public static unsafe int ParseChunkLen(ReadOnlySpan<byte> header)
    {
        nuint outChunkLen;
        int rc;
        fixed (byte* p = header)
        {
            rc = ItbNative.ITB_ParseChunkLen(p, (nuint)header.Length, out outChunkLen);
        }
        ItbException.Check(rc);
        return (int)outChunkLen;
    }

    /// <summary>
    /// Process-global Bit Soup mode (0 = byte-level Ouroboros,
    /// 1 = bit-soup). Affects only Encryptor instances created AFTER
    /// the property is set; pre-existing instances retain their
    /// at-construction-time setting. Independent of <see cref="LockSoup"/>
    /// at the setter level — there is no <c>BitSoup → LockSoup</c>
    /// cascade; the cascade direction is one-way <c>LockSoup(1) →
    /// BitSoup(1)</c>. In Single Ouroboros, either flag alone
    /// activates the dispatcher's keyed bit-permutation overlay.
    /// </summary>
    public static int BitSoup
    {
        get => ItbNative.ITB_GetBitSoup();
        set => ItbException.Check(ItbNative.ITB_SetBitSoup(value));
    }

    /// <summary>
    /// Process-global Lock Soup mode (0 = off, 1 = on). The Lock Soup
    /// step engages the per-cell PRF re-keying lane and pairs with
    /// <c>AttachLockSeed</c> on a noise seed. Setting a non-zero value
    /// auto-couples <see cref="BitSoup"/> = 1 (Lock Soup overlay layers
    /// on top of bit soup); the off-direction does not auto-disable
    /// <see cref="BitSoup"/>. Same lifecycle rules as <see cref="BitSoup"/>.
    /// </summary>
    public static int LockSoup
    {
        get => ItbNative.ITB_GetLockSoup();
        set => ItbException.Check(ItbNative.ITB_SetLockSoup(value));
    }

    /// <summary>
    /// Maximum number of worker threads libitb uses for chunk-level
    /// parallelism. 0 means "use Channels (8) workers". Affects all
    /// future Encrypt / Decrypt calls process-wide.
    /// </summary>
    public static int MaxWorkers
    {
        get => ItbNative.ITB_GetMaxWorkers();
        set => ItbException.Check(ItbNative.ITB_SetMaxWorkers(value));
    }

    /// <summary>
    /// Process-global nonce-bit width (128, 256, or 512). Affects the
    /// stream-frame header size — see <see cref="HeaderSize"/>. Same
    /// lifecycle rules as <see cref="BitSoup"/>: only Encryptor
    /// instances created after the property is set pick up the new
    /// value.
    /// </summary>
    public static int NonceBits
    {
        get => ItbNative.ITB_GetNonceBits();
        set => ItbException.Check(ItbNative.ITB_SetNonceBits(value));
    }

    /// <summary>
    /// Process-global barrier-fill rate (0 = no fill, 1 = full fill).
    /// Controls whether short final chunks are padded out to the
    /// chunk-size barrier. Same lifecycle rules as
    /// <see cref="BitSoup"/>.
    /// </summary>
    public static int BarrierFill
    {
        get => ItbNative.ITB_GetBarrierFill();
        set => ItbException.Check(ItbNative.ITB_SetBarrierFill(value));
    }
}
