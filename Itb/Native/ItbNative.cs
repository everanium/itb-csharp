// Source-generated P/Invoke surface over libitb's C ABI.
//
// Every signature mirrors a `//export` wrapper in cmd/cshared/main.go,
// canonicalised by cgo into dist/<os>-<arch>/libitb.h. The order of
// declarations in this file matches the order in libitb.h to make
// cross-reference straightforward.
//
// Type mapping
// ------------
//   C `int`        → `int`     (32-bit on every platform under .NET)
//   C `size_t`     → `nuint`   (host word size)
//   C `uintptr_t`  → `nuint`   (host word size; libitb handle)
//   C `uint64_t`   → `ulong`
//   C `uint8_t*`   → `byte*`   (raw byte buffer)
//   C `void*`      → `byte*`   (libitb buffer; always treated as bytes)
//   C `char*` (in) → `string`  (UTF-8 marshalled by source generator)
//   C `char*` (out)→ `byte*`   (raw byte buffer; UTF-8 decoded by caller)
//
// Threading note. `ITB_LastError` and `ITB_Easy_LastMismatchField` read
// process-global state that follows the C `errno` discipline: the most
// recent non-OK Status across the whole process wins, and a sibling
// thread that calls into libitb between the failing call and the
// diagnostic read may overwrite the message. Multi-threaded callers
// that need reliable diagnostic attribution should serialise FFI calls
// under a process-wide lock or accept that the textual message attached
// to <see cref="ItbException"/> may belong to a different call. The
// structural Status code on the failing call's return value is
// unaffected — only the textual diagnostic is racy.

using System.Runtime.InteropServices;

namespace Itb.Native;

internal static unsafe partial class ItbNative
{
    static ItbNative() => NativeLibraryLoader.EnsureRegistered();

    // ----------------------------------------------------------------
    // Library version + hash registry + last-error
    // ----------------------------------------------------------------

    [LibraryImport("libitb")]
    internal static partial int ITB_Version(byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_HashCount();

    [LibraryImport("libitb")]
    internal static partial int ITB_HashName(int i, byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_HashWidth(int i);

    [LibraryImport("libitb")]
    internal static partial int ITB_LastError(byte* @out, nuint capBytes, out nuint outLen);

    // ----------------------------------------------------------------
    // Seed lifecycle + accessors
    // ----------------------------------------------------------------

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_NewSeed(string hashName, int keyBits, out nuint outHandle);

    [LibraryImport("libitb")]
    internal static partial int ITB_FreeSeed(nuint handle);

    [LibraryImport("libitb")]
    internal static partial int ITB_SeedWidth(nuint handle, out int outStatus);

    [LibraryImport("libitb")]
    internal static partial int ITB_SeedHashName(nuint handle, byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_NewSeedFromComponents(
        string hashName,
        ulong* components,
        int componentsLen,
        byte* hashKey,
        int hashKeyLen,
        out nuint outHandle);

    [LibraryImport("libitb")]
    internal static partial int ITB_GetSeedHashKey(nuint handle, byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_GetSeedComponents(nuint handle, ulong* @out, int capCount, out int outLen);

    // ----------------------------------------------------------------
    // Low-level encrypt / decrypt — Single + Triple
    // ----------------------------------------------------------------

    [LibraryImport("libitb")]
    internal static partial int ITB_Encrypt(
        nuint noiseHandle,
        nuint dataHandle,
        nuint startHandle,
        byte* plaintext,
        nuint ptlen,
        byte* @out,
        nuint outCap,
        out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Decrypt(
        nuint noiseHandle,
        nuint dataHandle,
        nuint startHandle,
        byte* ciphertext,
        nuint ctlen,
        byte* @out,
        nuint outCap,
        out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Encrypt3(
        nuint noiseHandle,
        nuint dataHandle1,
        nuint dataHandle2,
        nuint dataHandle3,
        nuint startHandle1,
        nuint startHandle2,
        nuint startHandle3,
        byte* plaintext,
        nuint ptlen,
        byte* @out,
        nuint outCap,
        out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Decrypt3(
        nuint noiseHandle,
        nuint dataHandle1,
        nuint dataHandle2,
        nuint dataHandle3,
        nuint startHandle1,
        nuint startHandle2,
        nuint startHandle3,
        byte* ciphertext,
        nuint ctlen,
        byte* @out,
        nuint outCap,
        out nuint outLen);

    // ----------------------------------------------------------------
    // MAC registry + lifecycle
    // ----------------------------------------------------------------

    [LibraryImport("libitb")]
    internal static partial int ITB_MACCount();

    [LibraryImport("libitb")]
    internal static partial int ITB_MACName(int i, byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_MACKeySize(int i);

    [LibraryImport("libitb")]
    internal static partial int ITB_MACTagSize(int i);

    [LibraryImport("libitb")]
    internal static partial int ITB_MACMinKeyBytes(int i);

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_NewMAC(string macName, byte* key, nuint keyLen, out nuint outHandle);

    [LibraryImport("libitb")]
    internal static partial int ITB_FreeMAC(nuint handle);

    // ----------------------------------------------------------------
    // Authenticated encrypt / decrypt — Single + Triple
    // ----------------------------------------------------------------

    [LibraryImport("libitb")]
    internal static partial int ITB_EncryptAuth(
        nuint noiseHandle,
        nuint dataHandle,
        nuint startHandle,
        nuint macHandle,
        byte* plaintext,
        nuint ptlen,
        byte* @out,
        nuint outCap,
        out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_DecryptAuth(
        nuint noiseHandle,
        nuint dataHandle,
        nuint startHandle,
        nuint macHandle,
        byte* ciphertext,
        nuint ctlen,
        byte* @out,
        nuint outCap,
        out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_EncryptAuth3(
        nuint noiseHandle,
        nuint dataHandle1,
        nuint dataHandle2,
        nuint dataHandle3,
        nuint startHandle1,
        nuint startHandle2,
        nuint startHandle3,
        nuint macHandle,
        byte* plaintext,
        nuint ptlen,
        byte* @out,
        nuint outCap,
        out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_DecryptAuth3(
        nuint noiseHandle,
        nuint dataHandle1,
        nuint dataHandle2,
        nuint dataHandle3,
        nuint startHandle1,
        nuint startHandle2,
        nuint startHandle3,
        nuint macHandle,
        byte* ciphertext,
        nuint ctlen,
        byte* @out,
        nuint outCap,
        out nuint outLen);

    // ----------------------------------------------------------------
    // Process-global configuration getters / setters
    // ----------------------------------------------------------------

    [LibraryImport("libitb")]
    internal static partial int ITB_SetBitSoup(int mode);

    [LibraryImport("libitb")]
    internal static partial int ITB_GetBitSoup();

    [LibraryImport("libitb")]
    internal static partial int ITB_SetLockSoup(int mode);

    [LibraryImport("libitb")]
    internal static partial int ITB_GetLockSoup();

    [LibraryImport("libitb")]
    internal static partial int ITB_SetMaxWorkers(int n);

    [LibraryImport("libitb")]
    internal static partial int ITB_GetMaxWorkers();

    [LibraryImport("libitb")]
    internal static partial int ITB_SetNonceBits(int n);

    [LibraryImport("libitb")]
    internal static partial int ITB_GetNonceBits();

    [LibraryImport("libitb")]
    internal static partial int ITB_SetBarrierFill(int n);

    [LibraryImport("libitb")]
    internal static partial int ITB_GetBarrierFill();

    // ----------------------------------------------------------------
    // Stream support — chunk-length parsing + width / channel queries
    // ----------------------------------------------------------------

    [LibraryImport("libitb")]
    internal static partial int ITB_ParseChunkLen(byte* header, nuint headerLen, out nuint outChunkLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_MaxKeyBits();

    [LibraryImport("libitb")]
    internal static partial int ITB_Channels();

    [LibraryImport("libitb")]
    internal static partial int ITB_HeaderSize();

    // ----------------------------------------------------------------
    // Lock-seed attachment — couples a lock seed onto an existing
    // noise seed for the post-launch BitSoup + LockSoup + LockSeed path.
    // ----------------------------------------------------------------

    [LibraryImport("libitb")]
    internal static partial int ITB_AttachLockSeed(nuint noiseHandle, nuint lockHandle);

    // ----------------------------------------------------------------
    // Easy encryptor surface — wraps the github.com/everanium/itb/easy
    // sub-package; Single + Mixed entry points; configuration setters;
    // accessors for primitives / key bits / mode / MAC name / nonce
    // bits / header size / chunk-length parse; export / import; peek.
    // ----------------------------------------------------------------

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_Easy_New(string primitive, int keyBits, string macName, int mode, out nuint outHandle);

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_Easy_NewMixed(
        string primN,
        string primD,
        string primS,
        string? primL,
        int keyBits,
        string macName,
        out nuint outHandle);

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_Easy_NewMixed3(
        string primN,
        string primD1,
        string primD2,
        string primD3,
        string primS1,
        string primS2,
        string primS3,
        string? primL,
        int keyBits,
        string macName,
        out nuint outHandle);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_Free(nuint handle);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_PrimitiveAt(nuint handle, int slot, byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_IsMixed(nuint handle, out int outStatus);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_Encrypt(
        nuint handle,
        byte* plaintext,
        nuint ptlen,
        byte* @out,
        nuint outCap,
        out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_Decrypt(
        nuint handle,
        byte* ciphertext,
        nuint ctlen,
        byte* @out,
        nuint outCap,
        out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_EncryptAuth(
        nuint handle,
        byte* plaintext,
        nuint ptlen,
        byte* @out,
        nuint outCap,
        out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_DecryptAuth(
        nuint handle,
        byte* ciphertext,
        nuint ctlen,
        byte* @out,
        nuint outCap,
        out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_SetNonceBits(nuint handle, int n);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_SetBarrierFill(nuint handle, int n);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_SetBitSoup(nuint handle, int mode);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_SetLockSoup(nuint handle, int mode);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_SetLockSeed(nuint handle, int mode);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_SetChunkSize(nuint handle, int n);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_Primitive(nuint handle, byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_KeyBits(nuint handle, out int outStatus);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_Mode(nuint handle, out int outStatus);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_MACName(nuint handle, byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_SeedCount(nuint handle, out int outStatus);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_SeedComponents(nuint handle, int slot, ulong* @out, int capCount, out int outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_HasPRFKeys(nuint handle, out int outStatus);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_PRFKey(nuint handle, int slot, byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_MACKey(nuint handle, byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_Close(nuint handle);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_Export(nuint handle, byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_Import(nuint handle, byte* blob, nuint blobLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_PeekConfig(
        byte* blob,
        nuint blobLen,
        byte* primOut,
        nuint primCap,
        out nuint primLen,
        out int keyBitsOut,
        out int modeOut,
        byte* macOut,
        nuint macCap,
        out nuint macLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_LastMismatchField(byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_NonceBits(nuint handle, out int outStatus);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_HeaderSize(nuint handle, out int outStatus);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_ParseChunkLen(nuint handle, byte* header, nuint headerLen, out nuint outChunkLen);

    // ----------------------------------------------------------------
    // Native Blob — low-level state persistence (itb.Blob128 / 256 / 512)
    // ----------------------------------------------------------------

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob128_New(out nuint outHandle);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob256_New(out nuint outHandle);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob512_New(out nuint outHandle);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_Free(nuint handle);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_Width(nuint handle, out int outStatus);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_Mode(nuint handle, out int outStatus);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_SetKey(nuint handle, int slot, byte* key, nuint keyLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_GetKey(nuint handle, int slot, byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_SetComponents(nuint handle, int slot, ulong* comps, nuint count);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_GetComponents(nuint handle, int slot, ulong* @out, nuint outCap, out nuint outCount);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_SetMACKey(nuint handle, byte* key, nuint keyLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_GetMACKey(nuint handle, byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_SetMACName(nuint handle, byte* name, nuint nameLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_GetMACName(nuint handle, byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_Export(nuint handle, int optsBitmask, byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_Export3(nuint handle, int optsBitmask, byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_Import(nuint handle, byte* blob, nuint blobLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Blob_Import3(nuint handle, byte* blob, nuint blobLen);

    // ----------------------------------------------------------------
    // Streaming AEAD per-chunk dispatch — Single Ouroboros (3 seeds + MAC).
    // streamID points to a 32-byte buffer (length fixed by the
    // Streaming AEAD construction). cumulativePixelOffset is the
    // running sum of W*H over preceding chunks; finalFlag is non-zero
    // for the terminating chunk. finalFlagOut on the decrypt side
    // receives the recovered flag value (0 / 1).
    // ----------------------------------------------------------------

    [LibraryImport("libitb")]
    internal static partial int ITB_EncryptStreamAuthenticated128(
        nuint noiseHandle, nuint dataHandle, nuint startHandle, nuint macHandle,
        byte* plaintext, nuint ptlen,
        byte* streamID, ulong cumulativePixelOffset, int finalFlag,
        byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_EncryptStreamAuthenticated256(
        nuint noiseHandle, nuint dataHandle, nuint startHandle, nuint macHandle,
        byte* plaintext, nuint ptlen,
        byte* streamID, ulong cumulativePixelOffset, int finalFlag,
        byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_EncryptStreamAuthenticated512(
        nuint noiseHandle, nuint dataHandle, nuint startHandle, nuint macHandle,
        byte* plaintext, nuint ptlen,
        byte* streamID, ulong cumulativePixelOffset, int finalFlag,
        byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_DecryptStreamAuthenticated128(
        nuint noiseHandle, nuint dataHandle, nuint startHandle, nuint macHandle,
        byte* ciphertext, nuint ctlen,
        byte* streamID, ulong cumulativePixelOffset,
        byte* @out, nuint outCap, out nuint outLen,
        out int finalFlagOut);

    [LibraryImport("libitb")]
    internal static partial int ITB_DecryptStreamAuthenticated256(
        nuint noiseHandle, nuint dataHandle, nuint startHandle, nuint macHandle,
        byte* ciphertext, nuint ctlen,
        byte* streamID, ulong cumulativePixelOffset,
        byte* @out, nuint outCap, out nuint outLen,
        out int finalFlagOut);

    [LibraryImport("libitb")]
    internal static partial int ITB_DecryptStreamAuthenticated512(
        nuint noiseHandle, nuint dataHandle, nuint startHandle, nuint macHandle,
        byte* ciphertext, nuint ctlen,
        byte* streamID, ulong cumulativePixelOffset,
        byte* @out, nuint outCap, out nuint outLen,
        out int finalFlagOut);

    // Streaming AEAD per-chunk dispatch — Triple Ouroboros (7 seeds + MAC).

    [LibraryImport("libitb")]
    internal static partial int ITB_EncryptStreamAuthenticated3x128(
        nuint noiseHandle,
        nuint dataHandle1, nuint dataHandle2, nuint dataHandle3,
        nuint startHandle1, nuint startHandle2, nuint startHandle3,
        nuint macHandle,
        byte* plaintext, nuint ptlen,
        byte* streamID, ulong cumulativePixelOffset, int finalFlag,
        byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_EncryptStreamAuthenticated3x256(
        nuint noiseHandle,
        nuint dataHandle1, nuint dataHandle2, nuint dataHandle3,
        nuint startHandle1, nuint startHandle2, nuint startHandle3,
        nuint macHandle,
        byte* plaintext, nuint ptlen,
        byte* streamID, ulong cumulativePixelOffset, int finalFlag,
        byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_EncryptStreamAuthenticated3x512(
        nuint noiseHandle,
        nuint dataHandle1, nuint dataHandle2, nuint dataHandle3,
        nuint startHandle1, nuint startHandle2, nuint startHandle3,
        nuint macHandle,
        byte* plaintext, nuint ptlen,
        byte* streamID, ulong cumulativePixelOffset, int finalFlag,
        byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_DecryptStreamAuthenticated3x128(
        nuint noiseHandle,
        nuint dataHandle1, nuint dataHandle2, nuint dataHandle3,
        nuint startHandle1, nuint startHandle2, nuint startHandle3,
        nuint macHandle,
        byte* ciphertext, nuint ctlen,
        byte* streamID, ulong cumulativePixelOffset,
        byte* @out, nuint outCap, out nuint outLen,
        out int finalFlagOut);

    [LibraryImport("libitb")]
    internal static partial int ITB_DecryptStreamAuthenticated3x256(
        nuint noiseHandle,
        nuint dataHandle1, nuint dataHandle2, nuint dataHandle3,
        nuint startHandle1, nuint startHandle2, nuint startHandle3,
        nuint macHandle,
        byte* ciphertext, nuint ctlen,
        byte* streamID, ulong cumulativePixelOffset,
        byte* @out, nuint outCap, out nuint outLen,
        out int finalFlagOut);

    [LibraryImport("libitb")]
    internal static partial int ITB_DecryptStreamAuthenticated3x512(
        nuint noiseHandle,
        nuint dataHandle1, nuint dataHandle2, nuint dataHandle3,
        nuint startHandle1, nuint startHandle2, nuint startHandle3,
        nuint macHandle,
        byte* ciphertext, nuint ctlen,
        byte* streamID, ulong cumulativePixelOffset,
        byte* @out, nuint outCap, out nuint outLen,
        out int finalFlagOut);

    // Easy Mode Streaming AEAD per-chunk dispatch (driven by the
    // encryptor handle rather than separate seed + MAC handles).

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_EncryptStreamAuth(
        nuint handle,
        byte* plaintext, nuint ptlen,
        byte* streamID, ulong cumulativePixelOffset, int finalFlag,
        byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb")]
    internal static partial int ITB_Easy_DecryptStreamAuth(
        nuint handle,
        byte* ciphertext, nuint ctlen,
        byte* streamID, ulong cumulativePixelOffset,
        byte* @out, nuint outCap, out nuint outLen,
        out int finalFlagOut);

    // ----------------------------------------------------------------
    // Format-deniability wrapper — outer keystream cipher
    // (AES-128-CTR / ChaCha20 / SipHash-2-4 in CTR mode) over an ITB
    // ciphertext blob or bytestream. Mirrors the 12 ITB_Wrap* /
    // ITB_Unwrap* / ITB_WrapStream* / ITB_UnwrapStream* /
    // ITB_WrapperKeySize / ITB_WrapperNonceSize exports in
    // cmd/cshared/main.go. cipherName accepts "aes" / "chacha" /
    // "siphash"; every other entry follows the standard
    // probe-allocate-call idiom. The streaming Init / Update / Free
    // triple owns one wrap-stream handle (uintptr_t on the C side,
    // nuint here); pair every Init with exactly one Free.
    // ----------------------------------------------------------------

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_WrapperKeySize(string cipherName, out nuint outSize);

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_WrapperNonceSize(string cipherName, out nuint outSize);

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_Wrap(
        string cipherName,
        byte* key, nuint keyLen,
        byte* blob, nuint blobLen,
        byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_Unwrap(
        string cipherName,
        byte* key, nuint keyLen,
        byte* wire, nuint wireLen,
        byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_WrapInPlace(
        string cipherName,
        byte* key, nuint keyLen,
        byte* blob, nuint blobLen,
        byte* outNonce, nuint nonceCap);

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_UnwrapInPlace(
        string cipherName,
        byte* key, nuint keyLen,
        byte* wire, nuint wireLen);

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_WrapStreamWriter_Init(
        string cipherName,
        byte* key, nuint keyLen,
        byte* outNonce, nuint nonceCap,
        out nuint outHandle);

    [LibraryImport("libitb")]
    internal static partial int ITB_WrapStreamWriter_Update(
        nuint handle,
        byte* src, nuint srcLen,
        byte* dst, nuint dstCap);

    [LibraryImport("libitb")]
    internal static partial int ITB_WrapStreamWriter_Free(nuint handle);

    [LibraryImport("libitb", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_UnwrapStreamReader_Init(
        string cipherName,
        byte* key, nuint keyLen,
        byte* wireNonce, nuint nonceLen,
        out nuint outHandle);

    [LibraryImport("libitb")]
    internal static partial int ITB_UnwrapStreamReader_Update(
        nuint handle,
        byte* src, nuint srcLen,
        byte* dst, nuint dstCap);

    [LibraryImport("libitb")]
    internal static partial int ITB_UnwrapStreamReader_Free(nuint handle);
}
