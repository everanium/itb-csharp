// Public mirror of the internal Itb.Native.Status constants. Exposes
// every libitb status code as a named integer so callers outside this
// assembly can compare against ItbException.Status without resorting to
// magic numbers.
//
// Most failure codes are surfaced through typed exception subclasses
// (ItbEasyMismatchException, ItbBlobModeMismatchException,
// ItbBlobMalformedException, ItbBlobVersionTooNewException). The
// remaining codes — MacFailure, SeedWidthMix, BadHash, BadKeyBits, etc.
// — fall through to the base ItbException and are compared numerically:
//
//     try { ... }
//     catch (ItbException ex) when (ex.Status == StatusCode.MacFailure)
//     {
//         // tampered ciphertext or wrong MAC key
//     }

namespace Itb;

/// <summary>
/// Numeric status codes returned by libitb FFI calls. Mirrors the
/// internal <c>Itb.Native.Status</c> constants.
/// </summary>
public static class StatusCode
{
    public const int Ok = 0;
    public const int BadHash = 1;
    public const int BadKeyBits = 2;
    public const int BadHandle = 3;
    public const int BadInput = 4;
    public const int BufferTooSmall = 5;
    public const int EncryptFailed = 6;
    public const int DecryptFailed = 7;
    public const int SeedWidthMix = 8;
    public const int BadMac = 9;
    public const int MacFailure = 10;

    public const int EasyClosed = 11;
    public const int EasyMalformed = 12;
    public const int EasyVersionTooNew = 13;
    public const int EasyUnknownPrimitive = 14;
    public const int EasyUnknownMac = 15;
    public const int EasyBadKeyBits = 16;
    public const int EasyMismatch = 17;
    public const int EasyLockSeedAfterEncrypt = 18;

    public const int BlobModeMismatch = 19;
    public const int BlobMalformed = 20;
    public const int BlobVersionTooNew = 21;
    public const int BlobTooManyOpts = 22;

    public const int StreamTruncated = 23;
    public const int StreamAfterFinal = 24;

    public const int Internal = 99;
}
