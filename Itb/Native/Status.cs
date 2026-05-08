// Status codes returned by every libitb FFI entry point. Mirrors
// cmd/cshared/internal/capi/errors.go in the libitb source tree.
//
// Higher-level wrappers in Itb.* translate these into typed exceptions
// (see ItbException + subclasses); test code may import these constants
// via [InternalsVisibleTo("Itb.Tests")] to assert exact-status behaviour.

namespace Itb.Native;

internal static class Status
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

    // Easy encryptor (itb/easy sub-package) sentinel codes — block 11..18
    // is dedicated to the Encryptor surface so the lower codes 0..10 remain
    // reserved for the low-level Encrypt / Decrypt path.
    public const int EasyClosed = 11;
    public const int EasyMalformed = 12;
    public const int EasyVersionTooNew = 13;
    public const int EasyUnknownPrimitive = 14;
    public const int EasyUnknownMac = 15;
    public const int EasyBadKeyBits = 16;
    public const int EasyMismatch = 17;
    public const int EasyLockSeedAfterEncrypt = 18;

    // Native Blob (itb.Blob128 / 256 / 512) sentinel codes — block 19..22
    // is dedicated to the low-level state-blob surface so the lower codes
    // 0..18 remain reserved for the seed-handle / Encrypt / Decrypt /
    // Encryptor paths.
    public const int BlobModeMismatch = 19;
    public const int BlobMalformed = 20;
    public const int BlobVersionTooNew = 21;
    public const int BlobTooManyOpts = 22;

    // Streaming AEAD sentinel codes — block 23..24 covers the two
    // end-of-stream failure modes the binding-side stream-loop helper
    // detects after the per-chunk MAC verification path.
    public const int StreamTruncated = 23;
    public const int StreamAfterFinal = 24;

    public const int Internal = 99;
}
