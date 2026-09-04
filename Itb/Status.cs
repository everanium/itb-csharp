// Status codes mirrored from the libitb C ABI
// (cmd/cshared/internal/capi/errors.go). Numeric values are stable
// across releases.

namespace Itb;

/// <summary>Integer status code returned by every libitb entry
/// point.</summary>
public enum Status
{
    Ok = 0,
    BadHash = 1,
    BadKeyBits = 2,
    BadHandle = 3,
    BadInput = 4,
    BufferTooSmall = 5,
    EncryptFailed = 6,
    DecryptFailed = 7,
    SeedWidthMix = 8,
    BadMac = 9,
    MacFailure = 10,
    BlobMalformedRecipe = 11,
    RecipePrimitiveUnknown = 12,
    UnknownProfile = 13,
    Reserved14 = 14,
    Reserved15 = 15,
    Reserved16 = 16,
    Reserved17 = 17,
    BlobModeMismatch = 19,
    BlobMalformed = 20,
    BlobVersionTooNew = 21,
    BlobTooManyOpts = 22,
    StreamTruncated = 23,
    StreamAfterFinal = 24,
    TripleClosed = 25,
    ProfileExists = 26,
    Internal = 99,
}
