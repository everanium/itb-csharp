// MAC handle for ITB authenticated modes (HMAC-BLAKE3 / HMAC-SHA256 /
// KMAC-256). Provides a thin RAII wrapper over ITB_NewMAC /
// ITB_FreeMAC for use with the authenticated encrypt / decrypt entry
// points.

using Itb.Native;

namespace Itb;

/// <summary>
/// A handle to one MAC primitive instance, keyed at construction time.
/// Pass instances of this class to <see cref="Cipher.EncryptAuth"/> /
/// <see cref="Cipher.DecryptAuth"/> and the Triple variants for
/// authenticated encryption.
/// </summary>
public sealed class Mac : IDisposable
{
    private nuint _handle;
    private readonly string _macName;

    /// <summary>
    /// Constructs a new MAC instance bound to a caller-supplied key.
    /// </summary>
    /// <param name="macName">A canonical MAC name from
    /// <see cref="Library.ListMacs"/> (<c>"hmac-blake3"</c> recommended;
    /// <c>"hmac-sha256"</c> and <c>"kmac256"</c> also available).</param>
    /// <param name="key">The MAC key (32 bytes for HMAC-BLAKE3, 16-32
    /// bytes for HMAC-SHA256 / KMAC-256 depending on the
    /// <see cref="MacInfo.MinKeyBytes"/> / <see cref="MacInfo.KeySize"/>
    /// reported by <see cref="Library.ListMacs"/>).</param>
    public unsafe Mac(string macName, ReadOnlySpan<byte> key)
    {
        ArgumentNullException.ThrowIfNull(macName);
        nuint handle;
        int rc;
        fixed (byte* keyPtr = key)
        {
            rc = ItbNative.ITB_NewMAC(macName, keyPtr, (nuint)key.Length, out handle);
        }
        ItbException.Check(rc);
        _handle = handle;
        _macName = macName;
    }

    /// <summary>The raw libitb handle. Used internally by the
    /// authenticated entry points in <see cref="Cipher"/>.</summary>
    internal nuint Handle => _handle;

    /// <summary>The canonical MAC name this instance was constructed
    /// with.</summary>
    public string MacName => _macName;

    /// <summary>Releases the underlying libitb handle. Idempotent.</summary>
    public void Dispose()
    {
        if (_handle != 0)
        {
            ItbNative.ITB_FreeMAC(_handle);
            _handle = 0;
        }
        GC.SuppressFinalize(this);
    }

    ~Mac()
    {
        if (_handle != 0)
        {
            ItbNative.ITB_FreeMAC(_handle);
            _handle = 0;
        }
    }
}
