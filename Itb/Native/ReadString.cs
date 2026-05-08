// Internal helper for libitb's size-out-param string accessors. Probes
// with cap=0 to discover the required buffer size, then allocates and
// reads. Used by Library.Version, Library.ListHashes / ListMacs,
// Seed.HashName, Mac.Name, Encryptor.Primitive / MacName etc.
//
// libitb's char* output buffers are NUL-terminated; outLen returns the
// total written byte count INCLUDING the trailing NUL. The actual
// string length is therefore outLen - 1; the helper strips the NUL
// before UTF-8 decoding.

using System.Text;

namespace Itb.Native;

internal static class ReadString
{
    internal unsafe delegate int Func(byte* buf, nuint cap, out nuint outLen);

    /// <summary>
    /// Probes the size, allocates a buffer, and returns the UTF-8
    /// decoded string. Throws <see cref="ItbException"/> on any
    /// non-OK status.
    /// </summary>
    internal static unsafe string Read(Func fn)
    {
        int rc = fn(null, 0, out var requiredSize);
        if (rc != Status.Ok && rc != Status.BufferTooSmall)
        {
            throw ItbException.FromStatus(rc);
        }
        if (requiredSize <= 1)
        {
            return string.Empty;
        }

        var buf = new byte[(int)requiredSize];
        int rc2;
        nuint outLen;
        fixed (byte* p = buf)
        {
            rc2 = fn(p, requiredSize, out outLen);
        }
        if (rc2 != Status.Ok)
        {
            throw ItbException.FromStatus(rc2);
        }
        var actualLen = outLen > 0 ? (int)outLen - 1 : 0;
        return Encoding.UTF8.GetString(buf, 0, actualLen);
    }
}
