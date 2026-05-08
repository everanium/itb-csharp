// Exception hierarchy for libitb FFI failures.
//
// Every fallible libitb call returns a non-zero status code on failure;
// higher-level wrappers translate the code into one of the typed
// exceptions below via <see cref="ItbException.Check(int)"/> or
// <see cref="ItbException.FromStatus(int)"/>.
//
// The hierarchy uses typed subclasses so selective catch blocks can
// distinguish the structurally-distinct failure modes (Easy Mode
// config mismatch, Blob mode mismatch, Blob malformation, Blob
// version-too-new) while still falling through to the base
// ItbException for generic handling. The numeric Status property on
// every exception preserves the "match by code" idiom alongside the
// type-based catch hierarchy.
//
// Threading caveat. The textual <see cref="Exception.Message"/> is read
// from a process-wide atomic inside libitb that follows the C `errno`
// discipline: the most recent non-OK Status across the whole process
// wins, and a sibling thread that calls into libitb between the failing
// call and the diagnostic read may overwrite the message. The
// structural <see cref="Status"/> code on the failing call is
// unaffected — only the textual message is racy.

using System.Text;

namespace Itb;

public class ItbException : Exception
{
    /// <summary>Numeric status code returned by libitb (one of the
    /// constants in <see cref="Native.Status"/>).</summary>
    public int Status { get; }

    public ItbException(int status, string? message = null)
        : base(FormatMessage(status, message))
    {
        Status = status;
    }

    private static string FormatMessage(int status, string? message)
    {
        return string.IsNullOrEmpty(message)
            ? $"itb: status={status}"
            : $"itb: status={status} ({message})";
    }

    /// <summary>
    /// Constructs a typed <see cref="ItbException"/> subclass for the
    /// given status code, reading the textual diagnostic from
    /// <c>ITB_LastError</c>.
    /// </summary>
    internal static ItbException FromStatus(int status)
    {
        var msg = ReadLastError();
        return CreateForStatus(status, msg);
    }

    internal static ItbException CreateForStatus(int status, string message)
    {
        return status switch
        {
            Native.Status.EasyMismatch =>
                new ItbEasyMismatchException(status, message, ReadEasyMismatchField()),
            Native.Status.BlobModeMismatch =>
                new ItbBlobModeMismatchException(status, message),
            Native.Status.BlobMalformed =>
                new ItbBlobMalformedException(status, message),
            Native.Status.BlobVersionTooNew =>
                new ItbBlobVersionTooNewException(status, message),
            Native.Status.StreamTruncated =>
                new ItbStreamTruncatedException(status, message),
            Native.Status.StreamAfterFinal =>
                new ItbStreamAfterFinalException(status, message),
            _ => new ItbException(status, message),
        };
    }

    /// <summary>Throws the appropriate typed exception when
    /// <paramref name="status"/> is non-OK; otherwise returns.</summary>
    internal static void Check(int status)
    {
        if (status == Native.Status.Ok)
        {
            return;
        }
        throw FromStatus(status);
    }

    private static unsafe string ReadLastError()
    {
        // Inlined ReadString-equivalent that returns "" on any failure
        // instead of throwing — avoids recursion when constructing a
        // diagnostic for the original failure.
        try
        {
            int rc = Native.ItbNative.ITB_LastError(null, 0, out var requiredSize);
            if ((rc != Native.Status.Ok && rc != Native.Status.BufferTooSmall) || requiredSize <= 1)
            {
                return string.Empty;
            }
            var buf = new byte[(int)requiredSize];
            int rc2;
            nuint outLen;
            fixed (byte* p = buf)
            {
                rc2 = Native.ItbNative.ITB_LastError(p, requiredSize, out outLen);
            }
            if (rc2 != Native.Status.Ok)
            {
                return string.Empty;
            }
            var actualLen = outLen > 0 ? (int)outLen - 1 : 0;
            return Encoding.UTF8.GetString(buf, 0, actualLen);
        }
        catch
        {
            return string.Empty;
        }
    }

    private static unsafe string ReadEasyMismatchField()
    {
        try
        {
            int rc = Native.ItbNative.ITB_Easy_LastMismatchField(null, 0, out var requiredSize);
            if ((rc != Native.Status.Ok && rc != Native.Status.BufferTooSmall) || requiredSize <= 1)
            {
                return string.Empty;
            }
            var buf = new byte[(int)requiredSize];
            int rc2;
            nuint outLen;
            fixed (byte* p = buf)
            {
                rc2 = Native.ItbNative.ITB_Easy_LastMismatchField(p, requiredSize, out outLen);
            }
            if (rc2 != Native.Status.Ok)
            {
                return string.Empty;
            }
            var actualLen = outLen > 0 ? (int)outLen - 1 : 0;
            return Encoding.UTF8.GetString(buf, 0, actualLen);
        }
        catch
        {
            return string.Empty;
        }
    }
}

/// <summary>
/// Raised by <c>Encryptor.Import</c> or <c>Encryptor.PeekConfig</c> when
/// the supplied state blob disagrees with the live encryptor's
/// configuration on at least one field. <see cref="Field"/> carries the
/// offending JSON field name (e.g. <c>"primitive"</c>, <c>"key_bits"</c>,
/// <c>"mode"</c>, <c>"mac"</c>).
/// </summary>
/// <remarks>
/// <para><b>Field-attribution race.</b> The <see cref="Field"/> value is
/// read from <c>ITB_Easy_LastMismatchField</c> at exception construction
/// time — a process-wide atomic that follows the same C <c>errno</c>
/// discipline as <c>ITB_LastError</c> documented at the file header.
/// Two concurrent failing imports across separate threads can cross the
/// field-name strings between the two exceptions; the caller observes
/// whichever value libitb most recently published when the exception
/// was constructed. Callers that need reliable field attribution under
/// concurrent imports must serialise the import calls behind a
/// <c>lock</c>. The exception's <see cref="ItbException.Status"/> code
/// on the failing call's return value is unaffected — only the textual
/// field name is racy.</para>
/// </remarks>
public sealed class ItbEasyMismatchException : ItbException
{
    /// <summary>Name of the mismatched configuration field, or the
    /// empty string if libitb did not record one.</summary>
    public string Field { get; }

    internal ItbEasyMismatchException(int status, string? message, string? field)
        : base(status, FormatWithField(message, field ?? string.Empty))
    {
        Field = field ?? string.Empty;
    }

    private static string? FormatWithField(string? message, string field)
    {
        if (field.Length == 0)
        {
            return message;
        }
        return string.IsNullOrEmpty(message)
            ? $"mismatch on field '{field}'"
            : $"{message} (field '{field}')";
    }
}

/// <summary>
/// Raised by <c>Blob.Import</c> when a Single-mode blob is fed into a
/// Triple-mode handle (or vice-versa).
/// </summary>
public sealed class ItbBlobModeMismatchException : ItbException
{
    internal ItbBlobModeMismatchException(int status, string? message)
        : base(status, message)
    {
    }
}

/// <summary>
/// Raised by <c>Blob.Import</c> when the blob's framing / length /
/// magic-byte shape fails validation.
/// </summary>
public sealed class ItbBlobMalformedException : ItbException
{
    internal ItbBlobMalformedException(int status, string? message)
        : base(status, message)
    {
    }
}

/// <summary>
/// Raised by <c>Blob.Import</c> when the blob's version field is newer
/// than the running binding can decode.
/// </summary>
public sealed class ItbBlobVersionTooNewException : ItbException
{
    internal ItbBlobVersionTooNewException(int status, string? message)
        : base(status, message)
    {
    }
}

/// <summary>
/// Raised by the authenticated streaming decrypt path when the input
/// transcript exhausts without a chunk whose recovered
/// <c>final_flag</c> is <c>1</c>. Carries
/// <see cref="StatusCode.StreamTruncated"/> (numeric value <c>23</c>).
/// </summary>
public sealed class ItbStreamTruncatedException : ItbException
{
    internal ItbStreamTruncatedException(int status, string? message)
        : base(status, message)
    {
    }
}

/// <summary>
/// Raised by the authenticated streaming decrypt path when extra
/// chunk bytes follow the terminating chunk on the wire transcript.
/// Carries <see cref="StatusCode.StreamAfterFinal"/> (numeric value
/// <c>24</c>).
/// </summary>
public sealed class ItbStreamAfterFinalException : ItbException
{
    internal ItbStreamAfterFinalException(int status, string? message)
        : base(status, message)
    {
    }
}
