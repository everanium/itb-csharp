// Source-generated P/Invoke surface over the libitb C ABI, restricted
// to the ITB_Triple_* Pipeline entries plus the version / last-error /
// Go-runtime-knob accessors (and the hash-registry iteration triple
// consumed internally by the eitb diagnostic CLI).
//
// Every signature mirrors a prototype in cmd/cshared/libitb.h. Type
// mapping:
//
//   C `int`        -> `int`     (32-bit on every platform under .NET)
//   C `size_t`     -> `nuint`   (host word size)
//   C `uintptr_t`  -> SafeHandle subclass (PipelineHandle / StreamHandle)
//   C `void*`      -> `byte*`   (libitb buffer; always treated as bytes)
//   C `char*` (in) -> `string`  (UTF-8 marshalled by the source generator)
//   C `char*` (out)-> `byte*`   (raw byte buffer; UTF-8 decoded by caller)
//
// Threading note. `ITB_LastError` reads process-global state that
// follows the C `errno` discipline: the most recent non-OK status
// across the whole process wins, and a sibling thread that calls into
// libitb between the failing call and the diagnostic read may
// overwrite the message. The structural status code on the failing
// call's return value is unaffected — only the textual diagnostic is
// racy.

using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace Itb;

/// <summary>Owned Triple Pipeline handle; released via
/// <c>ITB_Triple_Free</c> (which zeroes key material Go-side).</summary>
internal sealed class PipelineHandle : SafeHandle
{
    public PipelineHandle() : base(IntPtr.Zero, ownsHandle: true) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        return NativeMethods.ITB_Triple_Free((nuint)handle) == (int)Status.Ok;
    }
}

/// <summary>Owned incremental stream-session handle; released via
/// <c>ITB_Triple_StreamFree</c> (cancels the session from any
/// state).</summary>
internal sealed class StreamHandle : SafeHandle
{
    public StreamHandle() : base(IntPtr.Zero, ownsHandle: true) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        return NativeMethods.ITB_Triple_StreamFree((nuint)handle) == (int)Status.Ok;
    }
}

internal static unsafe partial class NativeMethods
{
    internal const string LibName = "libitb";

    // Registers the DllImportResolver before the first P/Invoke stub
    // in this class runs.
    static NativeMethods() => NativeLoader.Register();

    /// <summary>Shape shared by the four buffer-in / buffer-out cipher
    /// entries (Message / one-shot stream, encrypt / decrypt).</summary>
    internal delegate int CipherFn(
        PipelineHandle handle, byte* src, nuint srcLen,
        byte* dst, nuint dstCap, out nuint outLen);

    /// <summary>Shape shared by the size-out-param C-string accessors
    /// (<c>ITB_Version</c>, <c>ITB_LastError</c>, <c>ITB_HashName</c>
    /// via closure).</summary>
    internal delegate int CStrFn(byte* buf, nuint capBytes, out nuint outLen);

    // ----------------------------------------------------------------
    // Version + last-error + Go runtime knobs
    // ----------------------------------------------------------------

    [LibraryImport(LibName)]
    internal static partial int ITB_Version(byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport(LibName)]
    internal static partial int ITB_LastError(byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport(LibName)]
    internal static partial long ITB_SetMemoryLimit(long limit);

    [LibraryImport(LibName)]
    internal static partial int ITB_SetGCPercent(int pct);

    // ----------------------------------------------------------------
    // Hash-registry iteration — internal diagnostic surface consumed
    // by the eitb CLI (InternalsVisibleTo); deliberately not exposed
    // through the public binding API.
    // ----------------------------------------------------------------

    [LibraryImport(LibName)]
    internal static partial int ITB_HashCount();

    [LibraryImport(LibName)]
    internal static partial int ITB_HashName(int i, byte* @out, nuint capBytes, out nuint outLen);

    [LibraryImport(LibName)]
    internal static partial int ITB_HashWidth(int i);

    // ----------------------------------------------------------------
    // Triple Pipeline lifecycle
    // ----------------------------------------------------------------

    [LibraryImport(LibName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_Triple_Init(
        string profile, string opts,
        byte* blobOut, nuint blobCap, out nuint blobLen,
        out PipelineHandle outHandle);

    [LibraryImport(LibName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_Triple_Open(
        string profile,
        byte* blob, nuint blobLen,
        string opts,
        byte* permMaster, nuint permMasterLen,
        byte* wrapMaster, nuint wrapMasterLen,
        nuint mastersCount,
        out PipelineHandle outHandle);

    [LibraryImport(LibName)]
    internal static partial int ITB_Triple_Rekey(
        PipelineHandle handle,
        byte* permMaster, nuint permMasterLen,
        byte* wrapMaster, nuint wrapMasterLen,
        byte* blobOut, nuint blobCap, out nuint blobLen);

    [LibraryImport(LibName)]
    internal static partial int ITB_Triple_Close(PipelineHandle handle);

    [LibraryImport(LibName)]
    internal static partial int ITB_Triple_Free(nuint handle);

    [LibraryImport(LibName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ITB_Triple_RegisterProfile(string name, string opts);

    // ----------------------------------------------------------------
    // Buffer-in / buffer-out cipher entries
    // ----------------------------------------------------------------

    [LibraryImport(LibName)]
    internal static partial int ITB_Triple_EncryptMessage(
        PipelineHandle handle, byte* plaintext, nuint ptlen,
        byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport(LibName)]
    internal static partial int ITB_Triple_DecryptMessage(
        PipelineHandle handle, byte* wire, nuint wireLen,
        byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport(LibName)]
    internal static partial int ITB_Triple_EncryptStream(
        PipelineHandle handle, byte* plaintext, nuint ptlen,
        byte* @out, nuint outCap, out nuint outLen);

    [LibraryImport(LibName)]
    internal static partial int ITB_Triple_DecryptStream(
        PipelineHandle handle, byte* wire, nuint wireLen,
        byte* @out, nuint outCap, out nuint outLen);

    // ----------------------------------------------------------------
    // Incremental stream sessions
    // ----------------------------------------------------------------

    [LibraryImport(LibName)]
    internal static partial int ITB_Triple_EncryptStreamBegin(
        PipelineHandle pipe, out StreamHandle outStream);

    [LibraryImport(LibName)]
    internal static partial int ITB_Triple_DecryptStreamBegin(
        PipelineHandle pipe, out StreamHandle outStream);

    [LibraryImport(LibName)]
    internal static partial int ITB_Triple_StreamWrite(
        StreamHandle stream, byte* src, nuint srcLen);

    [LibraryImport(LibName)]
    internal static partial int ITB_Triple_StreamEnd(StreamHandle stream);

    [LibraryImport(LibName)]
    internal static partial int ITB_Triple_StreamRead(
        StreamHandle stream, byte* @out, nuint outCap,
        out nuint outLen, out int finished);

    [LibraryImport(LibName)]
    internal static partial int ITB_Triple_StreamFree(nuint stream);

    // ----------------------------------------------------------------
    // Shared string helpers
    // ----------------------------------------------------------------

    /// <summary>
    /// Two-phase read over the <c>(out, cap, *outLen)</c> C-string
    /// contract: probe with NULL / 0 for the required capacity, then
    /// read and NUL-strip. Throws <see cref="ItbException"/> on any
    /// non-OK status.
    /// </summary>
    internal static string ReadCString(CStrFn fn)
    {
        int rc = fn(null, 0, out nuint need);
        if (rc != (int)Status.Ok && rc != (int)Status.BufferTooSmall)
        {
            throw ItbException.FromRc(rc);
        }
        if (need <= 1)
        {
            return string.Empty;
        }
        var buf = new byte[checked((int)need)];
        fixed (byte* p = buf)
        {
            rc = fn(p, (nuint)buf.Length, out need);
        }
        ItbException.Check(rc);
        int len = need > 0 ? checked((int)need) - 1 : 0;
        return Encoding.UTF8.GetString(buf, 0, len);
    }

    /// <summary>Reads the libitb library version string.</summary>
    internal static string VersionString() => ReadCString(ITB_Version);

    /// <summary>
    /// Reads the <c>ITB_LastError</c> diagnostic. Returns the empty
    /// string instead of throwing so the helper is safe to call while
    /// constructing an exception for the original failure.
    /// </summary>
    internal static string ReadLastError()
    {
        try
        {
            int rc = ITB_LastError(null, 0, out nuint need);
            if ((rc != (int)Status.Ok && rc != (int)Status.BufferTooSmall) || need <= 1)
            {
                return string.Empty;
            }
            var buf = new byte[checked((int)need)];
            fixed (byte* p = buf)
            {
                rc = ITB_LastError(p, (nuint)buf.Length, out need);
            }
            if (rc != (int)Status.Ok)
            {
                return string.Empty;
            }
            int len = need > 0 ? checked((int)need) - 1 : 0;
            return Encoding.UTF8.GetString(buf, 0, len);
        }
        catch
        {
            return string.Empty;
        }
    }
}

/// <summary>
/// Resolves libitb.{so,dylib,dll} at runtime and registers a
/// DllImportResolver against this assembly so every P/Invoke stub
/// routes through the resolved path. Lookup order mirrors the sibling
/// bindings:
///
///   1. `ITB_LIBITB_PATH` environment variable (path to the shared
///      library file).
///   2. `&lt;repo&gt;/dist/&lt;os&gt;-&lt;arch&gt;/libitb.&lt;ext&gt;` located by walking up
///      from the assembly directory until a matching dist/ folder is
///      found (in-repo builds; the assembly directory is typically
///      bindings/csharp/&lt;proj&gt;/bin/&lt;config&gt;/&lt;tfm&gt;/).
///   3. The OS default loader path (`LD_LIBRARY_PATH`, ld.so.cache,
///      `DYLD_LIBRARY_PATH`, `PATH`).
/// </summary>
internal static class NativeLoader
{
    private static int _registered;

    /// <summary>Idempotent resolver registration; invoked from the
    /// static constructor of <see cref="NativeMethods"/> so the first
    /// call into any P/Invoke stub routes through the
    /// resolver.</summary>
    internal static void Register()
    {
        if (Interlocked.CompareExchange(ref _registered, 1, 0) != 0)
        {
            return;
        }
        NativeLibrary.SetDllImportResolver(typeof(NativeLoader).Assembly, Resolve);
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != NativeMethods.LibName)
        {
            return IntPtr.Zero;
        }

        var env = Environment.GetEnvironmentVariable("ITB_LIBITB_PATH");
        if (!string.IsNullOrEmpty(env) && File.Exists(env))
        {
            return NativeLibrary.Load(env);
        }

        var dist = ResolveDistPath();
        if (dist is not null)
        {
            return NativeLibrary.Load(dist);
        }

        return NativeLibrary.Load(LibFilename, assembly, searchPath);
    }

    private static string? ResolveDistPath()
    {
        var asmPath = typeof(NativeLoader).Assembly.Location;
        if (string.IsNullOrEmpty(asmPath))
        {
            asmPath = AppContext.BaseDirectory;
        }
        var dir = new DirectoryInfo(Path.GetDirectoryName(asmPath) ?? ".");
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "dist", PlatformLibDir, LibFilename);
            if (File.Exists(candidate))
            {
                return candidate;
            }
            dir = dir.Parent;
        }
        return null;
    }

    private static string PlatformLibDir
    {
        get
        {
            string os =
                RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "darwin" :
                RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "windows" :
                "linux";
            string arch = RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.Arm64 => "arm64",
                _ => "amd64",
            };
            return $"{os}-{arch}";
        }
    }

    private static string LibFilename
    {
        get
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return "libitb.dll";
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return "libitb.dylib";
            }
            return "libitb.so";
        }
    }
}
