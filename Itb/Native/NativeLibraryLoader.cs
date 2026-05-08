// Resolves the path to libitb.{so,dylib,dll} at runtime and registers a
// DllImportResolver against the assembly so every [LibraryImport]-
// generated P/Invoke stub routes through the resolved path.
//
// Lookup order mirrors bindings/python/itb/_ffi.py and
// bindings/rust/src/ffi.rs:
//
//   1. ITB_LIBRARY_PATH environment variable (absolute path).
//   2. <repo>/dist/<os>-<arch>/libitb.<ext> located by walking up from
//      the assembly directory until a matching dist/ folder is found.
//      The assembly directory is typically
//      bindings/csharp/Itb/bin/<config>/<tfm>/Itb.dll, so the walk
//      crosses the test / bench output paths transparently.
//   3. The system loader (ld.so.cache / DYLD_LIBRARY_PATH / PATH) via
//      NativeLibrary.Load(libraryName, assembly, searchPath).
//
// The resolver runs once per process at the first call to any of the
// extern P/Invoke methods; .NET caches the resulting handle internally.

using System.Reflection;
using System.Runtime.InteropServices;

namespace Itb.Native;

internal static class NativeLibraryLoader
{
    internal const string LibName = "libitb";

    private static int _registered;

    /// <summary>
    /// Idempotent registration of the DllImportResolver. Called from the
    /// static constructor of <see cref="ItbNative"/> so the first call
    /// into any P/Invoke method routes through the resolver.
    /// </summary>
    internal static void EnsureRegistered()
    {
        if (Interlocked.CompareExchange(ref _registered, 1, 0) != 0)
        {
            return;
        }
        NativeLibrary.SetDllImportResolver(typeof(NativeLibraryLoader).Assembly, Resolve);
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != LibName)
        {
            return IntPtr.Zero;
        }

        var env = Environment.GetEnvironmentVariable("ITB_LIBRARY_PATH");
        if (!string.IsNullOrEmpty(env) && File.Exists(env))
        {
            return NativeLibrary.Load(env);
        }

        var distFile = ResolveDistPath(assembly);
        if (distFile is not null && File.Exists(distFile))
        {
            return NativeLibrary.Load(distFile);
        }

        return NativeLibrary.Load(LibFilename, assembly, searchPath);
    }

    private static string? ResolveDistPath(Assembly assembly)
    {
        var asmPath = assembly.Location;
        if (string.IsNullOrEmpty(asmPath))
        {
            asmPath = AppContext.BaseDirectory;
        }
        var asmDir = Path.GetDirectoryName(asmPath);
        if (string.IsNullOrEmpty(asmDir))
        {
            return null;
        }

        var platformDir = PlatformLibDir;
        var libFile = LibFilename;

        var dir = new DirectoryInfo(asmDir);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "dist", platformDir, libFile);
            if (File.Exists(candidate))
            {
                return candidate;
            }
            dir = dir.Parent;
        }
        return null;
    }

    internal static string PlatformLibDir
    {
        get
        {
            string os;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                os = "linux";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                os = "darwin";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                os = "windows";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD))
            {
                os = "freebsd";
            }
            else
            {
                os = "linux";
            }

            var arch = RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => "amd64",
                Architecture.Arm64 => "arm64",
                _ => "amd64",
            };

            return $"{os}-{arch}";
        }
    }

    internal static string LibFilename
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
