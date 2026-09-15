// SignalPolicy restores the host runtime's own disposition for the
// signal CoreCLR uses to suspend threads for a garbage collection.
//
// A Go runtime built as a c-shared library walks the whole signal table
// during its initialisation and adds SA_ONSTACK to handlers it does not
// otherwise claim. CoreCLR registers its thread-activation handler
// (SIGRTMIN) deliberately without SA_ONSTACK, because the deep path of
// that handler holds CONTEXT structures and needs roughly 10.5 KB — it
// is written for the thread's own multi-megabyte stack. Forced onto the
// alternate signal stack CoreCLR sized for SIGSEGV alone (16 KB, of
// which a guard page and the kernel's signal frame leave about 9 KB),
// the handler runs off the bottom into the guard page. The nested fault
// cannot be delivered, because the thread is already on the alternate
// stack, so the kernel raises SIGSEGV with si_code SI_KERNEL and the
// process dies with every test still passing.
//
// The disposition is sampled immediately before the shared library is
// loaded and again immediately after. The flag is cleared only when the
// load is what introduced it, so a host that sets SA_ONSTACK itself is
// left exactly as it configured itself. Signals the Go runtime claims
// for its own handlers are not touched at all.
//
// Scope and limits, stated plainly:
//   - Linux only. macOS suspends threads through Mach and has no
//     SIGRTMIN; Windows has no POSIX signals at all.
//   - sigaction is process-global. This is a deliberate, narrow
//     correction of one flag on one signal, not a private setting.
//   - A second Go c-shared library loaded later re-applies the flag.

using System;
using System.Runtime.InteropServices;

namespace Everanium.Itb3;

internal static class SignalPolicy
{
    private const int SA_ONSTACK = 0x08000000;

    // glibc x86-64 struct sigaction: handler at 0, sa_mask (128 bytes)
    // at 8, sa_flags (int) at 136, sa_restorer at 144 — 152 bytes.
    private const int StructSize = 152;
    private const int FlagsOffset = 136;

    [DllImport("libc", EntryPoint = "sigaction", SetLastError = true)]
    private static extern int SigAction(int signum, IntPtr act, IntPtr oldact);

    [DllImport("libc", EntryPoint = "__libc_current_sigrtmin")]
    private static extern int SigRtMin();

    /// <summary>Reads the current sa_flags of the host's thread-activation
    /// signal, or null when unavailable. Call immediately before loading
    /// the shared library.</summary>
    internal static int? SampleActivationFlags()
    {
        if (!OperatingSystem.IsLinux())
        {
            return null;
        }

        IntPtr buf = IntPtr.Zero;
        try
        {
            int signum = SigRtMin();
            if (signum <= 0)
            {
                return null;
            }

            buf = Marshal.AllocHGlobal(StructSize);
            for (int i = 0; i < StructSize; i++)
            {
                Marshal.WriteByte(buf, i, 0);
            }

            return SigAction(signum, IntPtr.Zero, buf) != 0
                ? null
                : Marshal.ReadInt32(buf, FlagsOffset);
        }
        catch
        {
            return null;
        }
        finally
        {
            if (buf != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buf);
            }
        }
    }

    /// <summary>Clears SA_ONSTACK from the host's thread-activation
    /// signal, but only when <paramref name="before"/> shows the flag was
    /// absent until the library loaded. Never throws.</summary>
    internal static void RestoreActivationFlags(int? before)
    {
        // Nothing sampled, or the host had already chosen SA_ONSTACK for
        // itself — in either case this is not ours to change.
        if (before is not int prior || (prior & SA_ONSTACK) != 0)
        {
            return;
        }

        IntPtr buf = IntPtr.Zero;
        try
        {
            int signum = SigRtMin();
            if (signum <= 0)
            {
                return;
            }

            buf = Marshal.AllocHGlobal(StructSize);
            for (int i = 0; i < StructSize; i++)
            {
                Marshal.WriteByte(buf, i, 0);
            }

            if (SigAction(signum, IntPtr.Zero, buf) != 0)
            {
                return;
            }

            int flags = Marshal.ReadInt32(buf, FlagsOffset);
            if ((flags & SA_ONSTACK) == 0)
            {
                // The load did not add it after all.
                return;
            }

            Marshal.WriteInt32(buf, FlagsOffset, flags & ~SA_ONSTACK);

            // Re-register the disposition exactly as read, one flag
            // lighter. A failure here is not worth surfacing: the caller
            // is mid-resolve and the library is otherwise fine.
            SigAction(signum, buf, IntPtr.Zero);
        }
        catch
        {
            // Diagnostic-only path. Never let it break a working load.
        }
        finally
        {
            if (buf != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buf);
            }
        }
    }
}
