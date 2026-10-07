// Plaintext content: the payload modes, the seeded per-worker
// generator, and the buffer fill from the operating-system CSPRNG.

using System.Runtime.InteropServices;

namespace Everanium.Itb3.Loop;

/// <summary>
/// Payload mode selector values for the --payload-mode flag.
///
///   - Fixed: one CSPRNG-generated buffer per worker, held unchanged
///     for the whole run (the default).
///   - Rotating: the buffer is regenerated before every iteration, so
///     no two encrypt calls see the same plaintext.
///   - PatternZero / PatternFf: degenerate constant fills (all 0x00 /
///     all 0xFF) probing minimum-entropy plaintext handling.
///   - PatternAscii: a repeating 'A'..'Z' ramp probing low-entropy
///     structured text.
/// </summary>
internal enum PayloadMode
{
    Fixed,
    Rotating,
    PatternZero,
    PatternFf,
    PatternAscii,
}

internal static class Payload
{
    private static readonly (string Name, PayloadMode Mode)[] Names =
    [
        ("fixed", PayloadMode.Fixed),
        ("rotating", PayloadMode.Rotating),
        ("pattern-zero", PayloadMode.PatternZero),
        ("pattern-ff", PayloadMode.PatternFf),
        ("pattern-ascii", PayloadMode.PatternAscii),
    ];

    internal static string Name(this PayloadMode mode)
    {
        foreach (var (name, m) in Names)
        {
            if (m == mode)
            {
                return name;
            }
        }
        return "fixed";
    }

    internal static PayloadMode? Parse(string s)
    {
        foreach (var (name, m) in Names)
        {
            if (name == s)
            {
                return m;
            }
        }
        return null;
    }

    /// <summary>
    /// Seeded plaintext. The seed makes plaintext content reproducible
    /// so a failing iteration can be replayed with the same bytes; it
    /// governs nothing else — pipeline keys, nonces and masters stay
    /// CSPRNG-drawn, so a seeded run is a reproduction aid and never a
    /// security test. Each worker's stream is domain-separated by its
    /// id so seeded workers still hold pairwise-distinct buffers under
    /// the fixed and rotating modes. The generator is splitmix64: a few
    /// lines in any language, which is why it is the one every binding
    /// uses.
    /// </summary>
    internal static ulong SeedWorker(ulong seed, int workerId) =>
        seed + (ulong)workerId + 1;

    private static ulong Splitmix64(ref ulong state)
    {
        unchecked
        {
            state += 0x9E3779B97F4A7C15UL;
            ulong z = state;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
            return z ^ (z >> 31);
        }
    }

    [DllImport("libc", EntryPoint = "getrandom", SetLastError = true)]
    private static extern nint GetRandom(IntPtr buf, nuint buflen, uint flags);

    /// <summary>
    /// Fills <paramref name="buf"/> from the operating-system CSPRNG.
    ///
    /// .NET-specific. The glibc entry is called directly rather than
    /// through <c>RandomNumberGenerator</c>: the .NET native layer
    /// reaches the kernel through <c>arc4random_buf</c>, a userspace
    /// generator that reseeds on its own schedule, so the number of
    /// kernel draws no longer tracks the number of fills and the
    /// plaintext-content flags become unobservable from outside the
    /// process. Going straight to the libc entry keeps one draw per
    /// fill, which is what makes --payload-mode and --seed checkable
    /// against a run that never touches them. The entry returns short
    /// on a signal and caps a single draw, so the fill loops until
    /// every byte is in place. False on failure.
    /// </summary>
    internal static unsafe bool FillRandom(Span<byte> buf)
    {
        fixed (byte* p = buf)
        {
            nuint off = 0;
            nuint len = (nuint)buf.Length;
            while (off < len)
            {
                nint r;
                try
                {
                    r = GetRandom((IntPtr)(p + off), len - off, 0);
                }
                catch (EntryPointNotFoundException)
                {
                    // .NET-specific fallback for a platform without the
                    // glibc entry; the managed generator is correct,
                    // only unobservable from a syscall trace.
                    System.Security.Cryptography.RandomNumberGenerator.Fill(buf[(int)off..]);
                    return true;
                }
                catch (DllNotFoundException)
                {
                    System.Security.Cryptography.RandomNumberGenerator.Fill(buf[(int)off..]);
                    return true;
                }
                if (r <= 0)
                {
                    return false;
                }
                off += (nuint)r;
            }
        }
        return true;
    }

    /// <summary>
    /// Writes one plaintext buffer according to the payload mode. The
    /// fixed and rotating modes draw from the seeded generator when the
    /// run is seeded and from the OS CSPRNG otherwise; the pattern
    /// modes are deterministic regardless of the seed. False when the
    /// CSPRNG fails.
    /// </summary>
    internal static bool Fill(PayloadMode mode, bool seeded, ref ulong rng, byte[] buf)
    {
        switch (mode)
        {
            case PayloadMode.Fixed:
            case PayloadMode.Rotating:
                if (!seeded)
                {
                    return FillRandom(buf);
                }
                for (int i = 0; i < buf.Length; i += 8)
                {
                    ulong v = Splitmix64(ref rng);
                    int n = Math.Min(8, buf.Length - i);
                    for (int k = 0; k < n; k++)
                    {
                        buf[i + k] = (byte)(v >> (8 * k));
                    }
                }
                return true;
            case PayloadMode.PatternZero:
                Array.Clear(buf);
                return true;
            case PayloadMode.PatternFf:
                Array.Fill(buf, (byte)0xFF);
                return true;
            default:
                for (int i = 0; i < buf.Length; i++)
                {
                    buf[i] = (byte)('A' + (i % 26));
                }
                return true;
        }
    }
}
