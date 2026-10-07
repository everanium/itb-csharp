// Size and duration parsing and the human renderings of sizes, rates
// and durations. Every rendering here is part of the output contract
// shared with the Go harness and the other bindings' loop utilities,
// so the formats are fixed to the character, not to taste.
//
// .NET-specific. Every conversion and every format specifier names
// CultureInfo.InvariantCulture explicitly. The process also pins its
// default culture at startup, but a formatter that relies on that
// alone renders "1,5MB/s" the day someone runs it under a
// comma-decimal locale with a thread the pin did not reach, and the
// output contract is byte-for-byte.

using System.Globalization;

namespace Everanium.Itb3.Loop;

internal static class Size
{
    /// <summary>Suffix table for <see cref="ParseSize"/>, matched in
    /// order so the longer spellings win over their prefixes.</summary>
    private static readonly (string Suffix, long Mult)[] SizeSuffixes =
    [
        ("KIB", 1L << 10),
        ("KB", 1L << 10),
        ("K", 1L << 10),
        ("MIB", 1L << 20),
        ("MB", 1L << 20),
        ("M", 1L << 20),
        ("GIB", 1L << 30),
        ("GB", 1L << 30),
        ("G", 1L << 30),
        ("B", 1L),
    ];

    /// <summary>
    /// Parses a human byte-size string ("16MB", "1MiB", "512K",
    /// "1073741824") into a byte count. Every suffix is a binary
    /// multiple: K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB =
    /// 1024^3, B or none = bytes; matching is case-insensitive and
    /// surrounding whitespace is trimmed. Null on a malformed or
    /// negative value.
    /// </summary>
    internal static long? ParseSize(string s)
    {
        string upper = s.Trim().ToUpperInvariant();
        if (upper.Length == 0)
        {
            return null;
        }
        long mult = 1;
        string digits = upper;
        foreach (var (suffix, m) in SizeSuffixes)
        {
            if (upper.EndsWith(suffix, StringComparison.Ordinal))
            {
                mult = m;
                digits = upper[..^suffix.Length];
                break;
            }
        }
        digits = digits.TrimEnd();
        if (digits.Length == 0)
        {
            return null;
        }
        foreach (char c in digits)
        {
            if (c is < '0' or > '9')
            {
                return null;
            }
        }
        if (!long.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out long n))
        {
            return null;
        }
        try
        {
            return checked(n * mult);
        }
        catch (OverflowException)
        {
            return null;
        }
    }

    /// <summary>Unit table for <see cref="ParseDuration"/>, matched in
    /// order so "ms" wins over "m" followed by a stray "s".</summary>
    private static readonly (string Unit, double Nanos)[] DurationUnits =
    [
        ("ns", 1.0),
        ("us", 1e3),
        ("ms", 1e6),
        ("s", 1e9),
        ("m", 60e9),
        ("h", 3600e9),
    ];

    /// <summary>
    /// Parses the Go duration grammar — a sequence of decimal numbers
    /// each followed by a unit (h, m, s, ms, us, ns), such as "30s",
    /// "5m", "1h30m", "1.5s" — into nanoseconds. Null on a malformed
    /// string.
    /// </summary>
    internal static long? ParseDuration(string s)
    {
        if (s.Length == 0)
        {
            return null;
        }
        var rest = s.AsSpan();
        double total = 0;
        while (rest.Length > 0)
        {
            int numLen = 0;
            while (numLen < rest.Length && (char.IsAsciiDigit(rest[numLen]) || rest[numLen] == '.'))
            {
                numLen++;
            }
            if (numLen == 0)
            {
                return null;
            }
            if (!double.TryParse(
                    rest[..numLen], NumberStyles.Float, CultureInfo.InvariantCulture, out double v))
            {
                return null;
            }
            rest = rest[numLen..];
            double? nanos = null;
            foreach (var (unit, ns) in DurationUnits)
            {
                if (!rest.StartsWith(unit, StringComparison.Ordinal))
                {
                    continue;
                }
                var after = rest[unit.Length..];
                // A unit whose next character is a letter is the prefix
                // of a longer token that is not a unit at all.
                if (after.Length > 0 && char.IsAsciiLetter(after[0]))
                {
                    continue;
                }
                rest = after;
                nanos = ns;
                break;
            }
            if (nanos is null)
            {
                return null;
            }
            total += v * nanos.Value;
        }
        if (total > 9.2e18)
        {
            return null;
        }
        return (long)total;
    }

    /// <summary>Renders a byte count with a binary-unit suffix:
    /// "1.0GiB", "16.0MiB", "4.0KiB", "512B".</summary>
    internal static string HumanBytes(long n)
    {
        var inv = CultureInfo.InvariantCulture;
        if (n >= 1L << 30)
        {
            return (n / (double)(1L << 30)).ToString("F1", inv) + "GiB";
        }
        if (n >= 1L << 20)
        {
            return (n / (double)(1L << 20)).ToString("F1", inv) + "MiB";
        }
        if (n >= 1L << 10)
        {
            return (n / (double)(1L << 10)).ToString("F1", inv) + "KiB";
        }
        return n.ToString(inv) + "B";
    }

    /// <summary>Renders a possibly-negative byte delta with an explicit
    /// sign.</summary>
    internal static string HumanBytesSigned(long n) =>
        n < 0 ? "-" + HumanBytes(-n) : "+" + HumanBytes(n);

    /// <summary>Binary MiB per second over a nanosecond window; zero
    /// when the window is unmeasured.</summary>
    internal static double MbPerSec(long bytes, long ns) =>
        ns <= 0 ? 0.0 : bytes / (double)(1L << 20) / (ns / 1e9);

    /// <summary>Renders a throughput as "123.4MB/s" (binary MiB per
    /// second) or "n/a" for an unmeasured window.</summary>
    internal static string HumanRate(long bytes, long ns) =>
        ns <= 0
            ? "n/a"
            : MbPerSec(bytes, ns).ToString("F1", CultureInfo.InvariantCulture) + "MB/s";

    /// <summary>The fractional part of a nanosecond remainder
    /// (0 .. 1e9) as ".ddd" with trailing zeros removed; empty for
    /// zero.</summary>
    private static string Fraction(long fracNs)
    {
        if (fracNs == 0)
        {
            return string.Empty;
        }
        return "." + fracNs.ToString("D9", CultureInfo.InvariantCulture).TrimEnd('0');
    }

    /// <summary>
    /// Renders a duration the way Go's <c>time.Duration</c> prints:
    /// zero as "0s"; below one second as milliseconds ("900ms",
    /// "1.5ms"); otherwise "[Hh][Mm]Ss" where the hour part appears
    /// when non-zero, the minute part when the hour part appears or
    /// the minutes are non-zero, and the seconds carry their fraction
    /// with trailing zeros removed ("5s", "5.003s", "1m0s",
    /// "1m5.25s", "1h0m0s"). The caller rounds first.
    /// </summary>
    internal static string HumanDuration(long ns)
    {
        var inv = CultureInfo.InvariantCulture;
        ns = Math.Abs(ns);
        if (ns == 0)
        {
            return "0s";
        }
        if (ns < 1_000_000_000)
        {
            long ms = ns / 1_000_000;
            long msFrac = (ns % 1_000_000) * 1000; // scaled to 9 digits
            return ms.ToString(inv) + Fraction(msFrac) + "ms";
        }
        long hours = ns / 3_600_000_000_000;
        long rem = ns % 3_600_000_000_000;
        long minutes = rem / 60_000_000_000;
        rem %= 60_000_000_000;
        long seconds = rem / 1_000_000_000;
        long frac = rem % 1_000_000_000;
        var sb = new System.Text.StringBuilder();
        if (hours > 0)
        {
            sb.Append(hours.ToString(inv)).Append('h');
        }
        if (hours > 0 || minutes > 0)
        {
            sb.Append(minutes.ToString(inv)).Append('m');
        }
        sb.Append(seconds.ToString(inv)).Append(Fraction(frac)).Append('s');
        return sb.ToString();
    }

    /// <summary>Rounds a nanosecond count to the nearest multiple of
    /// <paramref name="unitNs"/>.</summary>
    internal static long RoundTo(long ns, long unitNs) => (ns + unitNs / 2) / unitNs * unitNs;
}
