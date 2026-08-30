// URL-query builder for the opts pass-through string.
//
// The builder performs no validation — every key and value is
// rendered into a percent-encoded query string and passed through to
// Go verbatim; libitb rejects unknown keys or bad values with a
// diagnostic surfaced via ItbException. Primitive / MAC / cipher /
// palette names are opaque strings.

using System.Text;

namespace Itb;

/// <summary>
/// Builder producing the URL-query-encoded opts string consumed by
/// <see cref="Pipeline.Init"/>, <see cref="Pipeline.Open"/>, and
/// <see cref="Pipeline.RegisterProfile"/>. Setters chain; an empty
/// builder renders the empty query (pure profile defaults).
/// </summary>
public sealed class Opts
{
    private readonly List<KeyValuePair<string, string>> _pairs = new();

    /// <summary>Hex-encodes the parallax master override
    /// (<c>pm</c>).</summary>
    public Opts WithPermMaster(ReadOnlySpan<byte> master) => WithRaw("pm", Hex(master));

    /// <summary>Hex-encodes the wrapper master override
    /// (<c>wm</c>).</summary>
    public Opts WithWrapMaster(ReadOnlySpan<byte> master) => WithRaw("wm", Hex(master));

    public Opts WithParallax(bool on) => WithRaw("withParallax", Bool(on));

    public Opts WithWrapper(bool on) => WithRaw("withWrapper", Bool(on));

    public Opts WithMaxWorkers(long n) => WithRaw("maxWorkers", n.ToString());

    public Opts WithNonceBits(long n) => WithRaw("nonceBits", n.ToString());

    public Opts WithBarrierFill(long n) => WithRaw("barrierFill", n.ToString());

    public Opts WithChunkSize(long n) => WithRaw("chunkSize", n.ToString());

    public Opts WithKeyBits(long n) => WithRaw("keyBits", n.ToString());

    public Opts WithParallaxSegmentSize(long n) => WithRaw("parallaxSegmentSize", n.ToString());

    public Opts WithMacName(string name) => WithRaw("macName", name);

    public Opts WithInnerHash(string name) => WithRaw("innerHash", name);

    public Opts WithOuterCipher(string name) => WithRaw("outerCipher", name);

    /// <summary>Comma-joins the palette names
    /// (<c>parallaxPalette</c>).</summary>
    public Opts WithParallaxPalette(params string[] names) =>
        WithRaw("parallaxPalette", string.Join(',', names));

    /// <summary>Escape hatch appending a raw <c>key=value</c> pair.
    /// Covers every key the Go side accepts, including the
    /// register-profile grammar (<c>mode</c>, <c>width</c>,
    /// <c>innerHashes</c>, <c>parallaxOn</c>, <c>wrapperOn</c>, …).
    /// </summary>
    public Opts WithRaw(string key, string value)
    {
        _pairs.Add(new KeyValuePair<string, string>(key, value));
        return this;
    }

    /// <summary>Renders the accumulated pairs as a query
    /// string.</summary>
    internal string Build()
    {
        var sb = new StringBuilder();
        foreach (var (key, value) in _pairs)
        {
            if (sb.Length > 0)
            {
                sb.Append('&');
            }
            Encode(sb, key);
            sb.Append('=');
            Encode(sb, value);
        }
        return sb.ToString();
    }

    private static string Bool(bool on) => on ? "true" : "false";

    // Minimal percent-encoding: the accepted values are ASCII names,
    // decimal integers, true / false, hex, and comma-separated lists,
    // so everything outside the URL-safe subset (plus ',') is escaped
    // byte-wise over the UTF-8 encoding.
    private static void Encode(StringBuilder sb, string s)
    {
        foreach (byte b in Encoding.UTF8.GetBytes(s))
        {
            bool safe = b is (>= (byte)'A' and <= (byte)'Z')
                or (>= (byte)'a' and <= (byte)'z')
                or (>= (byte)'0' and <= (byte)'9')
                or (byte)'-' or (byte)'.' or (byte)'_' or (byte)'~' or (byte)',';
            if (safe)
            {
                sb.Append((char)b);
            }
            else
            {
                sb.Append('%').Append(b.ToString("X2"));
            }
        }
    }

    private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);
}
