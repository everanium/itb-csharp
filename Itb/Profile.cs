// Typed view of the Triple profile record — the JSON object that
// ITB_Triple_Inspect / ITB_Triple_Lookup emit, ITB_Triple_Register
// accepts, and the session blob carries in its wrap-layer.

using System.Text;
using System.Text.Json;

namespace Itb;

/// <summary>
/// A Triple Pipeline profile record.
///
/// The record is a plain data holder plus a JSON codec over the
/// fourteen keys of the wire object (<c>name</c>, <c>mode</c>,
/// <c>width</c>, <c>hash</c>, <c>hashes</c>, <c>keybits</c>,
/// <c>mac</c>, <c>tagstub</c>, <c>chunk</c>, <c>wrapper</c>,
/// <c>outer</c>, <c>parallax</c>, <c>palette</c>, <c>segment</c>). No
/// semantic validation happens on the .NET side — every field rule
/// (mode names, width / hash agreement, key sizes, palette shape,
/// reserved name prefixes) is enforced by Go at
/// <see cref="Pipeline.Register"/> / <see cref="Pipeline.Load"/> time
/// and surfaces as an <see cref="ItbException"/>. Primitive / MAC /
/// cipher names are opaque strings.
///
/// Encoding mirrors the Go codec: <c>mode</c>, <c>width</c>,
/// <c>keybits</c>, <c>wrapper</c>, <c>parallax</c> are always
/// emitted; an empty string, zero integer, or empty array is omitted.
/// <see cref="Hashes"/> carries either nothing or exactly eight slot
/// names in the order <c>[noise, lock, data1, data2, data3, start1,
/// start2, start3]</c>.
/// </summary>
public sealed class Profile
{
    /// <summary>Registry handle (<c>name</c>); empty on an anonymous
    /// record.</summary>
    public string Name { get; set; } = "";

    /// <summary>Pipeline mode (<c>mode</c>), e.g.
    /// <c>streaming-aead</c>.</summary>
    public string Mode { get; set; } = "";

    /// <summary>Seed width in bits (<c>width</c>).</summary>
    public int Width { get; set; }

    /// <summary>Uniform inner hash (<c>hash</c>); empty on a mixed
    /// profile.</summary>
    public string Hash { get; set; } = "";

    /// <summary>Eight-slot mixed constellation (<c>hashes</c>); empty
    /// on a uniform profile.</summary>
    public string[] Hashes { get; set; } = Array.Empty<string>();

    /// <summary>Key material size in bits (<c>keybits</c>).</summary>
    public int KeyBits { get; set; }

    /// <summary>MAC name (<c>mac</c>); empty on a No MAC
    /// profile.</summary>
    public string Mac { get; set; } = "";

    /// <summary>Tag stub size (<c>tagstub</c>); 0 when absent.</summary>
    public int TagStub { get; set; }

    /// <summary>Streaming chunk size (<c>chunk</c>); 0 when
    /// absent.</summary>
    public int Chunk { get; set; }

    /// <summary>Whether the wrapper layer is on
    /// (<c>wrapper</c>).</summary>
    public bool Wrapper { get; set; }

    /// <summary>Outer cipher name (<c>outer</c>); empty when
    /// absent.</summary>
    public string Outer { get; set; } = "";

    /// <summary>Whether the parallax layer is on
    /// (<c>parallax</c>).</summary>
    public bool Parallax { get; set; }

    /// <summary>Parallax palette (<c>palette</c>); empty when
    /// absent.</summary>
    public string[] Palette { get; set; } = Array.Empty<string>();

    /// <summary>Parallax segment size (<c>segment</c>); 0 when
    /// absent.</summary>
    public int Segment { get; set; }

    /// <summary>Renders the record as the wire JSON object.</summary>
    public string ToJson()
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            if (Name.Length > 0) w.WriteString("name", Name);
            w.WriteString("mode", Mode);
            w.WriteNumber("width", Width);
            if (Hash.Length > 0) w.WriteString("hash", Hash);
            if (Hashes.Length > 0) WriteStrings(w, "hashes", Hashes);
            w.WriteNumber("keybits", KeyBits);
            if (Mac.Length > 0) w.WriteString("mac", Mac);
            if (TagStub != 0) w.WriteNumber("tagstub", TagStub);
            if (Chunk != 0) w.WriteNumber("chunk", Chunk);
            w.WriteBoolean("wrapper", Wrapper);
            if (Outer.Length > 0) w.WriteString("outer", Outer);
            w.WriteBoolean("parallax", Parallax);
            if (Palette.Length > 0) WriteStrings(w, "palette", Palette);
            if (Segment != 0) w.WriteNumber("segment", Segment);
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    /// <summary>Decodes a wire JSON object into a record. Unknown keys
    /// are ignored here; the Go side is the strict decoder.</summary>
    public static Profile FromJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var p = new Profile();
        foreach (var prop in root.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "name": p.Name = prop.Value.GetString() ?? ""; break;
                case "mode": p.Mode = prop.Value.GetString() ?? ""; break;
                case "width": p.Width = prop.Value.GetInt32(); break;
                case "hash": p.Hash = prop.Value.GetString() ?? ""; break;
                case "hashes": p.Hashes = ReadStrings(prop.Value); break;
                case "keybits": p.KeyBits = prop.Value.GetInt32(); break;
                case "mac": p.Mac = prop.Value.GetString() ?? ""; break;
                case "tagstub": p.TagStub = prop.Value.GetInt32(); break;
                case "chunk": p.Chunk = prop.Value.GetInt32(); break;
                case "wrapper": p.Wrapper = prop.Value.GetBoolean(); break;
                case "outer": p.Outer = prop.Value.GetString() ?? ""; break;
                case "parallax": p.Parallax = prop.Value.GetBoolean(); break;
                case "palette": p.Palette = ReadStrings(prop.Value); break;
                case "segment": p.Segment = prop.Value.GetInt32(); break;
                default: break;
            }
        }
        return p;
    }

    /// <summary>Copies the record (arrays included).</summary>
    public Profile Clone()
    {
        var c = (Profile)MemberwiseClone();
        c.Hashes = (string[])Hashes.Clone();
        c.Palette = (string[])Palette.Clone();
        return c;
    }

    public override string ToString() => "Profile" + ToJson();

    public override bool Equals(object? obj) =>
        obj is Profile p && ToJson() == p.ToJson();

    public override int GetHashCode() => ToJson().GetHashCode();

    /// <summary>Decodes a JSON array of strings (the
    /// <c>ITB_Triple_Profiles</c> output).</summary>
    internal static string[] StringsFromJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return ReadStrings(doc.RootElement);
    }

    private static string[] ReadStrings(JsonElement e)
    {
        if (e.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<string>();
        }
        var list = new List<string>(e.GetArrayLength());
        foreach (var item in e.EnumerateArray())
        {
            list.Add(item.GetString() ?? "");
        }
        return list.ToArray();
    }

    private static void WriteStrings(Utf8JsonWriter w, string key, string[] values)
    {
        w.WriteStartArray(key);
        foreach (var v in values)
        {
            w.WriteStringValue(v);
        }
        w.WriteEndArray();
    }
}
