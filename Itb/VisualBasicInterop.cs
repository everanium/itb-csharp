// Pointer-free internal relays consumed by the sibling VB.NET
// binding (bindings/vbnet). Visual Basic has no unsafe / pointer
// surface, so the byte* plumbing of the hash-registry iteration and
// the internal Opts query rendering cannot be reached from VB code
// directly; these relays keep the pointer work on the C# side and
// are exposed through InternalsVisibleTo — the same privileged-eitb
// arrangement the C# Itb.Eitb project uses. Nothing here widens the
// public binding API.

using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("EveraniumItb.VisualBasic.Eitb")]
[assembly: InternalsVisibleTo("EveraniumItb.VisualBasic.Tests")]

namespace Itb;

/// <summary>Internal diagnostic relays for the VB.NET binding: the
/// hash-registry iteration triple (eitb <c>hashes</c>) and the Opts
/// query rendering (test parity).</summary>
internal static unsafe class VisualBasicInterop
{
    /// <summary>Registry size via <c>ITB_HashCount</c>.</summary>
    internal static int HashCount() => NativeMethods.ITB_HashCount();

    /// <summary>Primitive name at registry index <paramref name="i"/>
    /// via <c>ITB_HashName</c>.</summary>
    internal static string HashName(int i)
    {
        return NativeMethods.ReadCString(
            (byte* buf, nuint cap, out nuint len) =>
                NativeMethods.ITB_HashName(i, buf, cap, out len));
    }

    /// <summary>Hash width in bits at registry index
    /// <paramref name="i"/> via <c>ITB_HashWidth</c>.</summary>
    internal static int HashWidth(int i) => NativeMethods.ITB_HashWidth(i);

    /// <summary>Renders an <see cref="Opts"/> builder's accumulated
    /// pairs as the query string handed to libitb (no FFI
    /// involved).</summary>
    internal static string RenderOpts(Opts opts) => opts.Build();
}
