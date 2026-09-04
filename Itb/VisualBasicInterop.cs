// Internal relay consumed by the sibling VB.NET binding's test suite
// (bindings/vbnet). The Opts query rendering is internal to the C#
// binding; this relay exposes it through InternalsVisibleTo so the
// VB.NET tests can assert on the rendered query string. Nothing here
// widens the public binding API.

using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("EveraniumItb.VisualBasic.Tests")]

namespace Itb;

/// <summary>Internal relay for the VB.NET binding tests: the Opts
/// query rendering (test parity).</summary>
internal static class VisualBasicInterop
{
    /// <summary>Renders an <see cref="Opts"/> builder's accumulated
    /// pairs as the query string handed to libitb (no FFI
    /// involved).</summary>
    internal static string RenderOpts(Opts opts) => opts.Build();
}
