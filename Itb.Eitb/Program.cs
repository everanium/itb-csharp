// eitb — command-line demonstrator for the ITB C# binding.
//
// Subcommands:
//
//   eitb version                                   library + binding versions
//   eitb hashes                                    shipped hash primitive roster
//   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
//   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
//
// `encrypt` prints the session blob to stderr as hex; feed that hex
// back to `decrypt` on the receiving side.
//
// The `hashes` diagnostic iterates the registry through the internal
// FFI surface (InternalsVisibleTo) — the binding library itself
// deliberately exposes no primitive enumeration.

namespace Itb.Eitb;

internal static class Program
{
    private static int Main(string[] args)
    {
        Itb.Runtime.SetMemoryLimit(512L * 1024 * 1024);
        Itb.Runtime.SetGCPercent(20);
        try
        {
            switch (args.Length > 0 ? args[0] : null)
            {
                case "version":
                    return CmdVersion();
                case "hashes":
                    return CmdHashes();
                case "encrypt" when args.Length == 4:
                    return CmdEncrypt(args[1], args[2], args[3]);
                case "decrypt" when args.Length == 5:
                    return CmdDecrypt(args[1], args[2], args[3], args[4]);
                default:
                    Console.Error.WriteLine(
                        "usage: eitb version\n" +
                        "       eitb hashes\n" +
                        "       eitb encrypt <profile> <in-file> <out-file>\n" +
                        "       eitb decrypt <profile> <blob-hex> <in-file> <out-file>");
                    return 2;
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"eitb: {e.Message}");
            return 1;
        }
    }

    private static int CmdVersion()
    {
        Console.WriteLine($"libitb {Itb.Runtime.Version()}");
        Console.WriteLine($"itb-csharp {Itb.Runtime.BindingVersion}");
        return 0;
    }

    private static unsafe int CmdHashes()
    {
        int count = NativeMethods.ITB_HashCount();
        for (int i = 0; i < count; i++)
        {
            int index = i;
            string name = NativeMethods.ReadCString(
                (byte* buf, nuint cap, out nuint outLen) =>
                    NativeMethods.ITB_HashName(index, buf, cap, out outLen));
            int width = NativeMethods.ITB_HashWidth(i);
            Console.WriteLine($"{i,2}  {name,-12} {width} bits");
        }
        return 0;
    }

    // Profiles whose canonical name begins with "streaming-" route
    // through the one-shot streaming buffered pair instead of the
    // Single Message pair.
    private static bool IsStreamingProfile(string profile) =>
        profile.StartsWith("streaming-", StringComparison.Ordinal);

    // Recursively create the parent directory of `path` (mkdir -p).
    private static void EnsureParentDir(string path)
    {
        string? parent = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(parent))
        {
            Directory.CreateDirectory(parent);
        }
    }

    private static int CmdEncrypt(string profile, string inFile, string outFile)
    {
        var plain = File.ReadAllBytes(inFile);
        using var pipe = Pipeline.Init(profile);
        var wire = IsStreamingProfile(profile)
            ? pipe.EncryptStreamOneShot(plain)
            : pipe.EncryptMessage(plain);
        EnsureParentDir(outFile);
        File.WriteAllBytes(outFile, wire);
        Console.Error.WriteLine(Convert.ToHexStringLower(pipe.Blob));
        Console.WriteLine(
            $"encrypted {inFile} -> {outFile} ({plain.Length} -> {wire.Length} bytes)");
        return 0;
    }

    private static int CmdDecrypt(
        string profile, string blobHex, string inFile, string outFile)
    {
        var blob = Convert.FromHexString(blobHex);
        var wire = File.ReadAllBytes(inFile);
        using var pipe = Pipeline.Open(profile, blob);
        var plain = IsStreamingProfile(profile)
            ? pipe.DecryptStreamOneShot(wire)
            : pipe.DecryptMessage(wire);
        EnsureParentDir(outFile);
        File.WriteAllBytes(outFile, plain);
        Console.WriteLine(
            $"decrypted {inFile} -> {outFile} ({wire.Length} -> {plain.Length} bytes)");
        return 0;
    }
}
