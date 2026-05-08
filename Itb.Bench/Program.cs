// CLI dispatcher for the C# Easy Mode bench harness.
//
// Two pass shapes are exposed:
//
//     dotnet run --project Itb.Bench -c Release -- single
//     dotnet run --project Itb.Bench -c Release -- triple
//
// The orchestrator runs four passes (Single / Triple × ±LockSeed at
// min_seconds=5) and folds the per-pass output into BENCH.md. See
// Common.cs for the supported ITB_NONCE_BITS / ITB_LOCKSEED /
// ITB_BENCH_FILTER / ITB_BENCH_MIN_SEC environment variables.

namespace Itb.Bench;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 0;
        }

        var mode = args[0].Trim().ToLowerInvariant();
        switch (mode)
        {
            case "single":
                BenchSingle.Run();
                return 0;
            case "triple":
                BenchTriple.Run();
                return 0;
            case "-h":
            case "--help":
            case "help":
                PrintUsage();
                return 0;
            default:
                Console.Error.WriteLine($"unknown mode \"{mode}\" (expected \"single\" or \"triple\")");
                PrintUsage();
                return 2;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("usage: Itb.Bench <mode>");
        Console.WriteLine();
        Console.WriteLine("modes:");
        Console.WriteLine("  single   Single-Ouroboros bench grid (9 primitives + 1 mixed × 4 ops = 40 cases)");
        Console.WriteLine("  triple   Triple-Ouroboros bench grid (9 primitives + 1 mixed × 4 ops = 40 cases)");
        Console.WriteLine();
        Console.WriteLine("environment:");
        Console.WriteLine("  ITB_NONCE_BITS     128 / 256 / 512  (default 128)");
        Console.WriteLine("  ITB_LOCKSEED       non-empty / non-0 enables dedicated lockSeed (default off)");
        Console.WriteLine("  ITB_BENCH_FILTER   substring match on bench-case name (case-insensitive)");
        Console.WriteLine("  ITB_BENCH_MIN_SEC  minimum measured seconds per case (default 5.0)");
    }
}
