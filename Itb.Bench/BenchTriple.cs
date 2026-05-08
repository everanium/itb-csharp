// Easy Mode Triple-Ouroboros benchmarks for the C# binding.
//
// Mirrors the BenchmarkTriple* cohort from itb3_ext_test.go for the
// nine PRF-grade primitives, locked at 1024-bit ITB key width and
// 16 MiB CSPRNG-filled payload. One mixed-primitive variant
// (Encryptor.Mixed3 cycling the same BLAKE3 / Areion-SoEM-256 /
// ChaCha20 family + optional dedicated lockSeed used by bench_single_mixed)
// covers the Easy Mode Mixed surface alongside the single-primitive
// grid.
//
// Run with:
//
//     dotnet run --project Itb.Bench -c Release -- triple
//
//     ITB_NONCE_BITS=512 ITB_LOCKSEED=1 \
//         dotnet run --project Itb.Bench -c Release -- triple
//
//     ITB_BENCH_FILTER=blake3_encrypt \
//         dotnet run --project Itb.Bench -c Release -- triple
//
// The harness emits one Go-bench-style line per case (name, iters,
// ns/op, MB/s). See Common.cs for the supported environment
// variables and the convergence policy. The pure bit-soup
// configuration is intentionally not exercised on the Triple side —
// the BitSoup / LockSoup overlay routes through the auto-coupled
// path when ITB_LOCKSEED=1, which already covers the Triple bit-level
// split surface end-to-end.

namespace Itb.Bench;

/// <summary>
/// Triple-Ouroboros bench cases for the nine shipping PRF-grade
/// primitives plus one mixed-primitive variant.
/// </summary>
internal static class BenchTriple
{
    // Canonical 9-primitive PRF-grade order, mirroring bench_triple.rs
    // / bench_triple.py.
    private static readonly string[] PrimitivesCanonical =
    {
        "areion256",
        "areion512",
        "blake2b256",
        "blake2b512",
        "blake2s",
        "blake3",
        "aescmac",
        "siphash24",
        "chacha20",
    };

    // Mixed-primitive composition for Triple Ouroboros — the three
    // 256-bit-wide names used by bench_single_mixed are cycled across
    // the seven seed slots (noise + 3 data + 3 start). The dedicated
    // lockSeed slot is BLAKE3, attached only when ITB_LOCKSEED is set.
    private const string MixedNoise = "blake3";
    private const string MixedData1 = "areion256";
    private const string MixedData2 = "chacha20";
    private const string MixedData3 = "blake3";
    private const string MixedStart1 = "areion256";
    private const string MixedStart2 = "chacha20";
    private const string MixedStart3 = "blake3";

    /// <summary>
    /// Construct a single-primitive 1024-bit Triple-Ouroboros encryptor
    /// with HMAC-BLAKE3 authentication. Triple = mode "triple", 7-seed
    /// layout.
    /// </summary>
    private static Encryptor BuildTriple(string primitive)
    {
        var enc = new Encryptor(primitive, Common.KeyBits, Common.MacName, "triple");
        Common.ApplyLockSeedIfRequested(enc);
        return enc;
    }

    /// <summary>
    /// Construct a mixed-primitive Triple-Ouroboros encryptor with the
    /// three-name family across the seven middle slots. The dedicated
    /// lockSeed slot is allocated only when <c>ITB_LOCKSEED</c> is
    /// set, so the no-LockSeed bench arm measures the plain
    /// mixed-primitive cost without the BitSoup + LockSoup
    /// auto-couple.
    /// </summary>
    private static Encryptor BuildMixedTriple()
    {
        var primL = Common.EnvLockSeed() ? Common.MixedLock : null;
        return Encryptor.Mixed3(
            MixedNoise,
            MixedData1, MixedData2, MixedData3,
            MixedStart1, MixedStart2, MixedStart3,
            primL, Common.KeyBits, Common.MacName);
    }

    private static BenchCase MakeEncryptCase(string name, Encryptor enc)
    {
        var payload = Common.RandomBytes(Common.Payload16MB);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                _ = enc.Encrypt(payload);
            }
        }, Common.Payload16MB);
    }

    private static BenchCase MakeDecryptCase(string name, Encryptor enc)
    {
        var payload = Common.RandomBytes(Common.Payload16MB);
        var ciphertext = enc.Encrypt(payload);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                _ = enc.Decrypt(ciphertext);
            }
        }, Common.Payload16MB);
    }

    private static BenchCase MakeEncryptAuthCase(string name, Encryptor enc)
    {
        var payload = Common.RandomBytes(Common.Payload16MB);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                _ = enc.EncryptAuth(payload);
            }
        }, Common.Payload16MB);
    }

    private static BenchCase MakeDecryptAuthCase(string name, Encryptor enc)
    {
        var payload = Common.RandomBytes(Common.Payload16MB);
        var ciphertext = enc.EncryptAuth(payload);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                _ = enc.DecryptAuth(ciphertext);
            }
        }, Common.Payload16MB);
    }

    /// <summary>
    /// Assemble the full case list: 9 single-primitive entries × 4 ops
    /// plus 1 mixed entry × 4 ops = 40 cases. Order is primitive-major /
    /// op-minor so a filter on a primitive name keeps all four ops
    /// grouped together in the output.
    /// </summary>
    private static List<BenchCase> BuildCases()
    {
        var cases = new List<BenchCase>(40);
        foreach (var prim in PrimitivesCanonical)
        {
            var basePrefix = $"bench_triple_{prim}_{Common.KeyBits}bit";
            cases.Add(MakeEncryptCase($"{basePrefix}_encrypt_16mb", BuildTriple(prim)));
            cases.Add(MakeDecryptCase($"{basePrefix}_decrypt_16mb", BuildTriple(prim)));
            cases.Add(MakeEncryptAuthCase($"{basePrefix}_encrypt_auth_16mb", BuildTriple(prim)));
            cases.Add(MakeDecryptAuthCase($"{basePrefix}_decrypt_auth_16mb", BuildTriple(prim)));
        }
        var baseMixed = $"bench_triple_mixed_{Common.KeyBits}bit";
        cases.Add(MakeEncryptCase($"{baseMixed}_encrypt_16mb", BuildMixedTriple()));
        cases.Add(MakeDecryptCase($"{baseMixed}_decrypt_16mb", BuildMixedTriple()));
        cases.Add(MakeEncryptAuthCase($"{baseMixed}_encrypt_auth_16mb", BuildMixedTriple()));
        cases.Add(MakeDecryptAuthCase($"{baseMixed}_decrypt_auth_16mb", BuildMixedTriple()));
        return cases;
    }

    /// <summary>Bench entry point invoked by <see cref="Program"/>.</summary>
    public static void Run()
    {
        var nonceBits = Common.EnvNonceBits(128);
        Library.MaxWorkers = 0;
        Library.NonceBits = nonceBits;
        if (Common.EnvLockSeed())
        {
            Library.LockSoup = 1;
        }

        Console.WriteLine(
            string.Format(
                System.Globalization.CultureInfo.InvariantCulture,
                "# easy_triple primitives={0} key_bits={1} mac={2} nonce_bits={3} lockseed={4} workers=auto",
                PrimitivesCanonical.Length, Common.KeyBits, Common.MacName,
                nonceBits, Common.EnvLockSeed() ? "on" : "off"));
        Console.Out.Flush();

        var cases = BuildCases();
        cases.AddRange(BenchStream.BuildStreamCasesTriple());
        Common.RunAll(cases);
    }
}
