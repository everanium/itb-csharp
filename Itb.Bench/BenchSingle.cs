// Easy Mode Single-Ouroboros benchmarks for the C# binding.
//
// Mirrors the BenchmarkSingle* cohort from itb_ext_test.go for the
// nine PRF-grade primitives, locked at 1024-bit ITB key width and
// 16 MiB CSPRNG-filled payload. One mixed-primitive variant
// (Encryptor.Mixed with BLAKE3 / Areion-SoEM-256 / ChaCha20 across the
// noise / data / start slots, plus an optional dedicated lockSeed)
// covers the Easy Mode Mixed surface alongside the single-primitive
// grid.
//
// Run with:
//
//     dotnet run --project Itb.Bench -c Release -- single
//
//     ITB_NONCE_BITS=512 ITB_LOCKSEED=1 \
//         dotnet run --project Itb.Bench -c Release -- single
//
//     ITB_BENCH_FILTER=blake3_encrypt \
//         dotnet run --project Itb.Bench -c Release -- single
//
// The harness emits one Go-bench-style line per case (name, iters,
// ns/op, MB/s). See Common.cs for the supported environment
// variables and the convergence policy.

namespace Itb.Bench;

/// <summary>
/// Single-Ouroboros bench cases for the nine shipping PRF-grade
/// primitives plus one mixed-primitive variant.
/// </summary>
internal static class BenchSingle
{
    // Canonical 9-primitive PRF-grade order, mirroring bench_single.rs
    // / bench_single.py. The three below-spec lab primitives (CRC128,
    // FNV-1a, MD5) are not exposed through the libitb registry and are
    // therefore absent here by construction.
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

    // Mixed-primitive composition for bench_single_mixed_*. The three
    // user-facing slots (noise / data / start) span BLAKE3, Areion-SoEM-256
    // and ChaCha20 — every name resolves to a 256-bit native hash width
    // so the Encryptor.Mixed width-check passes. The dedicated lockSeed
    // primitive is BLAKE3, attached only when ITB_LOCKSEED is set.
    private const string MixedNoise = "blake3";
    private const string MixedData = "areion256";
    private const string MixedStart = "chacha20";

    /// <summary>
    /// Construct a single-primitive 1024-bit Single-Ouroboros encryptor
    /// with HMAC-BLAKE3 authentication, mirroring the shape used by every
    /// benchmark in this module.
    /// </summary>
    private static Encryptor BuildSingle(string primitive)
    {
        var enc = new Encryptor(primitive, Common.KeyBits, Common.MacName, "single");
        Common.ApplyLockSeedIfRequested(enc);
        return enc;
    }

    /// <summary>
    /// Construct a mixed-primitive Single-Ouroboros encryptor. The
    /// dedicated lockSeed slot is allocated only when
    /// <c>ITB_LOCKSEED</c> is set, so the no-LockSeed bench arm
    /// measures the plain mixed-primitive cost without the
    /// BitSoup + LockSoup auto-couple.
    /// </summary>
    private static Encryptor BuildMixedSingle()
    {
        // When primL is non-null, Encryptor.Mixed auto-couples
        // BitSoup + LockSoup on construction; an extra SetLockSeed
        // call would be a redundant no-op against the already-active
        // lockSeed slot. When primL is null the encryptor stays in
        // plain mixed mode.
        var primL = Common.EnvLockSeed() ? Common.MixedLock : null;
        return Encryptor.Mixed(
            MixedNoise, MixedData, MixedStart, primL, Common.KeyBits, Common.MacName);
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
            var basePrefix = $"bench_single_{prim}_{Common.KeyBits}bit";
            cases.Add(MakeEncryptCase($"{basePrefix}_encrypt_16mb", BuildSingle(prim)));
            cases.Add(MakeDecryptCase($"{basePrefix}_decrypt_16mb", BuildSingle(prim)));
            cases.Add(MakeEncryptAuthCase($"{basePrefix}_encrypt_auth_16mb", BuildSingle(prim)));
            cases.Add(MakeDecryptAuthCase($"{basePrefix}_decrypt_auth_16mb", BuildSingle(prim)));
        }
        var baseMixed = $"bench_single_mixed_{Common.KeyBits}bit";
        cases.Add(MakeEncryptCase($"{baseMixed}_encrypt_16mb", BuildMixedSingle()));
        cases.Add(MakeDecryptCase($"{baseMixed}_decrypt_16mb", BuildMixedSingle()));
        cases.Add(MakeEncryptAuthCase($"{baseMixed}_encrypt_auth_16mb", BuildMixedSingle()));
        cases.Add(MakeDecryptAuthCase($"{baseMixed}_decrypt_auth_16mb", BuildMixedSingle()));
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
                "# easy_single primitives={0} key_bits={1} mac={2} nonce_bits={3} lockseed={4} workers=auto",
                PrimitivesCanonical.Length, Common.KeyBits, Common.MacName,
                nonceBits, Common.EnvLockSeed() ? "on" : "off"));
        Console.Out.Flush();

        var cases = BuildCases();
        cases.AddRange(BenchStream.BuildStreamCasesSingle());
        Common.RunAll(cases);
    }
}
