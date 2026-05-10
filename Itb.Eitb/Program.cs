// C# eitb — runs every wrapper × ITB example end-to-end.
//
// Mirrors cmd/eitb/main.go adapted to the C# binding asymmetry: the
// binding has no Stream / IBufferWriter<byte> analogue for Non-AEAD
// streaming wrap surfaces (Streaming AEAD does have file-like helpers
// via Encryptor.EncryptStreamAuth / Cipher.EncryptStreamAuth, but the
// wrap layer still goes through the WrapStreamWriter.Update /
// UnwrapStreamReader.Update byte pump). The Non-AEAD streaming arm
// covers the User-Driven Loop variant only — caller produces an ITB
// ciphertext per chunk via Encryptor.Encrypt(chunk) (or the low-level
// Cipher.Encrypt), frames u32_LE_len || ct, and pushes through the
// wrap-stream writer.
//
// Matrix: 8 examples × 3 outer ciphers (aes / chacha / siphash) =
// 24 PASS/FAIL cells.
//
// Usage:
//
//     dotnet run --project Itb.Eitb
//     dotnet run --project Itb.Eitb -- --example aead
//     dotnet run --project Itb.Eitb -- --cipher aes -v

using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using Itb;
using Itb.Wrapper;
using ItbCipher = Itb.Cipher;
using OuterCipher = Itb.Wrapper.Cipher;

namespace Itb.Eitb;

internal static class Program
{
    private const int SingleMessageBytes = 1024;
    private const int StreamBytes = 64 * 1024;
    private const int StreamChunkSize = 16 * 1024;

    private static byte[] RandBytes(int n)
    {
        var buf = new byte[n];
        RandomNumberGenerator.Fill(buf);
        return buf;
    }

    private static string Sha256Short(byte[] b)
    {
        var hash = SHA256.HashData(b);
        return Convert.ToHexString(hash, 0, 8).ToLowerInvariant();
    }

    // ----------------------------------------------------------------
    // Common helpers
    // ----------------------------------------------------------------

    private static Encryptor BuildEasy(string? mac, int keyBits)
    {
        var enc = new Encryptor("areion512", keyBits, mac, "single");
        enc.SetNonceBits(512);
        enc.SetBarrierFill(4);
        enc.SetBitSoup(1);
        enc.SetLockSoup(1);
        return enc;
    }

    private static Seed[] BuildThreeSeeds(int keyBits)
    {
        return new[]
        {
            new Seed("areion512", keyBits),
            new Seed("areion512", keyBits),
            new Seed("areion512", keyBits),
        };
    }

    private static void DisposeSeeds(Seed[] seeds)
    {
        foreach (var s in seeds)
        {
            s.Dispose();
        }
    }

    private static void ApplyLowLevelConfig()
    {
        Library.NonceBits = 512;
        Library.BarrierFill = 4;
        Library.BitSoup = 1;
        Library.LockSoup = 1;
    }

    // ----------------------------------------------------------------
    // Streaming AEAD Easy (MAC Authenticated, IO-Driven)
    //
    // ITB Call: Encryptor.EncryptStreamAuth / DecryptStreamAuth.
    // Wrap shape: WrapStreamWriter / UnwrapStreamReader over the
    // continuous bytestream ITB emits.
    // ----------------------------------------------------------------

    private static (byte[], int) RunAeadEasyIo(OuterCipher cipher, byte[] plaintext)
    {
        using var enc = BuildEasy("hmac-blake3", 1024);
        var outerKey = Wrapper.Wrapper.GenerateKey(cipher);

        // Sender
        using var inner = new MemoryStream();
        enc.EncryptStreamAuth(new MemoryStream(plaintext), inner, StreamChunkSize);
        var innerBytes = inner.ToArray();
        using var ww = new WrapStreamWriter(cipher, outerKey);
        var nonce = ww.Nonce;
        var body = ww.Update(innerBytes);
        var wire = new byte[nonce.Length + body.Length];
        Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
        Buffer.BlockCopy(body, 0, wire, nonce.Length, body.Length);
        var wireN = wire.Length;

        // Receiver
        var nlen = Wrapper.Wrapper.NonceSize(cipher);
        using var ur = new UnwrapStreamReader(cipher, outerKey, wire.AsSpan(0, nlen));
        var innerWire = ur.Update(wire.AsSpan(nlen));
        using var outBuf = new MemoryStream();
        enc.DecryptStreamAuth(new MemoryStream(innerWire), outBuf);
        return (outBuf.ToArray(), wireN);
    }

    // ----------------------------------------------------------------
    // Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)
    // ----------------------------------------------------------------

    private static (byte[], int) RunAeadLowLevelIo(OuterCipher cipher, byte[] plaintext)
    {
        ApplyLowLevelConfig();
        var seeds = BuildThreeSeeds(1024);
        try
        {
            var macKey = RandBytes(32);
            using var mac = new Mac("hmac-blake3", macKey);
            var outerKey = Wrapper.Wrapper.GenerateKey(cipher);

            using var inner = new MemoryStream();
            StreamPipeline.EncryptStreamAuth(seeds[0], seeds[1], seeds[2], mac,
                new MemoryStream(plaintext), inner, StreamChunkSize);
            var innerBytes = inner.ToArray();

            using var ww = new WrapStreamWriter(cipher, outerKey);
            var nonce = ww.Nonce;
            var body = ww.Update(innerBytes);
            var wire = new byte[nonce.Length + body.Length];
            Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
            Buffer.BlockCopy(body, 0, wire, nonce.Length, body.Length);
            var wireN = wire.Length;

            var nlen = Wrapper.Wrapper.NonceSize(cipher);
            using var ur = new UnwrapStreamReader(cipher, outerKey, wire.AsSpan(0, nlen));
            var innerWire = ur.Update(wire.AsSpan(nlen));

            using var outBuf = new MemoryStream();
            StreamPipeline.DecryptStreamAuth(seeds[0], seeds[1], seeds[2], mac,
                new MemoryStream(innerWire), outBuf);
            return (outBuf.ToArray(), wireN);
        }
        finally
        {
            DisposeSeeds(seeds);
        }
    }

    // ----------------------------------------------------------------
    // Streaming Easy (No MAC, User-Driven Loop)
    //
    // Per-chunk encrypt + caller-side u32_LE framing emitted through
    // one wrap-stream session — both the length prefix and each
    // chunk body pass through the same keystream so neither shows in
    // cleartext.
    // ----------------------------------------------------------------

    private static (byte[], int) RunNoaeadEasyUserloop(OuterCipher cipher, byte[] plaintext)
    {
        using var enc = BuildEasy(null, 1024);
        var outerKey = Wrapper.Wrapper.GenerateKey(cipher);

        // Sender
        using var ww = new WrapStreamWriter(cipher, outerKey);
        using var wireBuf = new MemoryStream();
        wireBuf.Write(ww.Nonce);
        var off = 0;
        while (off < plaintext.Length)
        {
            var take = Math.Min(StreamChunkSize, plaintext.Length - off);
            var ct = enc.Encrypt(plaintext.AsSpan(off, take));
            var lenLe = BitConverter.GetBytes((uint)ct.Length);
            wireBuf.Write(ww.Update(lenLe));
            wireBuf.Write(ww.Update(ct));
            off += take;
        }
        var wire = wireBuf.ToArray();
        var wireN = wire.Length;

        // Receiver
        var nlen = Wrapper.Wrapper.NonceSize(cipher);
        using var ur = new UnwrapStreamReader(cipher, outerKey, wire.AsSpan(0, nlen));
        var decrypted = ur.Update(wire.AsSpan(nlen));
        using var outBuf = new MemoryStream();
        var pos = 0;
        while (pos < decrypted.Length)
        {
            if (pos + 4 > decrypted.Length)
            {
                throw new InvalidDataException($"truncated length prefix at pos {pos}");
            }
            var clen = (int)BitConverter.ToUInt32(decrypted, pos);
            pos += 4;
            if (pos + clen > decrypted.Length)
            {
                throw new InvalidDataException($"truncated body at pos {pos}: need {clen}");
            }
            var pt = enc.Decrypt(decrypted.AsSpan(pos, clen));
            outBuf.Write(pt);
            pos += clen;
        }
        return (outBuf.ToArray(), wireN);
    }

    // ----------------------------------------------------------------
    // Streaming Low-Level (No MAC, User-Driven Loop)
    // ----------------------------------------------------------------

    private static (byte[], int) RunNoaeadLowLevelUserloop(OuterCipher cipher, byte[] plaintext)
    {
        ApplyLowLevelConfig();
        var seeds = BuildThreeSeeds(1024);
        try
        {
            var outerKey = Wrapper.Wrapper.GenerateKey(cipher);

            using var ww = new WrapStreamWriter(cipher, outerKey);
            using var wireBuf = new MemoryStream();
            wireBuf.Write(ww.Nonce);
            var off = 0;
            while (off < plaintext.Length)
            {
                var take = Math.Min(StreamChunkSize, plaintext.Length - off);
                var ct = ItbCipher.Encrypt(seeds[0], seeds[1], seeds[2], plaintext.AsSpan(off, take));
                var lenLe = BitConverter.GetBytes((uint)ct.Length);
                wireBuf.Write(ww.Update(lenLe));
                wireBuf.Write(ww.Update(ct));
                off += take;
            }
            var wire = wireBuf.ToArray();
            var wireN = wire.Length;

            var nlen = Wrapper.Wrapper.NonceSize(cipher);
            using var ur = new UnwrapStreamReader(cipher, outerKey, wire.AsSpan(0, nlen));
            var decrypted = ur.Update(wire.AsSpan(nlen));
            using var outBuf = new MemoryStream();
            var pos = 0;
            while (pos < decrypted.Length)
            {
                if (pos + 4 > decrypted.Length)
                {
                    throw new InvalidDataException($"truncated length prefix at pos {pos}");
                }
                var clen = (int)BitConverter.ToUInt32(decrypted, pos);
                pos += 4;
                if (pos + clen > decrypted.Length)
                {
                    throw new InvalidDataException($"truncated body at pos {pos}: need {clen}");
                }
                var pt = ItbCipher.Decrypt(seeds[0], seeds[1], seeds[2], decrypted.AsSpan(pos, clen));
                outBuf.Write(pt);
                pos += clen;
            }
            return (outBuf.ToArray(), wireN);
        }
        finally
        {
            DisposeSeeds(seeds);
        }
    }

    // ----------------------------------------------------------------
    // Single Message — Easy: Areion-SoEM-512 (No MAC)
    //
    // One enc.Encrypt() call → one ITB blob. WrapInPlace mutates the
    // blob and returns the per-stream nonce; the caller composes
    // nonce || mutated-blob to produce the wire. UnwrapInPlace
    // mutates the wire and returns a Span aliasing the recovered
    // blob.
    // ----------------------------------------------------------------

    private static (byte[], int) RunMessageEasyNomac(OuterCipher cipher, byte[] plaintext)
    {
        using var enc = BuildEasy(null, 2048);
        var outerKey = Wrapper.Wrapper.GenerateKey(cipher);

        var encrypted = enc.Encrypt(plaintext);
        // wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
        // var wire = Wrapper.Wrapper.Wrap(cipher, outerKey, encrypted);
        var nonce = Wrapper.Wrapper.WrapInPlace(cipher, outerKey, encrypted);
        var wire = new byte[nonce.Length + encrypted.Length];
        Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
        Buffer.BlockCopy(encrypted, 0, wire, nonce.Length, encrypted.Length);
        var wireN = wire.Length;

        // unwrap respects immutability of `wire` (allocates a fresh recovered buffer):
        // var recovered = Wrapper.Wrapper.Unwrap(cipher, outerKey, wire);
        var recoveredSpan = Wrapper.Wrapper.UnwrapInPlace(cipher, outerKey, wire);
        var recovered = recoveredSpan.ToArray();
        var pt = enc.Decrypt(recovered);
        return (pt, wireN);
    }

    // ----------------------------------------------------------------
    // Single Message — Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated)
    // ----------------------------------------------------------------

    private static (byte[], int) RunMessageEasyAuth(OuterCipher cipher, byte[] plaintext)
    {
        using var enc = BuildEasy("hmac-blake3", 2048);
        var outerKey = Wrapper.Wrapper.GenerateKey(cipher);

        var encrypted = enc.EncryptAuth(plaintext);
        // wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
        // var wire = Wrapper.Wrapper.Wrap(cipher, outerKey, encrypted);
        var nonce = Wrapper.Wrapper.WrapInPlace(cipher, outerKey, encrypted);
        var wire = new byte[nonce.Length + encrypted.Length];
        Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
        Buffer.BlockCopy(encrypted, 0, wire, nonce.Length, encrypted.Length);
        var wireN = wire.Length;

        // unwrap respects immutability of `wire` (allocates a fresh recovered buffer):
        // var recovered = Wrapper.Wrapper.Unwrap(cipher, outerKey, wire);
        var recoveredSpan = Wrapper.Wrapper.UnwrapInPlace(cipher, outerKey, wire);
        var recovered = recoveredSpan.ToArray();
        var pt = enc.DecryptAuth(recovered);
        return (pt, wireN);
    }

    // ----------------------------------------------------------------
    // Single Message — Low-Level: Areion-SoEM-512 (No MAC)
    // ----------------------------------------------------------------

    private static (byte[], int) RunMessageLowLevelNomac(OuterCipher cipher, byte[] plaintext)
    {
        ApplyLowLevelConfig();
        var seeds = BuildThreeSeeds(2048);
        try
        {
            var outerKey = Wrapper.Wrapper.GenerateKey(cipher);

            var encrypted = ItbCipher.Encrypt(seeds[0], seeds[1], seeds[2], plaintext);
            // wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
            // var wire = Wrapper.Wrapper.Wrap(cipher, outerKey, encrypted);
            var nonce = Wrapper.Wrapper.WrapInPlace(cipher, outerKey, encrypted);
            var wire = new byte[nonce.Length + encrypted.Length];
            Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
            Buffer.BlockCopy(encrypted, 0, wire, nonce.Length, encrypted.Length);
            var wireN = wire.Length;

            // unwrap respects immutability of `wire` (allocates a fresh recovered buffer):
            // var recovered = Wrapper.Wrapper.Unwrap(cipher, outerKey, wire);
            var recoveredSpan = Wrapper.Wrapper.UnwrapInPlace(cipher, outerKey, wire);
            var recovered = recoveredSpan.ToArray();
            var pt = ItbCipher.Decrypt(seeds[0], seeds[1], seeds[2], recovered);
            return (pt, wireN);
        }
        finally
        {
            DisposeSeeds(seeds);
        }
    }

    // ----------------------------------------------------------------
    // Single Message — Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated)
    // ----------------------------------------------------------------

    private static (byte[], int) RunMessageLowLevelAuth(OuterCipher cipher, byte[] plaintext)
    {
        ApplyLowLevelConfig();
        var seeds = BuildThreeSeeds(2048);
        try
        {
            var macKey = RandBytes(32);
            using var mac = new Mac("hmac-blake3", macKey);
            var outerKey = Wrapper.Wrapper.GenerateKey(cipher);

            var encrypted = ItbCipher.EncryptAuth(seeds[0], seeds[1], seeds[2], mac, plaintext);
            // wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
            // var wire = Wrapper.Wrapper.Wrap(cipher, outerKey, encrypted);
            var nonce = Wrapper.Wrapper.WrapInPlace(cipher, outerKey, encrypted);
            var wire = new byte[nonce.Length + encrypted.Length];
            Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
            Buffer.BlockCopy(encrypted, 0, wire, nonce.Length, encrypted.Length);
            var wireN = wire.Length;

            // unwrap respects immutability of `wire` (allocates a fresh recovered buffer):
            // var recovered = Wrapper.Wrapper.Unwrap(cipher, outerKey, wire);
            var recoveredSpan = Wrapper.Wrapper.UnwrapInPlace(cipher, outerKey, wire);
            var recovered = recoveredSpan.ToArray();
            var pt = ItbCipher.DecryptAuth(seeds[0], seeds[1], seeds[2], mac, recovered);
            return (pt, wireN);
        }
        finally
        {
            DisposeSeeds(seeds);
        }
    }

    // ----------------------------------------------------------------
    // Matrix runner
    // ----------------------------------------------------------------

    private delegate (byte[], int) ExampleFn(OuterCipher cipher, byte[] plaintext);

    private sealed record Example(string Name, int PlaintextN, ExampleFn Run);

    private static Example[] Examples() => new[]
    {
        new Example("aead-easy-io",             StreamBytes,         RunAeadEasyIo),
        new Example("aead-lowlevel-io",         StreamBytes,         RunAeadLowLevelIo),
        new Example("noaead-easy-userloop",     StreamBytes,         RunNoaeadEasyUserloop),
        new Example("noaead-lowlevel-userloop", StreamBytes,         RunNoaeadLowLevelUserloop),
        new Example("message-easy-nomac",       SingleMessageBytes,  RunMessageEasyNomac),
        new Example("message-easy-auth",        SingleMessageBytes,  RunMessageEasyAuth),
        new Example("message-lowlevel-nomac",   SingleMessageBytes,  RunMessageLowLevelNomac),
        new Example("message-lowlevel-auth",    SingleMessageBytes,  RunMessageLowLevelAuth),
    };

    private static int Main(string[] args)
    {
        var (exampleFilter, cipherFilter, verbose) = ParseArgs(args);

        Library.MaxWorkers = 0;

        var pass = 0;
        var fail = 0;
        var examples = Examples();

        foreach (var ex in examples)
        {
            if (!string.IsNullOrEmpty(exampleFilter) && !ex.Name.Contains(exampleFilter))
            {
                continue;
            }
            foreach (var cipher in Wrapper.Wrapper.AllCiphers)
            {
                if (!string.IsNullOrEmpty(cipherFilter) && cipher.ToFfiName() != cipherFilter)
                {
                    continue;
                }
                var plaintext = RandBytes(ex.PlaintextN);
                byte[] recovered;
                int wireN;
                string? err = null;
                try
                {
                    (recovered, wireN) = ex.Run(cipher, plaintext);
                }
                catch (Exception e)
                {
                    recovered = Array.Empty<byte>();
                    wireN = 0;
                    err = e.Message;
                }
                var ok = err is null && recovered.AsSpan().SequenceEqual(plaintext);
                var tag = ok ? "PASS" : "FAIL";
                var line = string.Format(
                    CultureInfo.InvariantCulture,
                    "[{0}] {1,-26} + {2,-8}   pt={3} wire={4}",
                    tag, ex.Name, cipher.ToFfiName(), ex.PlaintextN, wireN);
                if (!ok)
                {
                    if (err is not null)
                    {
                        line += $"  err: {err}";
                    }
                    else
                    {
                        line += string.Format(CultureInfo.InvariantCulture,
                            "  err: plaintext mismatch (pt={0} rcv={1})",
                            Sha256Short(plaintext), Sha256Short(recovered));
                    }
                }
                Console.WriteLine(line);
                if (verbose && ok)
                {
                    Console.WriteLine($"       pt fingerprint:  {Sha256Short(plaintext)}");
                    Console.WriteLine($"       rcv fingerprint: {Sha256Short(recovered)}");
                }
                if (ok) { pass++; } else { fail++; }
            }
        }

        Console.WriteLine();
        Console.WriteLine($"=== Summary: {pass} PASS, {fail} FAIL ===");
        return fail > 0 ? 1 : 0;
    }

    private static (string ExampleFilter, string CipherFilter, bool Verbose) ParseArgs(string[] args)
    {
        var ex = string.Empty;
        var cn = string.Empty;
        var verbose = false;
        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a == "--example" && i + 1 < args.Length) { ex = args[++i]; }
            else if (a.StartsWith("--example=", StringComparison.Ordinal)) { ex = a["--example=".Length..]; }
            else if (a == "--cipher" && i + 1 < args.Length) { cn = args[++i]; }
            else if (a.StartsWith("--cipher=", StringComparison.Ordinal)) { cn = a["--cipher=".Length..]; }
            else if (a == "-v" || a == "--verbose") { verbose = true; }
            else if (a == "-h" || a == "--help")
            {
                Console.Error.WriteLine("Usage: Itb.Eitb [--example NAME] [--cipher aes|chacha|siphash] [-v]");
                Environment.Exit(0);
            }
            else
            {
                Console.Error.WriteLine($"eitb: unknown argument: {a}");
                Environment.Exit(2);
            }
        }
        return (ex, cn, verbose);
    }
}
