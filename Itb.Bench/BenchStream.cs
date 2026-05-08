// Streaming benchmarks for the C# binding — Easy Mode + Low-Level
// Mode across Single + Triple Ouroboros, encrypt + decrypt, with two
// caller shapes (Streaming AEAD over System.IO.Stream and plain
// caller-driven per-chunk loop). Eight cases per width × two widths
// = sixteen total streaming cases.
//
// The build helpers BuildStreamCasesSingle / BuildStreamCasesTriple
// fan the eight per-width cases into the existing BenchSingle.Run /
// BenchTriple.Run case lists via a single AddRange invocation (one
// line per file). Setup — CSPRNG payload fill, Encryptor / Seed /
// Mac construction, decrypt-side ciphertext pre-encryption — runs
// outside the timed iter body, mirroring the Python and Rust
// streaming-bench precedent.
//
// Configuration (lock-step across all 16 cases):
//
//   Primitive       areion512 (Areion-SoEM-512)
//   ITB key bits    1024
//   MAC (AEAD only) hmac-blake3 (32-byte CSPRNG key)
//   Total payload   64 MiB CSPRNG
//   Chunk size      16 MiB
//   bit-soup        off (default)
//   lock-soup       off (default)
//   lock-seed       off (default)
//
// AEAD-IO variant — Streaming AEAD wire transcript: 32-byte CSPRNG
// stream_id prefix followed by concatenated authenticated chunks.
// Easy path drives Encryptor.EncryptStreamAuth(input, output);
// Low-Level path drives StreamPipeline.EncryptStreamAuth(noise, data,
// start, mac, input, output).
//
// UserLoop variant — plain (No-MAC) Streaming via caller-side
// per-chunk loop. Wire framing: 4-byte big-endian ciphertext length
// prefix per chunk, matching the C# binding's documented framing
// convention for plain caller-driven streaming. Easy path runs
// Encryptor.Encrypt(chunk) per chunk; Low-Level path runs
// Cipher.Encrypt(noise, data, start, chunk) per chunk.

using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;

namespace Itb.Bench;

/// <summary>
/// Streaming bench-case builders for the (Mode × Width × Op × Variant)
/// matrix. The two public entry points are
/// <see cref="BuildStreamCasesSingle"/> (eight Single Ouroboros cases)
/// and <see cref="BuildStreamCasesTriple"/> (eight Triple Ouroboros
/// cases); each is wired into the existing BenchSingle / BenchTriple
/// case fan-in via one AddRange line in their respective Run method.
/// </summary>
internal static class BenchStream
{
    // Streaming-bench configuration constants — held local to this
    // module so the existing 16-MiB single-shot cases in BenchSingle /
    // BenchTriple keep their own Common.Payload16MB constant and
    // remain unaffected.

    /// <summary>Streaming primitive — Areion-SoEM-512.</summary>
    private const string StreamPrimitive = "areion512";

    /// <summary>Total streaming-bench payload (64 MiB).</summary>
    private const int StreamPayloadBytes = 64 * 1024 * 1024;

    /// <summary>Per-chunk size for streaming-bench cases (16 MiB).</summary>
    private const int StreamChunkSize = 16 * 1024 * 1024;

    /// <summary>4-byte big-endian length-prefix framing for the
    /// caller-driven plain-stream (UserLoop) variant. The decryptor
    /// reads four header bytes, parses the chunk length, then reads
    /// that many ciphertext bytes — matching the framing convention
    /// documented for the C# binding's plain caller-driven streaming
    /// example.</summary>
    private const int FramingHeaderBytes = 4;

    // ----------------------------------------------------------------
    // Public entry points — fan-in helpers for BenchSingle / BenchTriple
    // ----------------------------------------------------------------

    /// <summary>
    /// Build the eight Single Ouroboros streaming-bench cases:
    /// Easy + Low-Level, encrypt + decrypt, AEAD-IO + UserLoop.
    /// </summary>
    public static List<BenchCase> BuildStreamCasesSingle()
    {
        var cases = new List<BenchCase>(8);
        var basePrefix = $"bench_single_stream_{StreamPrimitive}_{Common.KeyBits}bit_64mb";
        cases.Add(MakeEasyAeadIoEncryptSingle($"{basePrefix}_easy_encrypt_aead_io"));
        cases.Add(MakeEasyAeadIoDecryptSingle($"{basePrefix}_easy_decrypt_aead_io"));
        cases.Add(MakeEasyUserLoopEncryptSingle($"{basePrefix}_easy_encrypt_userloop"));
        cases.Add(MakeEasyUserLoopDecryptSingle($"{basePrefix}_easy_decrypt_userloop"));
        cases.Add(MakeLowLevelAeadIoEncryptSingle($"{basePrefix}_lowlevel_encrypt_aead_io"));
        cases.Add(MakeLowLevelAeadIoDecryptSingle($"{basePrefix}_lowlevel_decrypt_aead_io"));
        cases.Add(MakeLowLevelUserLoopEncryptSingle($"{basePrefix}_lowlevel_encrypt_userloop"));
        cases.Add(MakeLowLevelUserLoopDecryptSingle($"{basePrefix}_lowlevel_decrypt_userloop"));
        return cases;
    }

    /// <summary>
    /// Build the eight Triple Ouroboros streaming-bench cases:
    /// Easy + Low-Level, encrypt + decrypt, AEAD-IO + UserLoop.
    /// </summary>
    public static List<BenchCase> BuildStreamCasesTriple()
    {
        var cases = new List<BenchCase>(8);
        var basePrefix = $"bench_triple_stream_{StreamPrimitive}_{Common.KeyBits}bit_64mb";
        cases.Add(MakeEasyAeadIoEncryptTriple($"{basePrefix}_easy_encrypt_aead_io"));
        cases.Add(MakeEasyAeadIoDecryptTriple($"{basePrefix}_easy_decrypt_aead_io"));
        cases.Add(MakeEasyUserLoopEncryptTriple($"{basePrefix}_easy_encrypt_userloop"));
        cases.Add(MakeEasyUserLoopDecryptTriple($"{basePrefix}_easy_decrypt_userloop"));
        cases.Add(MakeLowLevelAeadIoEncryptTriple($"{basePrefix}_lowlevel_encrypt_aead_io"));
        cases.Add(MakeLowLevelAeadIoDecryptTriple($"{basePrefix}_lowlevel_decrypt_aead_io"));
        cases.Add(MakeLowLevelUserLoopEncryptTriple($"{basePrefix}_lowlevel_encrypt_userloop"));
        cases.Add(MakeLowLevelUserLoopDecryptTriple($"{basePrefix}_lowlevel_decrypt_userloop"));
        return cases;
    }

    // ----------------------------------------------------------------
    // Setup helpers — Encryptor / Seed / MAC construction outside the
    // timed body. Default config — bit-soup / lock-soup / lock-seed
    // are NOT engaged on these encryptors regardless of the
    // ITB_LOCKSEED env var, so the streaming numbers report the bare
    // streaming overhead independent of the existing single-shot
    // ±LockSeed bench arms.
    // ----------------------------------------------------------------

    private static Encryptor BuildEasyEncryptor(string mode)
    {
        return new Encryptor(StreamPrimitive, Common.KeyBits, Common.MacName, mode);
    }

    private static (Seed noise, Seed data, Seed start) BuildLowLevelSeedsSingle()
    {
        var noise = new Seed(StreamPrimitive, Common.KeyBits);
        var data = new Seed(StreamPrimitive, Common.KeyBits);
        var start = new Seed(StreamPrimitive, Common.KeyBits);
        return (noise, data, start);
    }

    private static (Seed noise, Seed d1, Seed d2, Seed d3, Seed s1, Seed s2, Seed s3)
        BuildLowLevelSeedsTriple()
    {
        var noise = new Seed(StreamPrimitive, Common.KeyBits);
        var d1 = new Seed(StreamPrimitive, Common.KeyBits);
        var d2 = new Seed(StreamPrimitive, Common.KeyBits);
        var d3 = new Seed(StreamPrimitive, Common.KeyBits);
        var s1 = new Seed(StreamPrimitive, Common.KeyBits);
        var s2 = new Seed(StreamPrimitive, Common.KeyBits);
        var s3 = new Seed(StreamPrimitive, Common.KeyBits);
        return (noise, d1, d2, d3, s1, s2, s3);
    }

    private static Mac BuildMac()
    {
        Span<byte> key = stackalloc byte[32];
        RandomNumberGenerator.Fill(key);
        return new Mac(Common.MacName, key);
    }

    // ----------------------------------------------------------------
    // Easy Mode — Single Ouroboros
    // ----------------------------------------------------------------

    private static BenchCase MakeEasyAeadIoEncryptSingle(string name)
    {
        var enc = BuildEasyEncryptor("single");
        var payload = Common.RandomBytes(StreamPayloadBytes);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var src = new MemoryStream(payload, writable: false);
                using var dst = new MemoryStream();
                enc.EncryptStreamAuth(src, dst, StreamChunkSize);
            }
        }, StreamPayloadBytes);
    }

    private static BenchCase MakeEasyAeadIoDecryptSingle(string name)
    {
        var enc = BuildEasyEncryptor("single");
        var payload = Common.RandomBytes(StreamPayloadBytes);
        var transcript = EncryptToBytesEasyAeadIo(enc, payload);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var src = new MemoryStream(transcript, writable: false);
                using var dst = new MemoryStream();
                enc.DecryptStreamAuth(src, dst, StreamChunkSize);
            }
        }, StreamPayloadBytes);
    }

    private static BenchCase MakeEasyUserLoopEncryptSingle(string name)
    {
        var enc = BuildEasyEncryptor("single");
        var payload = Common.RandomBytes(StreamPayloadBytes);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var dst = new MemoryStream();
                EncryptUserLoopEasy(enc, payload, dst);
            }
        }, StreamPayloadBytes);
    }

    private static BenchCase MakeEasyUserLoopDecryptSingle(string name)
    {
        var enc = BuildEasyEncryptor("single");
        var payload = Common.RandomBytes(StreamPayloadBytes);
        byte[] transcript;
        using (var pre = new MemoryStream())
        {
            EncryptUserLoopEasy(enc, payload, pre);
            transcript = pre.ToArray();
        }
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var src = new MemoryStream(transcript, writable: false);
                using var dst = new MemoryStream();
                DecryptUserLoopEasy(enc, src, dst);
            }
        }, StreamPayloadBytes);
    }

    // ----------------------------------------------------------------
    // Easy Mode — Triple Ouroboros
    // ----------------------------------------------------------------

    private static BenchCase MakeEasyAeadIoEncryptTriple(string name)
    {
        var enc = BuildEasyEncryptor("triple");
        var payload = Common.RandomBytes(StreamPayloadBytes);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var src = new MemoryStream(payload, writable: false);
                using var dst = new MemoryStream();
                enc.EncryptStreamAuth(src, dst, StreamChunkSize);
            }
        }, StreamPayloadBytes);
    }

    private static BenchCase MakeEasyAeadIoDecryptTriple(string name)
    {
        var enc = BuildEasyEncryptor("triple");
        var payload = Common.RandomBytes(StreamPayloadBytes);
        var transcript = EncryptToBytesEasyAeadIo(enc, payload);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var src = new MemoryStream(transcript, writable: false);
                using var dst = new MemoryStream();
                enc.DecryptStreamAuth(src, dst, StreamChunkSize);
            }
        }, StreamPayloadBytes);
    }

    private static BenchCase MakeEasyUserLoopEncryptTriple(string name)
    {
        var enc = BuildEasyEncryptor("triple");
        var payload = Common.RandomBytes(StreamPayloadBytes);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var dst = new MemoryStream();
                EncryptUserLoopEasy(enc, payload, dst);
            }
        }, StreamPayloadBytes);
    }

    private static BenchCase MakeEasyUserLoopDecryptTriple(string name)
    {
        var enc = BuildEasyEncryptor("triple");
        var payload = Common.RandomBytes(StreamPayloadBytes);
        byte[] transcript;
        using (var pre = new MemoryStream())
        {
            EncryptUserLoopEasy(enc, payload, pre);
            transcript = pre.ToArray();
        }
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var src = new MemoryStream(transcript, writable: false);
                using var dst = new MemoryStream();
                DecryptUserLoopEasy(enc, src, dst);
            }
        }, StreamPayloadBytes);
    }

    // ----------------------------------------------------------------
    // Low-Level Mode — Single Ouroboros
    // ----------------------------------------------------------------

    private static BenchCase MakeLowLevelAeadIoEncryptSingle(string name)
    {
        var (noise, data, start) = BuildLowLevelSeedsSingle();
        var mac = BuildMac();
        var payload = Common.RandomBytes(StreamPayloadBytes);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var src = new MemoryStream(payload, writable: false);
                using var dst = new MemoryStream();
                StreamPipeline.EncryptStreamAuth(
                    noise, data, start, mac, src, dst, StreamChunkSize);
            }
        }, StreamPayloadBytes);
    }

    private static BenchCase MakeLowLevelAeadIoDecryptSingle(string name)
    {
        var (noise, data, start) = BuildLowLevelSeedsSingle();
        var mac = BuildMac();
        var payload = Common.RandomBytes(StreamPayloadBytes);
        byte[] transcript;
        using (var pre = new MemoryStream())
        using (var srcPre = new MemoryStream(payload, writable: false))
        {
            StreamPipeline.EncryptStreamAuth(
                noise, data, start, mac, srcPre, pre, StreamChunkSize);
            transcript = pre.ToArray();
        }
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var src = new MemoryStream(transcript, writable: false);
                using var dst = new MemoryStream();
                StreamPipeline.DecryptStreamAuth(
                    noise, data, start, mac, src, dst, StreamChunkSize);
            }
        }, StreamPayloadBytes);
    }

    private static BenchCase MakeLowLevelUserLoopEncryptSingle(string name)
    {
        var (noise, data, start) = BuildLowLevelSeedsSingle();
        var payload = Common.RandomBytes(StreamPayloadBytes);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var dst = new MemoryStream();
                EncryptUserLoopLowLevelSingle(noise, data, start, payload, dst);
            }
        }, StreamPayloadBytes);
    }

    private static BenchCase MakeLowLevelUserLoopDecryptSingle(string name)
    {
        var (noise, data, start) = BuildLowLevelSeedsSingle();
        var payload = Common.RandomBytes(StreamPayloadBytes);
        byte[] transcript;
        using (var pre = new MemoryStream())
        {
            EncryptUserLoopLowLevelSingle(noise, data, start, payload, pre);
            transcript = pre.ToArray();
        }
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var src = new MemoryStream(transcript, writable: false);
                using var dst = new MemoryStream();
                DecryptUserLoopLowLevelSingle(noise, data, start, src, dst);
            }
        }, StreamPayloadBytes);
    }

    // ----------------------------------------------------------------
    // Low-Level Mode — Triple Ouroboros
    // ----------------------------------------------------------------

    private static BenchCase MakeLowLevelAeadIoEncryptTriple(string name)
    {
        var (noise, d1, d2, d3, s1, s2, s3) = BuildLowLevelSeedsTriple();
        var mac = BuildMac();
        var payload = Common.RandomBytes(StreamPayloadBytes);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var src = new MemoryStream(payload, writable: false);
                using var dst = new MemoryStream();
                StreamPipeline.EncryptStreamAuthTriple(
                    noise, d1, d2, d3, s1, s2, s3, mac, src, dst, StreamChunkSize);
            }
        }, StreamPayloadBytes);
    }

    private static BenchCase MakeLowLevelAeadIoDecryptTriple(string name)
    {
        var (noise, d1, d2, d3, s1, s2, s3) = BuildLowLevelSeedsTriple();
        var mac = BuildMac();
        var payload = Common.RandomBytes(StreamPayloadBytes);
        byte[] transcript;
        using (var pre = new MemoryStream())
        using (var srcPre = new MemoryStream(payload, writable: false))
        {
            StreamPipeline.EncryptStreamAuthTriple(
                noise, d1, d2, d3, s1, s2, s3, mac, srcPre, pre, StreamChunkSize);
            transcript = pre.ToArray();
        }
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var src = new MemoryStream(transcript, writable: false);
                using var dst = new MemoryStream();
                StreamPipeline.DecryptStreamAuthTriple(
                    noise, d1, d2, d3, s1, s2, s3, mac, src, dst, StreamChunkSize);
            }
        }, StreamPayloadBytes);
    }

    private static BenchCase MakeLowLevelUserLoopEncryptTriple(string name)
    {
        var (noise, d1, d2, d3, s1, s2, s3) = BuildLowLevelSeedsTriple();
        var payload = Common.RandomBytes(StreamPayloadBytes);
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var dst = new MemoryStream();
                EncryptUserLoopLowLevelTriple(noise, d1, d2, d3, s1, s2, s3, payload, dst);
            }
        }, StreamPayloadBytes);
    }

    private static BenchCase MakeLowLevelUserLoopDecryptTriple(string name)
    {
        var (noise, d1, d2, d3, s1, s2, s3) = BuildLowLevelSeedsTriple();
        var payload = Common.RandomBytes(StreamPayloadBytes);
        byte[] transcript;
        using (var pre = new MemoryStream())
        {
            EncryptUserLoopLowLevelTriple(noise, d1, d2, d3, s1, s2, s3, payload, pre);
            transcript = pre.ToArray();
        }
        return new BenchCase(name, iters =>
        {
            for (long i = 0; i < iters; i++)
            {
                using var src = new MemoryStream(transcript, writable: false);
                using var dst = new MemoryStream();
                DecryptUserLoopLowLevelTriple(noise, d1, d2, d3, s1, s2, s3, src, dst);
            }
        }, StreamPayloadBytes);
    }

    // ----------------------------------------------------------------
    // Pre-encryption helper — produces the Easy AEAD-IO transcript
    // captured outside the timed body so the decrypt-side bench
    // measures only the inverse path.
    // ----------------------------------------------------------------

    private static byte[] EncryptToBytesEasyAeadIo(Encryptor enc, byte[] payload)
    {
        using var src = new MemoryStream(payload, writable: false);
        using var dst = new MemoryStream();
        enc.EncryptStreamAuth(src, dst, StreamChunkSize);
        return dst.ToArray();
    }

    // ----------------------------------------------------------------
    // UserLoop helpers — Easy Mode plain caller-driven per-chunk loop.
    // Wire framing: 4-byte big-endian ciphertext length prefix per
    // chunk, matching the tmp/csharp.example.md plain-stream framing
    // convention. Empty plaintext terminates the input — payload
    // length 0 is rejected by libitb itself per the empty-data
    // contract; the streaming bench's payload is 64 MiB so the
    // empty-input edge does not arise.
    // ----------------------------------------------------------------

    private static void EncryptUserLoopEasy(Encryptor enc, byte[] payload, Stream output)
    {
        var hdr = new byte[FramingHeaderBytes];
        var off = 0;
        while (off < payload.Length)
        {
            var take = Math.Min(StreamChunkSize, payload.Length - off);
            var chunk = new ReadOnlySpan<byte>(payload, off, take);
            var ct = enc.Encrypt(chunk);
            BinaryPrimitives.WriteUInt32BigEndian(hdr, (uint)ct.Length);
            output.Write(hdr, 0, FramingHeaderBytes);
            output.Write(ct, 0, ct.Length);
            off += take;
        }
    }

    private static void DecryptUserLoopEasy(Encryptor enc, Stream input, Stream output)
    {
        var hdr = new byte[FramingHeaderBytes];
        while (true)
        {
            var read = ReadFully(input, hdr, FramingHeaderBytes);
            if (read == 0)
            {
                return;
            }
            if (read < FramingHeaderBytes)
            {
                throw new InvalidDataException(
                    "user-loop decrypt: truncated chunk header");
            }
            var len = (int)BinaryPrimitives.ReadUInt32BigEndian(hdr);
            var ct = new byte[len];
            var got = ReadFully(input, ct, len);
            if (got != len)
            {
                throw new InvalidDataException(
                    "user-loop decrypt: truncated chunk body");
            }
            var pt = enc.Decrypt(ct);
            output.Write(pt, 0, pt.Length);
        }
    }

    // ----------------------------------------------------------------
    // UserLoop helpers — Low-Level Mode plain caller-driven per-chunk
    // loop. Same 4-byte big-endian length-prefix framing as the Easy
    // path; routes through Cipher.Encrypt / EncryptTriple instead of
    // the Encryptor wrapper.
    // ----------------------------------------------------------------

    private static void EncryptUserLoopLowLevelSingle(
        Seed noise, Seed data, Seed start, byte[] payload, Stream output)
    {
        var hdr = new byte[FramingHeaderBytes];
        var off = 0;
        while (off < payload.Length)
        {
            var take = Math.Min(StreamChunkSize, payload.Length - off);
            var chunk = new ReadOnlySpan<byte>(payload, off, take);
            var ct = Cipher.Encrypt(noise, data, start, chunk);
            BinaryPrimitives.WriteUInt32BigEndian(hdr, (uint)ct.Length);
            output.Write(hdr, 0, FramingHeaderBytes);
            output.Write(ct, 0, ct.Length);
            off += take;
        }
    }

    private static void DecryptUserLoopLowLevelSingle(
        Seed noise, Seed data, Seed start, Stream input, Stream output)
    {
        var hdr = new byte[FramingHeaderBytes];
        while (true)
        {
            var read = ReadFully(input, hdr, FramingHeaderBytes);
            if (read == 0)
            {
                return;
            }
            if (read < FramingHeaderBytes)
            {
                throw new InvalidDataException(
                    "user-loop decrypt: truncated chunk header");
            }
            var len = (int)BinaryPrimitives.ReadUInt32BigEndian(hdr);
            var ct = new byte[len];
            var got = ReadFully(input, ct, len);
            if (got != len)
            {
                throw new InvalidDataException(
                    "user-loop decrypt: truncated chunk body");
            }
            var pt = Cipher.Decrypt(noise, data, start, ct);
            output.Write(pt, 0, pt.Length);
        }
    }

    private static void EncryptUserLoopLowLevelTriple(
        Seed noise, Seed d1, Seed d2, Seed d3, Seed s1, Seed s2, Seed s3,
        byte[] payload, Stream output)
    {
        var hdr = new byte[FramingHeaderBytes];
        var off = 0;
        while (off < payload.Length)
        {
            var take = Math.Min(StreamChunkSize, payload.Length - off);
            var chunk = new ReadOnlySpan<byte>(payload, off, take);
            var ct = Cipher.EncryptTriple(noise, d1, d2, d3, s1, s2, s3, chunk);
            BinaryPrimitives.WriteUInt32BigEndian(hdr, (uint)ct.Length);
            output.Write(hdr, 0, FramingHeaderBytes);
            output.Write(ct, 0, ct.Length);
            off += take;
        }
    }

    private static void DecryptUserLoopLowLevelTriple(
        Seed noise, Seed d1, Seed d2, Seed d3, Seed s1, Seed s2, Seed s3,
        Stream input, Stream output)
    {
        var hdr = new byte[FramingHeaderBytes];
        while (true)
        {
            var read = ReadFully(input, hdr, FramingHeaderBytes);
            if (read == 0)
            {
                return;
            }
            if (read < FramingHeaderBytes)
            {
                throw new InvalidDataException(
                    "user-loop decrypt: truncated chunk header");
            }
            var len = (int)BinaryPrimitives.ReadUInt32BigEndian(hdr);
            var ct = new byte[len];
            var got = ReadFully(input, ct, len);
            if (got != len)
            {
                throw new InvalidDataException(
                    "user-loop decrypt: truncated chunk body");
            }
            var pt = Cipher.DecryptTriple(noise, d1, d2, d3, s1, s2, s3, ct);
            output.Write(pt, 0, pt.Length);
        }
    }

    /// <summary>
    /// Reads exactly <paramref name="count"/> bytes from
    /// <paramref name="input"/> into <paramref name="buffer"/>, looping
    /// past any short reads that <see cref="Stream.Read"/> may return.
    /// Returns the number of bytes actually read; a zero return on the
    /// first read signals end-of-stream.
    /// </summary>
    private static int ReadFully(Stream input, byte[] buffer, int count)
    {
        var total = 0;
        while (total < count)
        {
            var n = input.Read(buffer, total, count - total);
            if (n == 0)
            {
                return total;
            }
            total += n;
        }
        return total;
    }
}
