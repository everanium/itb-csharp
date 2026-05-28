// Format-deniability wrapper benchmarks for the C# binding.
//
// Mirrors the wrapper/bench_test.go cohort: pure wrapper round-trip
// throughput on a 16 MiB random buffer (no ITB call), plus full
// ITB + wrapper round-trip across Message Single / Message Triple /
// Streaming Single / Streaming Triple. Encrypt and decrypt are timed
// separately (sub-bench naming /encrypt and /decrypt) so the per-
// direction breakdown is visible.
//
// Sub-bench inventory (per binding, 102 total):
//
//   Wrapper Only round-trip        : 3 ciphers × {wrap, wrap_in_place} = 6
//   Message Single                 : 3 ciphers × 4 modes × 2 dirs    = 24
//   Message Triple                 : 3 ciphers × 4 modes × 2 dirs    = 24
//   Streaming Single               : 3 ciphers × 4 modes × 2 dirs    = 24
//   Streaming Triple               : 3 ciphers × 4 modes × 2 dirs    = 24
//
// Streaming sub-benches per direction = 4 modes × 3 ciphers × 2 dirs
// = 24 (= half of Go-native's 48 because the C# binding has no
// noaead-*-io variant — see binding asymmetry note in README.md).
// The 4 modes are aead-easy-io / aead-lowlevel-io /
// noaead-easy-userloop / noaead-lowlevel-userloop.
//
// Run with:
//
//     dotnet run --project Itb.Bench -c Release -- wrapper
//
// Filter via ITB_BENCH_FILTER (case-insensitive substring match on
// bench-case names). See Common.cs for the full env-var matrix.

// The bench-side namespace `Itb.Bench.Wrapper` shadows the runtime
// `Itb.Wrapper` namespace, so the wrapper types are reached through
// `global::` aliases below rather than a `using Itb.Wrapper;`
// directive. Extension methods (CipherExtensions.ToFfiName) cannot
// reach the type via a type alias — the `using static` directive on
// the extension class brings the methods into scope by the same
// fully-qualified path.

using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using Itb;
using ItbCipher = Itb.Cipher;
using OuterCipher = global::Itb.Wrapper.Cipher;
using WrapperCore = global::Itb.Wrapper.Wrapper;
using WrapStreamWriter = global::Itb.Wrapper.WrapStreamWriter;
using UnwrapStreamReader = global::Itb.Wrapper.UnwrapStreamReader;
using static Itb.Wrapper.CipherExtensions;

namespace Itb.Bench.Wrapper;

/// <summary>
/// Wrapper bench harness — emits one Go-bench-style line per case.
/// </summary>
internal static class BenchWrapper
{
    private const string Primitive = "areion512";
    private const int SeedWidth = 1024;
    private const string MacName = "hmac-blake3";
    private const int SingleSize = 16 * 1024 * 1024;
    private const int StreamSize = 64 * 1024 * 1024;
    private const int StreamChunk = 16 * 1024 * 1024;

    private const int NonceBits = 128;
    private const int BarrierFill = 1;
    private const int BitSoupOff = 0;
    private const int LockSoupOff = 0;

    private static readonly OuterCipher[] AllCiphers = WrapperCore.AllCiphers;

    private static byte[] RandBytes(int n)
    {
        var buf = new byte[n];
        RandomNumberGenerator.Fill(buf);
        return buf;
    }

    private static byte[] BenchOuterKey(OuterCipher cipher) =>
        WrapperCore.GenerateKey(cipher);

    /// <summary>
    /// Single-Ouroboros Encryptor configured for the wrapper bench
    /// matrix: minimum cipher config so the outer cipher delta is
    /// not masked by per-pixel feature cost.
    /// </summary>
    private static Encryptor BenchEasySingle(bool withMac)
    {
        var enc = withMac
            ? new Encryptor(Primitive, SeedWidth, MacName, "single")
            : new Encryptor(Primitive, SeedWidth, null, "single");
        enc.SetNonceBits(NonceBits);
        enc.SetBarrierFill(BarrierFill);
        enc.SetBitSoup(BitSoupOff);
        enc.SetLockSoup(LockSoupOff);
        return enc;
    }

    private static Encryptor BenchEasyTriple(bool withMac)
    {
        var enc = withMac
            ? new Encryptor(Primitive, SeedWidth, MacName, "triple")
            : new Encryptor(Primitive, SeedWidth, null, "triple");
        enc.SetNonceBits(NonceBits);
        enc.SetBarrierFill(BarrierFill);
        enc.SetBitSoup(BitSoupOff);
        enc.SetLockSoup(LockSoupOff);
        return enc;
    }

    private static Seed[] BenchLowLevelMakeSeeds(int count)
    {
        var seeds = new Seed[count];
        for (var i = 0; i < count; i++)
        {
            seeds[i] = new Seed(Primitive, SeedWidth);
        }
        return seeds;
    }

    // ----------------------------------------------------------------
    // 1. Wrapper Only round-trip (pure outer cipher cost, no ITB call)
    // ----------------------------------------------------------------

    private static IEnumerable<BenchCase> BuildWrapperOnly()
    {
        foreach (var cipher in AllCiphers)
        {
            var key = BenchOuterKey(cipher);
            var blob = RandBytes(SingleSize);

            // wrap: alloc-per-call
            yield return new BenchCase(
                $"BenchmarkWrapperOnly/{cipher.ToFfiName()}/wrap",
                iters =>
                {
                    for (var i = 0L; i < iters; i++)
                    {
                        var wire = WrapperCore.Wrap(cipher, key, blob);
                        var recovered = WrapperCore.Unwrap(cipher, key, wire);
                        // Anti-DCE — read one byte to keep the recovered buffer live.
                        if (recovered.Length == 0) { throw new InvalidOperationException(); }
                    }
                },
                SingleSize);

            // wrap_in_place: no output-buffer allocation on the wrap path
            // (a fresh wire copy is rebuilt per iter so the next wrap has
            // a clean blob).
            var nlen = WrapperCore.NonceSize(cipher);
            yield return new BenchCase(
                $"BenchmarkWrapperOnly/{cipher.ToFfiName()}/wrap_in_place",
                iters =>
                {
                    var wireBuf = new byte[nlen + blob.Length];
                    for (var i = 0L; i < iters; i++)
                    {
                        // Refresh blob copy so each iter starts from
                        // pristine plaintext. The memcpy is part of the
                        // measured cost (mirrors the Go-side bench).
                        Buffer.BlockCopy(blob, 0, wireBuf, nlen, blob.Length);
                        var nonce = WrapperCore.WrapInPlace(cipher, key, wireBuf.AsSpan(nlen));
                        Buffer.BlockCopy(nonce, 0, wireBuf, 0, nlen);
                        // Unwrap-in-place over the same buffer.
                        var recovered = WrapperCore.UnwrapInPlace(cipher, key, wireBuf);
                        if (recovered.Length == 0) { throw new InvalidOperationException(); }
                    }
                },
                SingleSize);
        }
    }

    // ----------------------------------------------------------------
    // 2. Message Single / Triple — full ITB + wrapper, single 16 MiB
    //    plaintext per iter, encrypt and decrypt timed separately.
    // ----------------------------------------------------------------

    private enum MsgMode
    {
        EasyNomac,
        EasyAuth,
        LowLevelNomac,
        LowLevelAuth,
    }

    private static string MsgModeTag(MsgMode mode) => mode switch
    {
        MsgMode.EasyNomac => "easy-nomac",
        MsgMode.EasyAuth => "easy-auth",
        MsgMode.LowLevelNomac => "lowlevel-nomac",
        MsgMode.LowLevelAuth => "lowlevel-auth",
        _ => throw new ArgumentOutOfRangeException(nameof(mode)),
    };

    /// <summary>
    /// Helper that owns a transient seed list (and optional MAC) for
    /// the duration of one Build* call so the BenchCase setup phase
    /// does not leak FFI handles. The bench inner loop closes over a
    /// fresh long-lived encrypt/decrypt context built once before the
    /// measured iterations start.
    /// </summary>
    private sealed class SeedBag : IDisposable
    {
        private readonly Seed[] _seeds;
        private readonly Mac? _mac;
        public SeedBag(Seed[] seeds, Mac? mac) { _seeds = seeds; _mac = mac; }
        public Seed[] Seeds => _seeds;
        public Mac? Mac => _mac;
        public void Dispose()
        {
            foreach (var s in _seeds) { s.Dispose(); }
            _mac?.Dispose();
        }
    }

    private static IEnumerable<BenchCase> BuildMessageSingle()
    {
        var plaintext = RandBytes(SingleSize);
        foreach (var mode in new[] { MsgMode.EasyNomac, MsgMode.EasyAuth, MsgMode.LowLevelNomac, MsgMode.LowLevelAuth })
        {
            foreach (var cipher in AllCiphers)
            {
                var modeTag = MsgModeTag(mode);
                var key = BenchOuterKey(cipher);
                var nlen = WrapperCore.NonceSize(cipher);

                // Encrypt context held for the lifetime of the case.
                IDisposable? ctx = null;
                Func<byte[], byte[]> encryptFn;
                Func<byte[], byte[]> decryptFn;
                BuildSingleEncDec(mode, out ctx, out encryptFn, out decryptFn);

                // Pre-generate a wire for the decrypt sub-bench.
                var initialCt = encryptFn(plaintext);
                var wireBytes = WrapperCore.Wrap(cipher, key, initialCt);

                yield return new BenchCase(
                    $"BenchmarkMessageSingle/{modeTag}/{cipher.ToFfiName()}/encrypt",
                    iters =>
                    {
                        for (var i = 0L; i < iters; i++)
                        {
                            var ct = encryptFn(plaintext);
                            var wire = WrapperCore.Wrap(cipher, key, ct);
                            if (wire.Length == 0) { throw new InvalidOperationException(); }
                        }
                    },
                    SingleSize);

                yield return new BenchCase(
                    $"BenchmarkMessageSingle/{modeTag}/{cipher.ToFfiName()}/decrypt",
                    iters =>
                    {
                        for (var i = 0L; i < iters; i++)
                        {
                            // Refresh wire from a pristine copy so each
                            // iter starts from valid bytes (the unwrap
                            // path mutates if in-place is used; this
                            // bench uses Unwrap which is non-mutating).
                            var ct = WrapperCore.Unwrap(cipher, key, wireBytes);
                            var pt = decryptFn(ct);
                            if (pt.Length == 0) { throw new InvalidOperationException(); }
                        }
                    },
                    SingleSize);
            }
        }
    }

    private static void BuildSingleEncDec(MsgMode mode, out IDisposable? ctx,
        out Func<byte[], byte[]> encryptFn, out Func<byte[], byte[]> decryptFn)
    {
        switch (mode)
        {
            case MsgMode.EasyNomac:
                {
                    var enc = BenchEasySingle(false);
                    ctx = enc;
                    encryptFn = pt => enc.Encrypt(pt);
                    decryptFn = ct => enc.Decrypt(ct);
                    return;
                }
            case MsgMode.EasyAuth:
                {
                    var enc = BenchEasySingle(true);
                    ctx = enc;
                    encryptFn = pt => enc.EncryptAuth(pt);
                    decryptFn = ct => enc.DecryptAuth(ct);
                    return;
                }
            case MsgMode.LowLevelNomac:
                {
                    var seeds = BenchLowLevelMakeSeeds(3);
                    var bag = new SeedBag(seeds, null);
                    ctx = bag;
                    encryptFn = pt => ItbCipher.Encrypt(seeds[0], seeds[1], seeds[2], pt);
                    decryptFn = ct => ItbCipher.Decrypt(seeds[0], seeds[1], seeds[2], ct);
                    return;
                }
            case MsgMode.LowLevelAuth:
                {
                    var seeds = BenchLowLevelMakeSeeds(3);
                    var mac = new Mac(MacName, RandBytes(32));
                    var bag = new SeedBag(seeds, mac);
                    ctx = bag;
                    encryptFn = pt => ItbCipher.EncryptAuth(seeds[0], seeds[1], seeds[2], mac, pt);
                    decryptFn = ct => ItbCipher.DecryptAuth(seeds[0], seeds[1], seeds[2], mac, ct);
                    return;
                }
            default:
                throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    private static void BuildTripleEncDec(MsgMode mode, out IDisposable? ctx,
        out Func<byte[], byte[]> encryptFn, out Func<byte[], byte[]> decryptFn)
    {
        switch (mode)
        {
            case MsgMode.EasyNomac:
                {
                    var enc = BenchEasyTriple(false);
                    ctx = enc;
                    encryptFn = pt => enc.Encrypt(pt);
                    decryptFn = ct => enc.Decrypt(ct);
                    return;
                }
            case MsgMode.EasyAuth:
                {
                    var enc = BenchEasyTriple(true);
                    ctx = enc;
                    encryptFn = pt => enc.EncryptAuth(pt);
                    decryptFn = ct => enc.DecryptAuth(ct);
                    return;
                }
            case MsgMode.LowLevelNomac:
                {
                    var seeds = BenchLowLevelMakeSeeds(7);
                    var bag = new SeedBag(seeds, null);
                    ctx = bag;
                    encryptFn = pt => ItbCipher.EncryptTriple(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], pt);
                    decryptFn = ct => ItbCipher.DecryptTriple(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], ct);
                    return;
                }
            case MsgMode.LowLevelAuth:
                {
                    var seeds = BenchLowLevelMakeSeeds(7);
                    var mac = new Mac(MacName, RandBytes(32));
                    var bag = new SeedBag(seeds, mac);
                    ctx = bag;
                    encryptFn = pt => ItbCipher.EncryptAuthTriple(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], mac, pt);
                    decryptFn = ct => ItbCipher.DecryptAuthTriple(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], mac, ct);
                    return;
                }
            default:
                throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    private static IEnumerable<BenchCase> BuildMessageTriple()
    {
        var plaintext = RandBytes(SingleSize);
        foreach (var mode in new[] { MsgMode.EasyNomac, MsgMode.EasyAuth, MsgMode.LowLevelNomac, MsgMode.LowLevelAuth })
        {
            foreach (var cipher in AllCiphers)
            {
                var modeTag = MsgModeTag(mode);
                var key = BenchOuterKey(cipher);

                BuildTripleEncDec(mode, out var ctx, out var encryptFn, out var decryptFn);

                var initialCt = encryptFn(plaintext);
                var wireBytes = WrapperCore.Wrap(cipher, key, initialCt);

                yield return new BenchCase(
                    $"BenchmarkMessageTriple/{modeTag}/{cipher.ToFfiName()}/encrypt",
                    iters =>
                    {
                        for (var i = 0L; i < iters; i++)
                        {
                            var ct = encryptFn(plaintext);
                            var wire = WrapperCore.Wrap(cipher, key, ct);
                            if (wire.Length == 0) { throw new InvalidOperationException(); }
                        }
                    },
                    SingleSize);

                yield return new BenchCase(
                    $"BenchmarkMessageTriple/{modeTag}/{cipher.ToFfiName()}/decrypt",
                    iters =>
                    {
                        for (var i = 0L; i < iters; i++)
                        {
                            var ct = WrapperCore.Unwrap(cipher, key, wireBytes);
                            var pt = decryptFn(ct);
                            if (pt.Length == 0) { throw new InvalidOperationException(); }
                        }
                    },
                    SingleSize);
            }
        }
    }

    // ----------------------------------------------------------------
    // 3. Streaming Single / Triple — 64 MiB plaintext, 16 MiB chunks.
    //    4 modes: aead-easy-io, aead-lowlevel-io,
    //    noaead-easy-userloop, noaead-lowlevel-userloop. The two
    //    noaead-*-io variants present in the Go-native bench are
    //    ABSENT here by binding asymmetry — Non-AEAD streaming has no
    //    file-like writer / reader pair in the C# binding.
    // ----------------------------------------------------------------

    private enum StreamMode
    {
        AeadEasyIo,
        AeadLowLevelIo,
        NoaeadEasyUserloop,
        NoaeadLowLevelUserloop,
    }

    private static string StreamModeTag(StreamMode mode) => mode switch
    {
        StreamMode.AeadEasyIo => "aead-easy-io",
        StreamMode.AeadLowLevelIo => "aead-lowlevel-io",
        StreamMode.NoaeadEasyUserloop => "noaead-easy-userloop",
        StreamMode.NoaeadLowLevelUserloop => "noaead-lowlevel-userloop",
        _ => throw new ArgumentOutOfRangeException(nameof(mode)),
    };

    /// <summary>
    /// Streaming bench cases for one mode (Single or Triple). Each
    /// (mode, cipher) pair emits two sub-benches (encrypt + decrypt).
    /// </summary>
    private static IEnumerable<BenchCase> BuildStreamingFor(bool triple)
    {
        var plaintext = RandBytes(StreamSize);
        var benchKindTag = triple ? "BenchmarkStreamingTriple" : "BenchmarkStreamingSingle";
        foreach (var mode in new[] { StreamMode.AeadEasyIo, StreamMode.AeadLowLevelIo, StreamMode.NoaeadEasyUserloop, StreamMode.NoaeadLowLevelUserloop })
        {
            foreach (var cipher in AllCiphers)
            {
                var modeTag = StreamModeTag(mode);
                var key = BenchOuterKey(cipher);

                Func<byte[], byte[]> encryptFn;
                Func<byte[], byte[]> decryptFn;

                switch (mode)
                {
                    case StreamMode.AeadEasyIo:
                        {
                            var enc = triple ? BenchEasyTriple(true) : BenchEasySingle(true);
                            encryptFn = pt =>
                            {
                                using var inner = new MemoryStream();
                                enc.EncryptStreamAuth(new MemoryStream(pt), inner, StreamChunk);
                                var innerBytes = inner.ToArray();
                                using var ww = new WrapStreamWriter(cipher, key);
                                var nonce = ww.Nonce;
                                var body = ww.Update(innerBytes);
                                var wire = new byte[nonce.Length + body.Length];
                                Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
                                Buffer.BlockCopy(body, 0, wire, nonce.Length, body.Length);
                                return wire;
                            };
                            decryptFn = wire =>
                            {
                                var nlen = WrapperCore.NonceSize(cipher);
                                using var ur = new UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
                                var innerWire = ur.Update(wire.AsSpan(nlen));
                                using var outBuf = new MemoryStream();
                                enc.DecryptStreamAuth(new MemoryStream(innerWire), outBuf);
                                return outBuf.ToArray();
                            };
                            break;
                        }
                    case StreamMode.AeadLowLevelIo:
                        {
                            var seedCount = triple ? 7 : 3;
                            var seeds = BenchLowLevelMakeSeeds(seedCount);
                            var mac = new Mac(MacName, RandBytes(32));
                            encryptFn = pt =>
                            {
                                using var inner = new MemoryStream();
                                if (triple)
                                {
                                    StreamPipeline.EncryptStreamAuthTriple(
                                        seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], mac,
                                        new MemoryStream(pt), inner, StreamChunk);
                                }
                                else
                                {
                                    StreamPipeline.EncryptStreamAuth(seeds[0], seeds[1], seeds[2], mac,
                                        new MemoryStream(pt), inner, StreamChunk);
                                }
                                var innerBytes = inner.ToArray();
                                using var ww = new WrapStreamWriter(cipher, key);
                                var nonce = ww.Nonce;
                                var body = ww.Update(innerBytes);
                                var wire = new byte[nonce.Length + body.Length];
                                Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
                                Buffer.BlockCopy(body, 0, wire, nonce.Length, body.Length);
                                return wire;
                            };
                            decryptFn = wire =>
                            {
                                var nlen = WrapperCore.NonceSize(cipher);
                                using var ur = new UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
                                var innerWire = ur.Update(wire.AsSpan(nlen));
                                using var outBuf = new MemoryStream();
                                if (triple)
                                {
                                    StreamPipeline.DecryptStreamAuthTriple(
                                        seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], mac,
                                        new MemoryStream(innerWire), outBuf);
                                }
                                else
                                {
                                    StreamPipeline.DecryptStreamAuth(seeds[0], seeds[1], seeds[2], mac,
                                        new MemoryStream(innerWire), outBuf);
                                }
                                return outBuf.ToArray();
                            };
                            break;
                        }
                    case StreamMode.NoaeadEasyUserloop:
                        {
                            var enc = triple ? BenchEasyTriple(false) : BenchEasySingle(false);
                            encryptFn = pt =>
                            {
                                using var ww = new WrapStreamWriter(cipher, key);
                                using var wireBuf = new MemoryStream();
                                wireBuf.Write(ww.Nonce);
                                var off = 0;
                                while (off < pt.Length)
                                {
                                    var take = Math.Min(StreamChunk, pt.Length - off);
                                    var ct = enc.Encrypt(pt.AsSpan(off, take));
                                    wireBuf.Write(ww.Update(BitConverter.GetBytes((uint)ct.Length)));
                                    wireBuf.Write(ww.Update(ct));
                                    off += take;
                                }
                                return wireBuf.ToArray();
                            };
                            decryptFn = wire =>
                            {
                                var nlen = WrapperCore.NonceSize(cipher);
                                using var ur = new UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
                                var decrypted = ur.Update(wire.AsSpan(nlen));
                                using var outBuf = new MemoryStream();
                                var pos = 0;
                                while (pos < decrypted.Length)
                                {
                                    var clen = (int)BitConverter.ToUInt32(decrypted, pos);
                                    pos += 4;
                                    var pt = enc.Decrypt(decrypted.AsSpan(pos, clen));
                                    outBuf.Write(pt);
                                    pos += clen;
                                }
                                return outBuf.ToArray();
                            };
                            break;
                        }
                    case StreamMode.NoaeadLowLevelUserloop:
                        {
                            var seedCount = triple ? 7 : 3;
                            var seeds = BenchLowLevelMakeSeeds(seedCount);
                            encryptFn = pt =>
                            {
                                using var ww = new WrapStreamWriter(cipher, key);
                                using var wireBuf = new MemoryStream();
                                wireBuf.Write(ww.Nonce);
                                var off = 0;
                                while (off < pt.Length)
                                {
                                    var take = Math.Min(StreamChunk, pt.Length - off);
                                    byte[] ct = triple
                                        ? ItbCipher.EncryptTriple(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], pt.AsSpan(off, take))
                                        : ItbCipher.Encrypt(seeds[0], seeds[1], seeds[2], pt.AsSpan(off, take));
                                    wireBuf.Write(ww.Update(BitConverter.GetBytes((uint)ct.Length)));
                                    wireBuf.Write(ww.Update(ct));
                                    off += take;
                                }
                                return wireBuf.ToArray();
                            };
                            decryptFn = wire =>
                            {
                                var nlen = WrapperCore.NonceSize(cipher);
                                using var ur = new UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
                                var decrypted = ur.Update(wire.AsSpan(nlen));
                                using var outBuf = new MemoryStream();
                                var pos = 0;
                                while (pos < decrypted.Length)
                                {
                                    var clen = (int)BitConverter.ToUInt32(decrypted, pos);
                                    pos += 4;
                                    byte[] ptChunk = triple
                                        ? ItbCipher.DecryptTriple(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], decrypted.AsSpan(pos, clen))
                                        : ItbCipher.Decrypt(seeds[0], seeds[1], seeds[2], decrypted.AsSpan(pos, clen));
                                    outBuf.Write(ptChunk);
                                    pos += clen;
                                }
                                return outBuf.ToArray();
                            };
                            break;
                        }
                    default:
                        throw new ArgumentOutOfRangeException(nameof(mode));
                }

                // Pre-generate one wire so the decrypt sub-bench has
                // something to feed (mirrors Go-native bench shape).
                var initialWire = encryptFn(plaintext);

                yield return new BenchCase(
                    $"{benchKindTag}/{modeTag}/{cipher.ToFfiName()}/encrypt",
                    iters =>
                    {
                        for (var i = 0L; i < iters; i++)
                        {
                            var w = encryptFn(plaintext);
                            if (w.Length == 0) { throw new InvalidOperationException(); }
                        }
                    },
                    StreamSize);

                yield return new BenchCase(
                    $"{benchKindTag}/{modeTag}/{cipher.ToFfiName()}/decrypt",
                    iters =>
                    {
                        for (var i = 0L; i < iters; i++)
                        {
                            var pt = decryptFn(initialWire);
                            if (pt.Length == 0) { throw new InvalidOperationException(); }
                        }
                    },
                    StreamSize);
            }
        }
    }

    // ----------------------------------------------------------------
    // Lazy case factory list — one (name, factory) pair per sub-bench.
    // Each factory allocates payload + context only when called, so
    // peak RSS is bounded to roughly one case at a time.
    // ----------------------------------------------------------------

    private static List<(string Name, Func<BenchCase> Factory)> BuildLazyCases()
    {
        var lazy = new List<(string, Func<BenchCase>)>(306);

        // Wrapper Only — every cipher × 2 shapes (alloc + in-place).
        foreach (var cipher in AllCiphers)
        {
            var c = cipher; // capture
            lazy.Add(($"BenchmarkWrapperOnly/{c.ToFfiName()}/wrap",
                () =>
                {
                    var key = BenchOuterKey(c);
                    var blob = RandBytes(SingleSize);
                    return new BenchCase(
                        $"BenchmarkWrapperOnly/{c.ToFfiName()}/wrap",
                        iters =>
                        {
                            for (var i = 0L; i < iters; i++)
                            {
                                var wire = WrapperCore.Wrap(c, key, blob);
                                var recovered = WrapperCore.Unwrap(c, key, wire);
                                if (recovered.Length == 0) throw new InvalidOperationException();
                            }
                        }, SingleSize);
                }));
            var nlen = WrapperCore.NonceSize(c);
            lazy.Add(($"BenchmarkWrapperOnly/{c.ToFfiName()}/wrap_in_place",
                () =>
                {
                    var key2 = BenchOuterKey(c);
                    var blob2 = RandBytes(SingleSize);
                    return new BenchCase(
                        $"BenchmarkWrapperOnly/{c.ToFfiName()}/wrap_in_place",
                        iters =>
                        {
                            var wireBuf = new byte[nlen + blob2.Length];
                            for (var i = 0L; i < iters; i++)
                            {
                                Buffer.BlockCopy(blob2, 0, wireBuf, nlen, blob2.Length);
                                var nonce = WrapperCore.WrapInPlace(c, key2, wireBuf.AsSpan(nlen));
                                Buffer.BlockCopy(nonce, 0, wireBuf, 0, nlen);
                                var recovered = WrapperCore.UnwrapInPlace(c, key2, wireBuf);
                                if (recovered.Length == 0) throw new InvalidOperationException();
                            }
                        }, SingleSize);
                }));
        }

        // Message Single and Triple — 4 modes × every cipher × 2 dirs × 2 ouroboros.
        foreach (var mode in new[] { MsgMode.EasyNomac, MsgMode.EasyAuth, MsgMode.LowLevelNomac, MsgMode.LowLevelAuth })
        {
            foreach (var triple in new[] { false, true })
            {
                foreach (var cipher in AllCiphers)
                {
                    var c = cipher;
                    var m = mode;
                    var t = triple;
                    var tag = triple ? "BenchmarkMessageTriple" : "BenchmarkMessageSingle";
                    var modeTag = MsgModeTag(m);

                    lazy.Add(($"{tag}/{modeTag}/{c.ToFfiName()}/encrypt",
                        () =>
                        {
                            var key = BenchOuterKey(c);
                            var plaintext = RandBytes(SingleSize);
                            IDisposable? ctx = null;
                            Func<byte[], byte[]> encFn;
                            Func<byte[], byte[]> decFn;
                            if (t) BuildTripleEncDec(m, out ctx, out encFn, out decFn);
                            else BuildSingleEncDec(m, out ctx, out encFn, out decFn);
                            _ = ctx;
                            return new BenchCase(
                                $"{tag}/{modeTag}/{c.ToFfiName()}/encrypt",
                                iters =>
                                {
                                    for (var i = 0L; i < iters; i++)
                                    {
                                        var ct = encFn(plaintext);
                                        var wire = WrapperCore.Wrap(c, key, ct);
                                        if (wire.Length == 0) throw new InvalidOperationException();
                                    }
                                }, SingleSize);
                        }));

                    lazy.Add(($"{tag}/{modeTag}/{c.ToFfiName()}/decrypt",
                        () =>
                        {
                            var key = BenchOuterKey(c);
                            var plaintext = RandBytes(SingleSize);
                            IDisposable? ctx = null;
                            Func<byte[], byte[]> encFn;
                            Func<byte[], byte[]> decFn;
                            if (t) BuildTripleEncDec(m, out ctx, out encFn, out decFn);
                            else BuildSingleEncDec(m, out ctx, out encFn, out decFn);
                            _ = ctx;
                            var initialCt = encFn(plaintext);
                            var wireBytes = WrapperCore.Wrap(c, key, initialCt);
                            return new BenchCase(
                                $"{tag}/{modeTag}/{c.ToFfiName()}/decrypt",
                                iters =>
                                {
                                    for (var i = 0L; i < iters; i++)
                                    {
                                        var ct = WrapperCore.Unwrap(c, key, wireBytes);
                                        var pt = decFn(ct);
                                        if (pt.Length == 0) throw new InvalidOperationException();
                                    }
                                }, SingleSize);
                        }));
                }
            }
        }

        // Streaming Single and Triple — 4 modes × every cipher × 2 dirs × 2 ouroboros.
        foreach (var mode in new[] { StreamMode.AeadEasyIo, StreamMode.AeadLowLevelIo, StreamMode.NoaeadEasyUserloop, StreamMode.NoaeadLowLevelUserloop })
        {
            foreach (var triple in new[] { false, true })
            {
                foreach (var cipher in AllCiphers)
                {
                    var c = cipher;
                    var sm = mode;
                    var t = triple;
                    var tag = triple ? "BenchmarkStreamingTriple" : "BenchmarkStreamingSingle";
                    var modeTag = StreamModeTag(sm);

                    lazy.Add(($"{tag}/{modeTag}/{c.ToFfiName()}/encrypt",
                        () =>
                        {
                            // BuildStreamingFor sets up encryptFn/decryptFn using
                            // closures over enc/seeds; we replicate that inline here.
                            var key = BenchOuterKey(c);
                            var plaintext = RandBytes(StreamSize);
                            Func<byte[], byte[]> encFn = BuildStreamingEncryptFn(c, key, sm, t);
                            return new BenchCase(
                                $"{tag}/{modeTag}/{c.ToFfiName()}/encrypt",
                                iters =>
                                {
                                    for (var i = 0L; i < iters; i++)
                                    {
                                        var w = encFn(plaintext);
                                        if (w.Length == 0) throw new InvalidOperationException();
                                    }
                                }, StreamSize);
                        }));

                    lazy.Add(($"{tag}/{modeTag}/{c.ToFfiName()}/decrypt",
                        () =>
                        {
                            var key = BenchOuterKey(c);
                            var plaintext = RandBytes(StreamSize);
                            var (encFn, decFn) = BuildStreamingPair(c, key, sm, t);
                            var initialWire = encFn(plaintext);
                            return new BenchCase(
                                $"{tag}/{modeTag}/{c.ToFfiName()}/decrypt",
                                iters =>
                                {
                                    for (var i = 0L; i < iters; i++)
                                    {
                                        var pt = decFn(initialWire);
                                        if (pt.Length == 0) throw new InvalidOperationException();
                                    }
                                }, StreamSize);
                        }));
                }
            }
        }

        return lazy;
    }

    // Helper: build a matched (encFn, decFn) pair sharing the SAME ITB keying
    // material so that initialWire = encFn(pt) can be correctly fed into decFn.
    private static (Func<byte[], byte[]> encFn, Func<byte[], byte[]> decFn) BuildStreamingPair(
        OuterCipher cipher, byte[] key, StreamMode mode, bool triple)
    {
        switch (mode)
        {
            case StreamMode.AeadEasyIo:
            {
                var enc = triple ? BenchEasyTriple(true) : BenchEasySingle(true);
                Func<byte[], byte[]> encFn = pt =>
                {
                    using var inner = new MemoryStream();
                    enc.EncryptStreamAuth(new MemoryStream(pt), inner, StreamChunk);
                    var innerBytes = inner.ToArray();
                    using var ww = new WrapStreamWriter(cipher, key);
                    var nonce = ww.Nonce;
                    var body = ww.Update(innerBytes);
                    var wire = new byte[nonce.Length + body.Length];
                    Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
                    Buffer.BlockCopy(body, 0, wire, nonce.Length, body.Length);
                    return wire;
                };
                Func<byte[], byte[]> decFn = wire =>
                {
                    var nlen = WrapperCore.NonceSize(cipher);
                    using var ur = new UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
                    var innerWire = ur.Update(wire.AsSpan(nlen));
                    using var outBuf = new MemoryStream();
                    enc.DecryptStreamAuth(new MemoryStream(innerWire), outBuf);
                    return outBuf.ToArray();
                };
                return (encFn, decFn);
            }
            case StreamMode.AeadLowLevelIo:
            {
                var seedCount = triple ? 7 : 3;
                var seeds = BenchLowLevelMakeSeeds(seedCount);
                var mac = new Mac(MacName, RandBytes(32));
                Func<byte[], byte[]> encFn = pt =>
                {
                    using var inner = new MemoryStream();
                    if (triple)
                        StreamPipeline.EncryptStreamAuthTriple(
                            seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], mac,
                            new MemoryStream(pt), inner, StreamChunk);
                    else
                        StreamPipeline.EncryptStreamAuth(seeds[0], seeds[1], seeds[2], mac,
                            new MemoryStream(pt), inner, StreamChunk);
                    var innerBytes = inner.ToArray();
                    using var ww = new WrapStreamWriter(cipher, key);
                    var nonce = ww.Nonce;
                    var body = ww.Update(innerBytes);
                    var wire = new byte[nonce.Length + body.Length];
                    Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
                    Buffer.BlockCopy(body, 0, wire, nonce.Length, body.Length);
                    return wire;
                };
                Func<byte[], byte[]> decFn = wire =>
                {
                    var nlen = WrapperCore.NonceSize(cipher);
                    using var ur = new UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
                    var innerWire = ur.Update(wire.AsSpan(nlen));
                    using var outBuf = new MemoryStream();
                    if (triple)
                        StreamPipeline.DecryptStreamAuthTriple(
                            seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], mac,
                            new MemoryStream(innerWire), outBuf);
                    else
                        StreamPipeline.DecryptStreamAuth(seeds[0], seeds[1], seeds[2], mac,
                            new MemoryStream(innerWire), outBuf);
                    return outBuf.ToArray();
                };
                return (encFn, decFn);
            }
            case StreamMode.NoaeadEasyUserloop:
            {
                var enc = triple ? BenchEasyTriple(false) : BenchEasySingle(false);
                Func<byte[], byte[]> encFn = pt =>
                {
                    using var ww = new WrapStreamWriter(cipher, key);
                    using var wireBuf = new MemoryStream();
                    wireBuf.Write(ww.Nonce);
                    var off = 0;
                    while (off < pt.Length)
                    {
                        var take = Math.Min(StreamChunk, pt.Length - off);
                        var ct = enc.Encrypt(pt.AsSpan(off, take));
                        wireBuf.Write(ww.Update(BitConverter.GetBytes((uint)ct.Length)));
                        wireBuf.Write(ww.Update(ct));
                        off += take;
                    }
                    return wireBuf.ToArray();
                };
                Func<byte[], byte[]> decFn = wire =>
                {
                    var nlen = WrapperCore.NonceSize(cipher);
                    using var ur = new UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
                    var decrypted = ur.Update(wire.AsSpan(nlen));
                    using var outBuf = new MemoryStream();
                    var pos = 0;
                    while (pos < decrypted.Length)
                    {
                        var clen = (int)BitConverter.ToUInt32(decrypted, pos);
                        pos += 4;
                        var pt = enc.Decrypt(decrypted.AsSpan(pos, clen));
                        outBuf.Write(pt);
                        pos += clen;
                    }
                    return outBuf.ToArray();
                };
                return (encFn, decFn);
            }
            case StreamMode.NoaeadLowLevelUserloop:
            {
                var seedCount = triple ? 7 : 3;
                var seeds = BenchLowLevelMakeSeeds(seedCount);
                Func<byte[], byte[]> encFn = pt =>
                {
                    using var ww = new WrapStreamWriter(cipher, key);
                    using var wireBuf = new MemoryStream();
                    wireBuf.Write(ww.Nonce);
                    var off = 0;
                    while (off < pt.Length)
                    {
                        var take = Math.Min(StreamChunk, pt.Length - off);
                        byte[] ct = triple
                            ? ItbCipher.EncryptTriple(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], pt.AsSpan(off, take))
                            : ItbCipher.Encrypt(seeds[0], seeds[1], seeds[2], pt.AsSpan(off, take));
                        wireBuf.Write(ww.Update(BitConverter.GetBytes((uint)ct.Length)));
                        wireBuf.Write(ww.Update(ct));
                        off += take;
                    }
                    return wireBuf.ToArray();
                };
                Func<byte[], byte[]> decFn = wire =>
                {
                    var nlen = WrapperCore.NonceSize(cipher);
                    using var ur = new UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
                    var decrypted = ur.Update(wire.AsSpan(nlen));
                    using var outBuf = new MemoryStream();
                    var pos = 0;
                    while (pos < decrypted.Length)
                    {
                        var clen = (int)BitConverter.ToUInt32(decrypted, pos);
                        pos += 4;
                        byte[] ptChunk = triple
                            ? ItbCipher.DecryptTriple(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], decrypted.AsSpan(pos, clen))
                            : ItbCipher.Decrypt(seeds[0], seeds[1], seeds[2], decrypted.AsSpan(pos, clen));
                        outBuf.Write(ptChunk);
                        pos += clen;
                    }
                    return outBuf.ToArray();
                };
                return (encFn, decFn);
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    // Helper: build a streaming encrypt function for (cipher, key, streamMode, triple).
    private static Func<byte[], byte[]> BuildStreamingEncryptFn(
        OuterCipher cipher, byte[] key, StreamMode mode, bool triple)
    {
        switch (mode)
        {
            case StreamMode.AeadEasyIo:
            {
                var enc = triple ? BenchEasyTriple(true) : BenchEasySingle(true);
                return pt =>
                {
                    using var inner = new MemoryStream();
                    enc.EncryptStreamAuth(new MemoryStream(pt), inner, StreamChunk);
                    var innerBytes = inner.ToArray();
                    using var ww = new WrapStreamWriter(cipher, key);
                    var nonce = ww.Nonce;
                    var body = ww.Update(innerBytes);
                    var wire = new byte[nonce.Length + body.Length];
                    Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
                    Buffer.BlockCopy(body, 0, wire, nonce.Length, body.Length);
                    return wire;
                };
            }
            case StreamMode.AeadLowLevelIo:
            {
                var seedCount = triple ? 7 : 3;
                var seeds = BenchLowLevelMakeSeeds(seedCount);
                var mac = new Mac(MacName, RandBytes(32));
                return pt =>
                {
                    using var inner = new MemoryStream();
                    if (triple)
                        StreamPipeline.EncryptStreamAuthTriple(
                            seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], mac,
                            new MemoryStream(pt), inner, StreamChunk);
                    else
                        StreamPipeline.EncryptStreamAuth(seeds[0], seeds[1], seeds[2], mac,
                            new MemoryStream(pt), inner, StreamChunk);
                    var innerBytes = inner.ToArray();
                    using var ww = new WrapStreamWriter(cipher, key);
                    var nonce = ww.Nonce;
                    var body = ww.Update(innerBytes);
                    var wire = new byte[nonce.Length + body.Length];
                    Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
                    Buffer.BlockCopy(body, 0, wire, nonce.Length, body.Length);
                    return wire;
                };
            }
            case StreamMode.NoaeadEasyUserloop:
            {
                var enc = triple ? BenchEasyTriple(false) : BenchEasySingle(false);
                return pt =>
                {
                    using var ww = new WrapStreamWriter(cipher, key);
                    using var wireBuf = new MemoryStream();
                    wireBuf.Write(ww.Nonce);
                    var off = 0;
                    while (off < pt.Length)
                    {
                        var take = Math.Min(StreamChunk, pt.Length - off);
                        var ct = enc.Encrypt(pt.AsSpan(off, take));
                        wireBuf.Write(ww.Update(BitConverter.GetBytes((uint)ct.Length)));
                        wireBuf.Write(ww.Update(ct));
                        off += take;
                    }
                    return wireBuf.ToArray();
                };
            }
            case StreamMode.NoaeadLowLevelUserloop:
            {
                var seedCount = triple ? 7 : 3;
                var seeds = BenchLowLevelMakeSeeds(seedCount);
                return pt =>
                {
                    using var ww = new WrapStreamWriter(cipher, key);
                    using var wireBuf = new MemoryStream();
                    wireBuf.Write(ww.Nonce);
                    var off = 0;
                    while (off < pt.Length)
                    {
                        var take = Math.Min(StreamChunk, pt.Length - off);
                        byte[] ct = triple
                            ? ItbCipher.EncryptTriple(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], pt.AsSpan(off, take))
                            : ItbCipher.Encrypt(seeds[0], seeds[1], seeds[2], pt.AsSpan(off, take));
                        wireBuf.Write(ww.Update(BitConverter.GetBytes((uint)ct.Length)));
                        wireBuf.Write(ww.Update(ct));
                        off += take;
                    }
                    return wireBuf.ToArray();
                };
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    // Helper: build a streaming decrypt function for (cipher, key, streamMode, triple).
    private static Func<byte[], byte[]> BuildStreamingDecryptFn(
        OuterCipher cipher, byte[] key, StreamMode mode, bool triple)
    {
        switch (mode)
        {
            case StreamMode.AeadEasyIo:
            {
                var enc = triple ? BenchEasyTriple(true) : BenchEasySingle(true);
                return wire =>
                {
                    var nlen = WrapperCore.NonceSize(cipher);
                    using var ur = new UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
                    var innerWire = ur.Update(wire.AsSpan(nlen));
                    using var outBuf = new MemoryStream();
                    enc.DecryptStreamAuth(new MemoryStream(innerWire), outBuf);
                    return outBuf.ToArray();
                };
            }
            case StreamMode.AeadLowLevelIo:
            {
                var seedCount = triple ? 7 : 3;
                var seeds = BenchLowLevelMakeSeeds(seedCount);
                var mac = new Mac(MacName, RandBytes(32));
                return wire =>
                {
                    var nlen = WrapperCore.NonceSize(cipher);
                    using var ur = new UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
                    var innerWire = ur.Update(wire.AsSpan(nlen));
                    using var outBuf = new MemoryStream();
                    if (triple)
                        StreamPipeline.DecryptStreamAuthTriple(
                            seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], mac,
                            new MemoryStream(innerWire), outBuf);
                    else
                        StreamPipeline.DecryptStreamAuth(seeds[0], seeds[1], seeds[2], mac,
                            new MemoryStream(innerWire), outBuf);
                    return outBuf.ToArray();
                };
            }
            case StreamMode.NoaeadEasyUserloop:
            {
                var enc = triple ? BenchEasyTriple(false) : BenchEasySingle(false);
                return wire =>
                {
                    var nlen = WrapperCore.NonceSize(cipher);
                    using var ur = new UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
                    var decrypted = ur.Update(wire.AsSpan(nlen));
                    using var outBuf = new MemoryStream();
                    var pos = 0;
                    while (pos < decrypted.Length)
                    {
                        var clen = (int)BitConverter.ToUInt32(decrypted, pos);
                        pos += 4;
                        var pt = enc.Decrypt(decrypted.AsSpan(pos, clen));
                        outBuf.Write(pt);
                        pos += clen;
                    }
                    return outBuf.ToArray();
                };
            }
            case StreamMode.NoaeadLowLevelUserloop:
            {
                var seedCount = triple ? 7 : 3;
                var seeds = BenchLowLevelMakeSeeds(seedCount);
                return wire =>
                {
                    var nlen = WrapperCore.NonceSize(cipher);
                    using var ur = new UnwrapStreamReader(cipher, key, wire.AsSpan(0, nlen));
                    var decrypted = ur.Update(wire.AsSpan(nlen));
                    using var outBuf = new MemoryStream();
                    var pos = 0;
                    while (pos < decrypted.Length)
                    {
                        var clen = (int)BitConverter.ToUInt32(decrypted, pos);
                        pos += 4;
                        byte[] ptChunk = triple
                            ? ItbCipher.DecryptTriple(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], decrypted.AsSpan(pos, clen))
                            : ItbCipher.Decrypt(seeds[0], seeds[1], seeds[2], decrypted.AsSpan(pos, clen));
                        outBuf.Write(ptChunk);
                        pos += clen;
                    }
                    return outBuf.ToArray();
                };
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    /// <summary>
    /// Bench entry point invoked by <see cref="Itb.Bench.Program"/>.
    /// </summary>
    public static void Run()
    {
        Library.MaxWorkers = 0;
        Library.NonceBits = NonceBits;
        Library.BarrierFill = BarrierFill;
        Library.BitSoup = BitSoupOff;
        Library.LockSoup = LockSoupOff;

        var lazyCases = BuildLazyCases();
        Console.WriteLine(string.Format(
            CultureInfo.InvariantCulture,
            "# wrapper primitive={0} key_bits={1} mac={2} nonce_bits={3} barrier_fill={4} bit_soup={5} lock_soup={6} workers=auto cases={7}",
            Primitive, SeedWidth, MacName, NonceBits, BarrierFill, BitSoupOff, LockSoupOff, lazyCases.Count));
        Console.Out.Flush();

        Common.RunLazy(lazyCases);
    }
}
