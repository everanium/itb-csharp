# ITB C# / .NET Binding

Source-generated `[LibraryImport]` wrapper over the libitb shared
library (`cmd/cshared`). Runtime FFI — no C compiler at install
time, no compile-time link against libitb; the `.so` / `.dll` /
`.dylib` is resolved and dispatched at first use through
`NativeLibrary.SetDllImportResolver`.

**Path placeholder.** `<itb>` denotes the path to the local ITB
repository checkout (or this binding's mirror clone) — for example,
`/home/you/go/src/itb` or `~/projects/itb-csharp`. Substitute the
literal token in the recipes below.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go go-tools dotnet-sdk dotnet-runtime aspnet-runtime
```

## Build the shared library

The convenience driver `bindings/csharp/build.sh` builds
`libitb.so` plus the C# / .NET binding's release assemblies in one
step. Run it from anywhere:

```bash
./bindings/csharp/build.sh
```

The driver expands to two underlying steps — building libitb from
the repo root, then `dotnet build -c Release` on the binding side.
Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/csharp && dotnet build -c Release
```

(macOS produces `libitb.dylib` under `dist/darwin-<arch>/`,
Windows produces `libitb.dll` under `dist/windows-<arch>/`.)

## Add to a .NET project

The library is published as `Itb` targeting `net10.0`. As a
project reference from inside this repository:

```xml
<ItemGroup>
  <ProjectReference Include="bindings/csharp/Itb/Itb.csproj" />
</ItemGroup>
```

Build once before running tests:

```bash
cd bindings/csharp
dotnet build -c Release
```

Project metadata: `AssemblyName = "Itb"`, `Version = 0.1.0`,
`TargetFramework = net10.0`, `LangVersion = latest`,
`AllowUnsafeBlocks = true`, `License = MIT`. The runtime
dependency is the .NET base library only — no NuGet package is
introduced (`[LibraryImport]` and `NativeLibrary` are built-ins).

## Library lookup order

1. `ITB_LIBRARY_PATH` environment variable (absolute path).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved by walking up
   from the assembly directory (`bindings/csharp/Itb/bin/<config>/<tfm>/`)
   until a matching `dist/` folder is found.
3. System loader path (`ld.so.cache`, `DYLD_LIBRARY_PATH`, `PATH`).

## Memory

Two process-wide knobs constrain Go runtime arena pacing. Both readable at libitb load time via env vars:

- `ITB_GOMEMLIMIT=512MiB` — soft memory limit in bytes; supports `B` / `KiB` / `MiB` / `GiB` / `TiB` suffixes.
- `ITB_GOGC=20` — GC trigger percentage; default `100`, lower triggers GC more aggressively.

Programmatic setters override env-set values at any time. Pass `-1` to either setter to query the current value without changing it.

```csharp
Itb.Library.SetMemoryLimit(512L << 20);
Itb.Library.SetGcPercent(20);
```

## Tests

```bash
./bindings/csharp/run_tests.sh
```

The harness verifies `libitb.so` is present, exports
`LD_LIBRARY_PATH`, and invokes `dotnet test -c Release`. Positional
arguments are forwarded straight to `dotnet test` (e.g.
`./run_tests.sh --filter FullyQualifiedName~Blake3` to scope the
run). The integration test suite under `bindings/csharp/Itb.Tests/`
mirrors the cross-binding coverage: Single + Triple Ouroboros,
mixed primitives, authenticated paths, blob round-trip, streaming
chunked I/O, error paths, lockSeed lifecycle.

## Benchmarks

A custom Go-bench-style harness lives under `Itb.Bench/` and
covers the four ops (`encrypt`, `decrypt`, `encrypt_auth`,
`decrypt_auth`) across the nine PRF-grade primitives plus one
mixed-primitive variant for both Single and Triple Ouroboros at
1024-bit ITB key width and 16 MiB payload. Run via:

```bash
dotnet run --project Itb.Bench -c Release -- single
dotnet run --project Itb.Bench -c Release -- triple
```

Environment variables: `ITB_NONCE_BITS` (default 128),
`ITB_LOCKSEED` (default off), `ITB_BENCH_FILTER` (case-insensitive
substring), `ITB_BENCH_MIN_SEC` (default 5).

See [`Itb.Bench/BENCH.md`](Itb.Bench/BENCH.md) for recorded
throughput results across the canonical pass matrix.

The four-pass canonical sweep (Single + Triple × ±LockSeed) that
fills `Itb.Bench/BENCH.md` is driven by the wrapper script in the
binding root:

```bash
./bindings/csharp/run_bench.sh                  # full 4-pass canonical sweep
./bindings/csharp/run_bench.sh --lockseed-only  # pass 3 + pass 4 only
```

The harness sets `LD_LIBRARY_PATH` to `dist/linux-amd64/`,
manages `ITB_LOCKSEED` per pass, and forwards `ITB_NONCE_BITS` /
`ITB_BENCH_FILTER` / `ITB_BENCH_MIN_SEC` straight through to the
underlying `dotnet run -c Release --project Itb.Bench -- single` /
`-- triple` invocations.

## Streaming AEAD

**Streaming AEAD** authenticates a chunked stream end-to-end while
preserving the deniability of the per-chunk MAC-Inside-Encrypt
container. Each chunk's MAC binds the encrypted payload to a 32-byte
CSPRNG stream anchor (written as a once-per-stream wire prefix), the
cumulative pixel offset of preceding chunks, and a final-flag bit —
defending against chunk reorder, replay within or across streams
sharing the PRF / MAC key, silent mid-stream drop, and truncate-tail.
The wire format adds 32 bytes of stream prefix plus one byte of
encrypted trailing flag per chunk; no externally visible MAC tag.

The two examples below encrypt a 64 MiB random source file in 16 MiB
chunks and verify a sha256 round-trip on the decrypted output.
Production deployments typically encrypt files at 1 GiB+ scale through
the same loop pattern; the chunk size selection (16 MiB here) controls
per-iteration memory residency.

**Easy Mode:**

`Encryptor.EncryptStreamAuth` accepts any
`Stream` source and any `Stream` sink; `FileStream` opened via
`File.OpenRead` / `File.Create` is the typical production-scale
choice. The MAC key is allocated CSPRNG-fresh inside the encryptor at
constructor time. `using` blocks drive deterministic disposal on both
the encryptor and the file streams.

```csharp
using System.IO;
using System.Security.Cryptography;
using Itb;
using Itb.Wrapper;
using OuterCipher = Itb.Wrapper.Cipher;

const string SRC_PATH = "/tmp/64mb.src";
const string ENC_PATH = "/tmp/64mb.enc";
const string DST_PATH = "/tmp/64mb.dst";
const string INNER_PATH = "/tmp/64mb.inner";
const int CHUNK_SIZE = 16 * 1024 * 1024;

static string Sha256Of(string path)
{
    using var sha = SHA256.Create();
    using var fs = File.OpenRead(path);
    return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
}

// Materialise a 64 MiB random source file once.
if (!File.Exists(SRC_PATH) || new FileInfo(SRC_PATH).Length != 64L * 1024 * 1024)
{
    byte[] buf = RandomNumberGenerator.GetBytes(64 * 1024 * 1024);
    File.WriteAllBytes(SRC_PATH, buf);
}

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
var outerKey = Wrapper.GenerateKey(OuterCipher.Aes128Ctr);

using var enc = new Encryptor("areion512", 1024, "hmac-blake3", "single");

// Sender — encrypt to an intermediate file, then wrap end-to-end
// through one keystream session.
using (var fin = File.OpenRead(SRC_PATH))
using (var fout = File.Create(INNER_PATH))
{
    enc.EncryptStreamAuth(fin, fout, CHUNK_SIZE);
}
// Format-deniability ITB masking via outer-cipher streaming wrapper (AES-128-CTR) - same ~0% overhead in stream mode (Recommended in every case).
using (var ww = new WrapStreamWriter(OuterCipher.Aes128Ctr, outerKey))
using (var fin = File.OpenRead(INNER_PATH))
using (var fout = File.Create(ENC_PATH))
{
    fout.Write(ww.Nonce);
    var buf = new byte[CHUNK_SIZE];
    int n;
    while ((n = fin.Read(buf, 0, buf.Length)) > 0)
    {
        fout.Write(ww.Update(buf.AsSpan(0, n)));
    }
}
File.Delete(INNER_PATH);

// Receiver — strip the leading nonce, unwrap the body, decrypt.
using (var fin = File.OpenRead(ENC_PATH))
{
    var nlen = Wrapper.NonceSize(OuterCipher.Aes128Ctr);
    var nonceBuf = new byte[nlen];
    fin.ReadExactly(nonceBuf);
    using var ur = new UnwrapStreamReader(OuterCipher.Aes128Ctr, outerKey, nonceBuf);
    using var fout = File.Create(INNER_PATH);
    var buf = new byte[CHUNK_SIZE];
    int n;
    while ((n = fin.Read(buf, 0, buf.Length)) > 0)
    {
        fout.Write(ur.Update(buf.AsSpan(0, n)));
    }
}
using (var fin = File.OpenRead(INNER_PATH))
using (var fout = File.Create(DST_PATH))
{
    enc.DecryptStreamAuth(fin, fout, CHUNK_SIZE);
}
File.Delete(INNER_PATH);

string srcHash = Sha256Of(SRC_PATH);
string dstHash = Sha256Of(DST_PATH);
Console.WriteLine($"Easy Mode src sha256: {srcHash}");
Console.WriteLine($"Easy Mode dst sha256: {dstHash}");
if (srcHash != dstHash) throw new Exception("Easy Mode: sha256 mismatch");
Console.WriteLine("[OK] Easy Mode: 64 MiB roundtrip via stream-auth verified");
```

**Build + run:**

The example project carries a single `<ProjectReference>` to the
binding's `Itb.csproj` and consumes the `Itb` namespace directly:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <RootNamespace>Example</RootNamespace>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="<itb>/bindings/csharp/Itb/Itb.csproj" />
  </ItemGroup>
</Project>
```

Place `Program.cs` (containing the source above) and `Example.csproj`
under `<itb>/csharp_example/`, then:

```sh
cd <itb>/csharp_example && dotnet run -c Release
```

The binding's `NativeLibrary` resolver locates
`<itb>/dist/<os>-<arch>/libitb.so` automatically once the project
reference resolves the `Itb` assembly — no `ITB_LIBRARY_PATH` export
is required when the shared library lives under the repository's
canonical `dist/` tree. Override with `ITB_LIBRARY_PATH=/abs/path` to
point at a non-canonical build.

**Output (verified):**

```
Easy Mode src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Easy Mode dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Easy Mode: 64 MiB roundtrip via stream-auth verified
```

---

**Low-Level Mode:**

Static functions on `StreamPipeline` take
three explicit `Seed` handles plus an explicitly constructed `Mac`
(32-byte key drawn via `RandomNumberGenerator.GetBytes(32)`) and
stream through the same chunked-AEAD construction. Both seeds and MAC
are `IDisposable` and bound to the same `using` discipline as the
encryptor.

```csharp
using System.IO;
using System.Security.Cryptography;
using Itb;
using Itb.Wrapper;
using OuterCipher = Itb.Wrapper.Cipher;

const string SRC_PATH = "/tmp/64mb.src";
const string ENC_PATH = "/tmp/64mb.enc";
const string DST_PATH = "/tmp/64mb.dst";
const string INNER_PATH = "/tmp/64mb.inner";
const int CHUNK_SIZE = 16 * 1024 * 1024;

static string Sha256Of(string path)
{
    using var sha = SHA256.Create();
    using var fs = File.OpenRead(path);
    return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
}

using var noise = new Seed("areion512", 1024);
using var data  = new Seed("areion512", 1024);
using var start = new Seed("areion512", 1024);
var macKey = RandomNumberGenerator.GetBytes(32);
using var mac = new Mac("hmac-blake3", macKey);

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
var outerKey = Wrapper.GenerateKey(OuterCipher.Aes128Ctr);

// Sender — encrypt to an intermediate file, then wrap end-to-end.
using (var fin = File.OpenRead(SRC_PATH))
using (var fout = File.Create(INNER_PATH))
{
    StreamPipeline.EncryptStreamAuth(noise, data, start, mac, fin, fout, CHUNK_SIZE);
}
// Format-deniability ITB masking via outer-cipher streaming wrapper (AES-128-CTR) - same ~0% overhead in stream mode (Recommended in every case).
using (var ww = new WrapStreamWriter(OuterCipher.Aes128Ctr, outerKey))
using (var fin = File.OpenRead(INNER_PATH))
using (var fout = File.Create(ENC_PATH))
{
    fout.Write(ww.Nonce);
    var buf = new byte[CHUNK_SIZE];
    int n;
    while ((n = fin.Read(buf, 0, buf.Length)) > 0)
    {
        fout.Write(ww.Update(buf.AsSpan(0, n)));
    }
}
File.Delete(INNER_PATH);

// Receiver
using (var fin = File.OpenRead(ENC_PATH))
{
    var nlen = Wrapper.NonceSize(OuterCipher.Aes128Ctr);
    var nonceBuf = new byte[nlen];
    fin.ReadExactly(nonceBuf);
    using var ur = new UnwrapStreamReader(OuterCipher.Aes128Ctr, outerKey, nonceBuf);
    using var fout = File.Create(INNER_PATH);
    var buf = new byte[CHUNK_SIZE];
    int n;
    while ((n = fin.Read(buf, 0, buf.Length)) > 0)
    {
        fout.Write(ur.Update(buf.AsSpan(0, n)));
    }
}
using (var fin = File.OpenRead(INNER_PATH))
using (var fout = File.Create(DST_PATH))
{
    StreamPipeline.DecryptStreamAuth(noise, data, start, mac, fin, fout, CHUNK_SIZE);
}
File.Delete(INNER_PATH);

string srcHash = Sha256Of(SRC_PATH);
string dstHash = Sha256Of(DST_PATH);
Console.WriteLine($"Low-Level src sha256: {srcHash}");
Console.WriteLine($"Low-Level dst sha256: {dstHash}");
if (srcHash != dstHash) throw new Exception("Low-Level: sha256 mismatch");
Console.WriteLine("[OK] Low-Level Mode: 64 MiB roundtrip via stream-auth verified");
```

**Build + run:**

```sh
cd <itb>/csharp_example && dotnet run -c Release
```

**Output (verified):**

```
Low-Level src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Low-Level dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Low-Level Mode: 64 MiB roundtrip via stream-auth verified
```

The C# binding's stream-auth surface accepts any `System.IO.Stream`
subtype, so `FileStream`, `MemoryStream`, network sockets, and gzip /
brotli decoders all participate uniformly without bespoke adapter
types. Easy Mode `Encryptor` mode parameter is the case-insensitive
string `"single"` for Single Ouroboros (or `"triple"` for the 7-seed
Triple Ouroboros mode). Low-Level Mode does not carry a top-level mode
parameter — Single vs Triple is selected by which `StreamPipeline`
overload is invoked.

## Quick Start — `Itb.Encryptor` + HMAC-BLAKE3 (MAC Authenticated)

The high-level `Encryptor` (mirroring the
`github.com/everanium/itb/easy` Go sub-package) replaces the
seven-line setup ceremony of the lower-level
`Seed` / `Cipher.Encrypt` / `Cipher.Decrypt` path with one
constructor call: the encryptor allocates its own three (Single)
or seven (Triple) seeds plus MAC closure, snapshots the global
configuration into a per-instance Config, and exposes setters that
mutate only its own state without touching the process-wide
`Library` accessors. Two encryptors with different settings can
run concurrently without cross-contamination.

The MAC primitive is bound at construction time — the `mac`
parameter selects one of the registry names (`hmac-blake3` —
recommended default, `hmac-sha256`, `kmac256`). The encryptor
allocates a fresh 32-byte CSPRNG MAC key alongside the per-seed
PRF keys; `enc.Export()` carries all of them in a single JSON
blob. On the receiver side, `dec.Import(blob)` restores the MAC
key together with the seeds, so the encrypt-today /
decrypt-tomorrow flow is one method call per side.

When the `mac` argument is omitted (or `null`) the binding picks
`hmac-blake3` rather than forwarding `null` through to libitb's
own default — HMAC-BLAKE3 measures the lightest authenticated-mode
overhead across the Easy Mode bench surface (~9% over plain
encrypt vs HMAC-SHA256's ~15% vs KMAC-256's ~44%).

```csharp
// Sender

using Itb;
using Itb.Wrapper;
using OuterCipher = Itb.Wrapper.Cipher;

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
var outerKey = Wrapper.GenerateKey(OuterCipher.Aes128Ctr);

// Per-instance configuration — mutates only this encryptor's
// Config. Two encryptors built side-by-side carry independent
// settings; process-wide Library accessors are NOT consulted
// after construction. mode: "single" = Single Ouroboros (3 seeds);
// mode: "triple" = Triple Ouroboros (7 seeds).
using var enc = new Encryptor(
    primitive: "areion512",
    keyBits: 2048,
    mac: "hmac-blake3",
    mode: "single");

enc.SetNonceBits(512);    // 512-bit nonce (default: 128-bit)
enc.SetBarrierFill(4);    // CSPRNG fill margin (default: 1, valid: 1, 2, 4, 8, 16, 32)
enc.SetBitSoup(1);        // optional bit-level split ("bit-soup"; default: 0 = byte-level)
                          // auto-enabled for Single Ouroboros if SetLockSoup(1) is on
enc.SetLockSoup(1);       // optional Insane Interlocked Mode: per-chunk PRF-keyed
                          // bit-permutation overlay on top of bit-soup;
                          // auto-enabled for Single Ouroboros if SetBitSoup(1) is on

// enc.SetLockSeed(1);    // optional dedicated lockSeed for the bit-permutation
                          // derivation channel — separates that PRF's keying
                          // material from the noiseSeed-driven noise-injection
                          // channel; auto-couples SetLockSoup(1) +
                          // SetBitSoup(1). Adds one extra seed slot
                          // (3 → 4 for Single, 7 → 8 for Triple). Must be
                          // called BEFORE the first EncryptAuth — switching
                          // mid-session raises ItbException with status
                          // EasyLockSeedAfterEncrypt.

// Persistence blob — carries seeds + PRF keys + MAC key (and the
// dedicated lockSeed material when SetLockSeed(1) is active).
var blob = enc.Export();
Console.WriteLine($"state blob: {blob.Length} bytes");
Console.WriteLine($"primitive: {enc.Primitive}, key_bits: {enc.KeyBits}, mode: {enc.Mode}, mac: {enc.MacName}");

var plaintext = "any text or binary data - including 0x00 bytes"u8.ToArray();
// var chunkSize = 4 * 1024 * 1024;  // 4 MiB - bulk local crypto, not small-frame network streaming

// Authenticated encrypt — 32-byte tag is computed across the
// entire decrypted capacity and embedded inside the RGBWYOPA
// container, preserving oracle-free deniability.
var encrypted = enc.EncryptAuth(plaintext);
Console.WriteLine($"encrypted: {encrypted.Length} bytes");

// Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
var nonce = Wrapper.WrapInPlace(OuterCipher.Aes128Ctr, outerKey, encrypted);
var wire = new byte[nonce.Length + encrypted.Length];
Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
Buffer.BlockCopy(encrypted, 0, wire, nonce.Length, encrypted.Length);
Console.WriteLine($"wire: {wire.Length} bytes");

// Send wire + state blob; Dispose at scope end (via using var)
// releases the handle and zeroes the per-encryptor output buffer.
// enc.Close() is the explicit zeroisation entry point that does
// not release the handle.


// Receiver

// Receive wire + state blob
// var wire = ...;
// var blob = ...;

Library.MaxWorkers = 8;   // limit to 8 CPU cores (default: 0 = all CPUs)

// Optional: peek at the blob's metadata before constructing a
// matching encryptor. Useful when the receiver multiplexes blobs
// of different shapes (different primitive / mode / MAC choices).
var cfg = Encryptor.PeekConfig(blob);
Console.WriteLine($"peek: primitive={cfg.Primitive}, key_bits={cfg.KeyBits}, mode={cfg.Mode}, mac={cfg.MacName}");

using var dec = new Encryptor(
    primitive: cfg.Primitive,
    keyBits: cfg.KeyBits,
    mac: cfg.MacName,
    mode: cfg.Mode == 3 ? "triple" : "single");

// dec.Import(blob) below automatically restores the full
// per-instance configuration (NonceBits, BarrierFill, BitSoup,
// LockSoup, and the dedicated lockSeed material when sender's
// SetLockSeed(1) was active). The Set*() lines below are kept
// for documentation — they show the knobs available for explicit
// pre-Import override. BarrierFill is asymmetric: a receiver-set
// value > 1 takes priority over the blob's BarrierFill (the
// receiver's heavier CSPRNG margin is preserved across Import).
dec.SetNonceBits(512);
dec.SetBarrierFill(4);
dec.SetBitSoup(1);
dec.SetLockSoup(1);

// Restore PRF keys, seed components, MAC key, and the per-instance
// configuration overrides (NonceBits / BarrierFill / BitSoup /
// LockSoup / LockSeed) from the saved blob.
dec.Import(blob);

// Strip the leading nonce, unwrap the body, then decrypt.
var recoveredSpan = Wrapper.UnwrapInPlace(OuterCipher.Aes128Ctr, outerKey, wire);
var recovered = recoveredSpan.ToArray();

// Authenticated decrypt — any single-bit tamper triggers MAC
// failure (no oracle leak about which byte was tampered). Mismatch
// surfaces as ItbException with status MacFailure, not a corrupted
// plaintext.
try
{
    var decrypted = dec.DecryptAuth(recovered);
    Console.WriteLine($"decrypted: {System.Text.Encoding.UTF8.GetString(decrypted)}");
}
catch (ItbException ex) when (ex.Status == StatusCode.MacFailure)
{
    Console.WriteLine("MAC verification failed — tampered or wrong key");
}
```

## Quick Start — Mixed primitives (Different PRF per seed slot)

`Encryptor.Mixed` and `Encryptor.Mixed3` accept per-slot
primitive names — the noise / data / start (and optional dedicated
lockSeed) seed slots can use different PRF primitives within the
same native hash width. The mix-and-match-PRF freedom of the
lower-level path, surfaced through the high-level `Encryptor`
without forcing the caller off the Easy Mode constructor. The
state blob carries per-slot primitives + per-slot PRF keys; the
receiver constructs a matching encryptor with the same arguments
and calls `Import` to restore.

```csharp
// Sender

using Itb;
using Itb.Wrapper;
using OuterCipher = Itb.Wrapper.Cipher;

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
var outerKey = Wrapper.GenerateKey(OuterCipher.Aes128Ctr);

// Per-slot primitive selection (Single Ouroboros, 3 + 1 slots).
// Every name must share the same native hash width — mixing widths
// raises ItbException at construction time.
// Triple Ouroboros mirror — Encryptor.Mixed3 takes seven
// per-slot names (noise + 3 data + 3 start) plus the optional
// primL lockSeed.
using var enc = Encryptor.Mixed(
    primN: "blake3",         // noiseSeed:  BLAKE3
    primD: "blake2s",        // dataSeed:   BLAKE2s
    primS: "areion256",      // startSeed:  Areion-SoEM-256
    keyBits: 1024,
    mac: "hmac-blake3",
    primL: "blake2b256");    // dedicated lockSeed (null for no lockSeed slot)

// Per-instance configuration applies as for the new Encryptor(...)
// case shown above.
enc.SetNonceBits(512);
enc.SetBarrierFill(4);
// BitSoup + LockSoup are auto-coupled on the on-direction by primL
// above; explicit calls below are unnecessary but harmless if added.
// enc.SetBitSoup(1);
// enc.SetLockSoup(1);

// Per-slot introspection — enc.Primitive returns the first slot's
// name, enc.PrimitiveAt(slot) returns each slot's name, enc.IsMixed
// is the typed predicate. Slot ordering is canonical: 0 = noiseSeed,
// 1 = dataSeed, 2 = startSeed, 3 = lockSeed (Single); Triple grows
// the middle range to 7 slots + lockSeed.
Console.WriteLine($"mixed={enc.IsMixed} primitive={enc.Primitive}");
for (var i = 0; i < 4; i++)
{
    Console.WriteLine($"  slot {i}: {enc.PrimitiveAt(i)}");
}

var blob = enc.Export();
var plaintext = "mixed-primitive Easy Mode payload"u8.ToArray();
var encrypted = enc.EncryptAuth(plaintext);

// Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
var nonce = Wrapper.WrapInPlace(OuterCipher.Aes128Ctr, outerKey, encrypted);
var wire = new byte[nonce.Length + encrypted.Length];
Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
Buffer.BlockCopy(encrypted, 0, wire, nonce.Length, encrypted.Length);


// Receiver

// Receive wire + state blob
// var wire = ...;
// var blob = ...;

// Receiver constructs a matching mixed encryptor — every per-slot
// primitive name plus keyBits and mac must agree with the sender.
// Import validates each per-slot primitive against the receiver's
// bound spec; mismatches raise ItbEasyMismatchException with the
// "primitive" field tag.
using var dec = Encryptor.Mixed(
    primN: "blake3",
    primD: "blake2s",
    primS: "areion256",
    keyBits: 1024,
    mac: "hmac-blake3",
    primL: "blake2b256");

dec.Import(blob);

// Strip the leading nonce, unwrap the body, then decrypt.
var recoveredSpan = Wrapper.UnwrapInPlace(OuterCipher.Aes128Ctr, outerKey, wire);
var recovered = recoveredSpan.ToArray();

var decrypted = dec.DecryptAuth(recovered);
Console.WriteLine($"decrypted: {System.Text.Encoding.UTF8.GetString(decrypted)}");
```

## Quick Start — Triple Ouroboros

Triple Ouroboros (3× security: P × 2^(3×key_bits)) takes seven
seeds (one shared `noiseSeed` plus three `dataSeed` and three
`startSeed`) on the low-level path, all wrapped behind a single
`Encryptor` call when `mode: "triple"` is passed to the
constructor.

```csharp
using Itb;
using Itb.Wrapper;
using OuterCipher = Itb.Wrapper.Cipher;

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
var outerKey = Wrapper.GenerateKey(OuterCipher.Aes128Ctr);

// mode: "triple" selects Triple Ouroboros. All other constructor
// arguments behave identically to the Single (mode: "single") case
// shown above.
using var enc = new Encryptor(
    primitive: "areion512",
    keyBits: 2048,
    mac: "hmac-blake3",
    mode: "triple");

var plaintext = "Triple Ouroboros payload"u8.ToArray();
var encrypted = enc.EncryptAuth(plaintext);

// Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
var nonce = Wrapper.WrapInPlace(OuterCipher.Aes128Ctr, outerKey, encrypted);
var wire = new byte[nonce.Length + encrypted.Length];
Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
Buffer.BlockCopy(encrypted, 0, wire, nonce.Length, encrypted.Length);

// Receiver — strip the leading nonce, unwrap the body, then decrypt.
var recoveredSpan = Wrapper.UnwrapInPlace(OuterCipher.Aes128Ctr, outerKey, wire);
var recovered = recoveredSpan.ToArray();
var decrypted = enc.DecryptAuth(recovered);
```

The seven-seed split is internal to the encryptor; the on-wire
ciphertext format is identical in shape to Single Ouroboros — only
the internal payload split / interleave differs. Mixed-primitive
Triple is reachable via `Encryptor.Mixed3`.

## Quick Start — Areion-SoEM-512 + HMAC-BLAKE3 (Low-Level, MAC Authenticated)

The lower-level path uses explicit `Seed` handles for the
noise / data / start trio plus an optional dedicated `Seed` wired
in through `Seed.AttachLockSeed`. Useful when the caller needs
full control over per-slot keying (e.g. PRF material stored in an
HSM) or when slotting into the existing Go `itb.Encrypt` /
`itb.Decrypt` call surface from a C# client. The high-level
`Encryptor` above wraps this same path with one constructor call.

```csharp
// Sender

using Itb;
using Itb.Wrapper;
using ItbCipher = Itb.Cipher;
using OuterCipher = Itb.Wrapper.Cipher;

// Optional: global configuration (all process-wide, atomic)
Library.MaxWorkers = 8;     // limit to 8 CPU cores (default: 0 = all CPUs)
Library.NonceBits = 512;    // 512-bit nonce (default: 128-bit)
Library.BarrierFill = 4;    // CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)

Library.BitSoup = 1;        // optional bit-level split ("bit-soup"; default: 0 = byte-level)
                            // automatically enabled for Single Ouroboros if
                            // Library.LockSoup = 1 or vice versa

Library.LockSoup = 1;       // optional Insane Interlocked Mode: per-chunk PRF-keyed
                            // bit-permutation overlay on top of bit-soup;
                            // automatically enabled for Single Ouroboros if
                            // Library.BitSoup = 1 or vice versa

// Three independent CSPRNG-keyed Areion-SoEM-512 seeds. Each Seed
// pre-keys its primitive once at construction; the C ABI / FFI
// layer auto-wires the AVX-512 + VAES + ILP + ZMM-batched chain-
// absorb dispatch through Seed::BatchHash — no manual batched-arm
// attachment is required on the C# side.
using var ns = new Seed("areion512", 2048);   // random noise CSPRNG seeds + hash key generated
using var ds = new Seed("areion512", 2048);   // random data  CSPRNG seeds + hash key generated
using var ss = new Seed("areion512", 2048);   // random start CSPRNG seeds + hash key generated

// Optional: dedicated lockSeed for the bit-permutation derivation
// channel. Separates that PRF's keying material from the noiseSeed-
// driven noise-injection channel without changing the public encrypt
// / decrypt signatures. The bit-permutation overlay must be engaged
// (Library.BitSoup = 1 or Library.LockSoup = 1 — both already on
// above) before the first encrypt; the build-PRF guard panics on
// encrypt-time when an attach is present without either flag.
using var ls = new Seed("areion512", 2048);   // random lock CSPRNG seeds + hash key generated
ns.AttachLockSeed(ls);

// HMAC-BLAKE3 — 32-byte CSPRNG key, 32-byte tag. Real code should
// pull the key bytes from a CSPRNG (e.g. RandomNumberGenerator.Fill);
// the zero key here is for example purposes only.
var macKey = new byte[32];
using var mac = new Mac("hmac-blake3", macKey);

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
var outerKey = Wrapper.GenerateKey(OuterCipher.Aes128Ctr);

var plaintext = "any text or binary data - including 0x00 bytes"u8.ToArray();

// Authenticated encrypt — 32-byte tag is computed across the
// entire decrypted capacity and embedded inside the RGBWYOPA
// container, preserving oracle-free deniability.
var encrypted = ItbCipher.EncryptAuth(ns, ds, ss, mac, plaintext);
Console.WriteLine($"encrypted: {encrypted.Length} bytes");

// Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
var nonce = Wrapper.WrapInPlace(OuterCipher.Aes128Ctr, outerKey, encrypted);
var wire = new byte[nonce.Length + encrypted.Length];
Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
Buffer.BlockCopy(encrypted, 0, wire, nonce.Length, encrypted.Length);
Console.WriteLine($"wire: {wire.Length} bytes");

// Cross-process persistence: Blob512 packs every seed's hash key +
// components, the optional dedicated lockSeed, and the MAC key +
// name into one JSON blob alongside the captured process-wide
// globals. BlobExportOpts.LockSeed / BlobExportOpts.Mac opt the
// corresponding sections in.
using var blob = new Blob512();
blob.SetKey(BlobSlot.N, ns.GetHashKey());
blob.SetComponents(BlobSlot.N, ns.GetComponents());
blob.SetKey(BlobSlot.D, ds.GetHashKey());
blob.SetComponents(BlobSlot.D, ds.GetComponents());
blob.SetKey(BlobSlot.S, ss.GetHashKey());
blob.SetComponents(BlobSlot.S, ss.GetComponents());
blob.SetKey(BlobSlot.L, ls.GetHashKey());
blob.SetComponents(BlobSlot.L, ls.GetComponents());
blob.SetMacKey(macKey);
blob.SetMacName("hmac-blake3");
var blobBytes = blob.Export(BlobExportOpts.LockSeed | BlobExportOpts.Mac);


// Receiver — same code block, shared `using` from above.

Library.MaxWorkers = 8;   // deployment knob — not serialised by Blob512

// Receive wire + blobBytes
// var wire = ...;
// var blobBytes = ...;

// Blob512.Import restores per-slot hash keys + components AND
// applies the captured globals (NonceBits / BarrierFill / BitSoup /
// LockSoup) via the process-wide setters.
using var restored = new Blob512();
restored.Import(blobBytes);

using var nsRestored = Seed.FromComponents(
    "areion512",
    restored.GetComponents(BlobSlot.N),
    restored.GetKey(BlobSlot.N));
using var dsRestored = Seed.FromComponents(
    "areion512",
    restored.GetComponents(BlobSlot.D),
    restored.GetKey(BlobSlot.D));
using var ssRestored = Seed.FromComponents(
    "areion512",
    restored.GetComponents(BlobSlot.S),
    restored.GetKey(BlobSlot.S));
using var lsRestored = Seed.FromComponents(
    "areion512",
    restored.GetComponents(BlobSlot.L),
    restored.GetKey(BlobSlot.L));
nsRestored.AttachLockSeed(lsRestored);

var macName = restored.GetMacName();
var macKeyRestored = restored.GetMacKey();
using var macRestored = new Mac(macName, macKeyRestored);

// Strip the leading nonce, unwrap the body, then decrypt.
var recoveredSpan = Wrapper.UnwrapInPlace(OuterCipher.Aes128Ctr, outerKey, wire);
var recovered = recoveredSpan.ToArray();

// Authenticated decrypt — any single-bit tamper triggers MAC
// failure (no oracle leak about which byte was tampered).
var decrypted = ItbCipher.DecryptAuth(nsRestored, dsRestored, ssRestored, macRestored, recovered);
Console.WriteLine($"decrypted: {System.Text.Encoding.UTF8.GetString(decrypted)}");
```

## Streams — chunked I/O over `System.IO.Stream`

`StreamEncryptor` / `StreamDecryptor` (and the seven-seed
counterparts `StreamEncryptorTriple` / `StreamDecryptorTriple`)
wrap the Single Message Encrypt / Decrypt API behind a `Write` /
`Feed`-driven chunked I/O surface. ITB ciphertexts cap at
~64 MB plaintext per chunk; streaming larger payloads slices the
input into chunks at the binding layer, encrypts each chunk
through the regular FFI path, and concatenates the results.
Memory peak is bounded by `chunkSize` (default
`StreamDefaults.DefaultChunkSize` = 16 MiB) regardless of the
total payload length.

```csharp
using System.IO;
using Itb;

using var n = new Seed("blake3", 1024);
using var d = new Seed("blake3", 1024);
using var s = new Seed("blake3", 1024);

// Encrypt: write plaintext into the encryptor, ciphertext lands
// in the wrapped Stream sink. Close() flushes the trailing partial
// chunk; Dispose best-effort-flushes on scope exit.
var sink = new MemoryStream();
using (var enc = new StreamEncryptor(n, d, s, sink, chunkSize: 1 << 16))
{
    enc.Write("chunk one"u8);
    enc.Write("chunk two"u8);
    enc.Close();
}
var ciphertext = sink.ToArray();

// Decrypt: feed ciphertext bytes (any granularity, partial chunks
// are buffered until complete), plaintext lands in the wrapped
// Stream sink as each chunk completes. Close() errors when
// leftover bytes do not form a complete chunk.
var psink = new MemoryStream();
using (var dec = new StreamDecryptor(n, d, s, psink))
{
    dec.Feed(ciphertext);
    dec.Close();
}
// psink.ToArray() == "chunk onechunk two"u8.ToArray()
```

For driving an encrypt or decrypt straight off a `Stream` pair
(input and output), the `StreamPipeline` helpers loop until EOF
internally:

```csharp
using System.IO;
using Itb;

using var n = new Seed("blake3", 1024);
using var d = new Seed("blake3", 1024);
using var s = new Seed("blake3", 1024);

var plaintext = new byte[5 * 1024 * 1024];
new Random(42).NextBytes(plaintext);

var ciphertextSink = new MemoryStream();
StreamPipeline.EncryptStream(
    n, d, s,
    new MemoryStream(plaintext),
    ciphertextSink,
    chunkSize: 1 << 20);

var recoveredSink = new MemoryStream();
StreamPipeline.DecryptStream(
    n, d, s,
    new MemoryStream(ciphertextSink.ToArray()),
    recoveredSink,
    readSize: 1 << 16);
```

Switching `Library.NonceBits` mid-stream produces a chunk header
layout the paired decryptor (which snapshots `Library.HeaderSize`
at construction) cannot parse — the nonce size must be stable for
the lifetime of one stream pair.

## Native Blob — low-level state persistence

`Blob128` / `Blob256` / `Blob512` wrap the libitb Native Blob C
ABI: a width-specific container that packs the low-level encryptor
material (per-seed hash key + components + optional dedicated
lockSeed + optional MAC key + name) plus the captured process-wide
configuration into one self-describing JSON blob. Used on the
lower-level encrypt / decrypt path where each seed slot may carry
a different primitive — the high-level `Encryptor.Export` wraps a
narrower one-primitive-per-encryptor surface that uses the same
wire format under the hood.

```csharp
using Itb;

// Sender side — pack a Single-Ouroboros + Areion-SoEM-512 + MAC
// state blob.
using var ns = new Seed("areion512", 2048);
using var ds = new Seed("areion512", 2048);
using var ss = new Seed("areion512", 2048);

var macKey = new byte[32];
using var blob = new Blob512();
blob.SetKey(BlobSlot.N, ns.GetHashKey());
blob.SetComponents(BlobSlot.N, ns.GetComponents());
blob.SetKey(BlobSlot.D, ds.GetHashKey());
blob.SetComponents(BlobSlot.D, ds.GetComponents());
blob.SetKey(BlobSlot.S, ss.GetHashKey());
blob.SetComponents(BlobSlot.S, ss.GetComponents());
blob.SetMacKey(macKey);
blob.SetMacName("hmac-blake3");
var blobBytes = blob.Export(BlobExportOpts.Mac);   // LockSeed not opted in

// Receiver side — round-trip back to working seed material.
using var restored = new Blob512();
restored.Import(blobBytes);

using var nsRestored = Seed.FromComponents(
    "areion512",
    restored.GetComponents(BlobSlot.N),
    restored.GetKey(BlobSlot.N));
// ... wire ds, ss the same way; rebuild MAC; Cipher.DecryptAuth ...
```

The blob is mode-discriminated: `Blob512.Export` packs Single
material; `Blob512.ExportTriple` packs Triple material; the
matching `Blob512.Import` / `Blob512.ImportTriple` receivers
reject the wrong importer with `ItbBlobModeMismatchException`.

## Hash primitives (Single / Triple)

Names match the canonical `hashes/` registry. Listed below in the
canonical primitive ordering used across ITB documentation —
`AES-CMAC`, `SipHash-2-4`, `ChaCha20`, `Areion-SoEM-256`,
`BLAKE2s`, `BLAKE3`, `BLAKE2b-256`, `BLAKE2b-512`,
`Areion-SoEM-512` — the FFI names are `aescmac`, `siphash24`,
`chacha20`, `areion256`, `blake2s`, `blake3`, `blake2b256`,
`blake2b512`, `areion512`. Triple Ouroboros (3× security) takes
seven seeds (one shared `noiseSeed` plus three `dataSeed` and three
`startSeed`) via `Cipher.EncryptTriple` / `Cipher.DecryptTriple`
and the authenticated counterparts `Cipher.EncryptAuthTriple` /
`Cipher.DecryptAuthTriple`. Streaming counterparts:
`StreamEncryptorTriple` / `StreamDecryptorTriple` /
`StreamPipeline.EncryptStreamTriple` /
`StreamPipeline.DecryptStreamTriple`.

All seeds passed to one `Cipher.Encrypt` / `Cipher.Decrypt` call
must share the same native hash width. Mixing widths raises
`ItbException` with status `SeedWidthMix`.

## MAC primitives

Names match the libitb MAC registry; ordering matches that registry's declaration order.

| MAC | Key bytes | Tag bytes | Underlying primitive |
|---|---|---|---|
| `kmac256` | 32 | 32 | KMAC256 (Keccak-derived) |
| `hmac-sha256` | 32 | 32 | HMAC over SHA-256 |
| `hmac-blake3` | 32 | 32 | HMAC over BLAKE3 |

`kmac256` and `hmac-sha256` accept keys 16 bytes and longer; the binding fleet's tests and examples use 32 bytes uniformly across primitives for cross-binding consistency. `hmac-blake3` requires exactly 32 bytes by construction.

## Process-wide configuration

Every setter takes effect for all subsequent encrypt / decrypt
calls in the process. `Library.NonceBits` and `Library.BarrierFill`
are enumerated — out-of-enumeration values surface as
`ItbException` with status `BadInput`. `Library.BitSoup`,
`Library.LockSoup`, and `Library.MaxWorkers` are forwarded without
client-side validation — libitb interprets any non-zero value as
"on" for the two soup setters, and `MaxWorkers = 0` selects the
all-CPUs default.

| Property | Accepted values | Default | Validated |
|---|---|---|---|
| `Library.MaxWorkers` | non-negative int | 0 (auto) | forwarded |
| `Library.NonceBits` | 128, 256, 512 | 128 | yes (`BadInput` on miss) |
| `Library.BarrierFill` | 1, 2, 4, 8, 16, 32 | 1 | yes (`BadInput` on miss) |
| `Library.BitSoup` | 0 (off), non-zero (on) | 0 | forwarded |
| `Library.LockSoup` | 0 (off), non-zero (on) | 0 | forwarded |

Read-only properties: `Library.MaxKeyBits`, `Library.Channels`,
`Library.HeaderSize`, `Library.Version`.

For low-level chunk parsing (e.g. when implementing custom file
formats around ITB chunks): `Library.ParseChunkLen(header)`
inspects the fixed-size chunk header and returns the chunk's
total on-the-wire length; `Library.HeaderSize` returns the active
header byte count (20 / 36 / 68 for nonce sizes 128 / 256 /
512 bits).

MAC names available via `Library.ListMacs()`: `kmac256`,
`hmac-sha256`, `hmac-blake3`. Hash names via
`Library.ListHashes()`.

## Concurrency

The libitb shared library exposes process-wide configuration
through a small set of atomics (`Library.NonceBits`,
`Library.BarrierFill`, `Library.BitSoup`, `Library.LockSoup`,
`Library.MaxWorkers`). Multiple threads calling these setters
concurrently without external coordination will race for the
final value visible to subsequent encrypt / decrypt calls —
serialise the mutators behind a `lock` (or set them once at
startup before spawning workers) when multiple .NET threads need
to touch them.

Per-encryptor configuration via `Encryptor.SetNonceBits` /
`Encryptor.SetBarrierFill` / `Encryptor.SetBitSoup` /
`Encryptor.SetLockSoup` mutates only that handle's Config copy
and is safe to call from the owning thread without affecting
other `Encryptor` instances. The cipher methods
(`Encryptor.Encrypt` / `Encryptor.Decrypt` /
`Encryptor.EncryptAuth` / `Encryptor.DecryptAuth`) write into a
per-instance output-buffer cache; sharing one `Encryptor` across
threads requires external synchronisation. Distinct `Encryptor`
handles, each owned by one thread, run independently against the
libitb worker pool.

By contrast, the low-level cipher free functions (`Cipher.Encrypt`
/ `Cipher.Decrypt` / `Cipher.EncryptAuth` / `Cipher.DecryptAuth`
plus the Triple counterparts) allocate output per call and are
**thread-safe** under concurrent invocation on the same `Seed`
handles — libitb's worker pool dispatches them independently. Two
exceptions: `Seed.AttachLockSeed` mutates the noise Seed and must
not race against an in-flight cipher call on it, and the
process-wide setters above stay process-global.

The `Seed`, `Mac`, `Encryptor`, `Blob128` / `Blob256` / `Blob512`
handle types are reference types whose underlying libitb handles
are protected by libitb's internal mutex-protected handle table.
Crossing a handle to another thread — moving via channel,
disposing on a worker, calling read-only accessors from two
threads against the same handle — is sound: libitb's cgo handle
table is internally mutex-protected, and the binding never holds
.NET-side state for these handles outside the per-call FFI surface
(the only .NET-side state is the `Encryptor`'s output-buffer
cache, which the cipher methods serialise via the per-instance
buffer field).

## Error model

Every failure surfaces as `ItbException` with a `Status` numeric
code and a textual `Message`. Four typed subclasses dispatch
selected status codes for selective `catch` blocks:

| Status code | Subclass | Carries |
|---|---|---|
| `EasyMismatch` (17) | `ItbEasyMismatchException` | `.Field` — JSON field name on which Import disagreed |
| `BlobModeMismatch` (19) | `ItbBlobModeMismatchException` | — |
| `BlobMalformed` (20) | `ItbBlobMalformedException` | — |
| `BlobVersionTooNew` (21) | `ItbBlobVersionTooNewException` | — |

Other status codes raise the base `ItbException`. Match on
`ex.Status` against `StatusCode.MacFailure` /
`StatusCode.SeedWidthMix` / etc. for non-typed paths:

```csharp
using Itb;

try
{
    using var mac = new Mac("nonsense", new byte[32]);
}
catch (ItbException ex) when (ex.Status == StatusCode.BadMac)
{
    Console.Error.WriteLine($"code={ex.Status} msg={ex.Message}");
}
```

Status codes are documented in `cmd/cshared/internal/capi/errors.go`
and exposed as public constants on `Itb.StatusCode` (e.g.
`StatusCode.MacFailure`, `StatusCode.SeedWidthMix`,
`StatusCode.BadHash`).

**Note:** empty plaintext / ciphertext is rejected by libitb itself
with `ItbException(StatusCode.EncryptFailed)` ("itb: empty data") on
every cipher entry point. Pass at least one byte.

### Status codes

| Code | Name | Description |
|---|---|---|
| 0 | `StatusCode.Ok` | Success — the only non-failure return value |
| 1 | `StatusCode.BadHash` | Unknown hash primitive name |
| 2 | `StatusCode.BadKeyBits` | ITB key width invalid for the chosen primitive |
| 3 | `StatusCode.BadHandle` | FFI handle invalid or already freed |
| 4 | `StatusCode.BadInput` | Generic shape / range / domain violation on a call argument |
| 5 | `StatusCode.BufferTooSmall` | Output buffer cap below required size; probe-then-allocate idiom |
| 6 | `StatusCode.EncryptFailed` | Encrypt path raised on the Go side (rare; structural / OOM) |
| 7 | `StatusCode.DecryptFailed` | Decrypt path raised on the Go side (corrupt ciphertext shape) |
| 8 | `StatusCode.SeedWidthMix` | Seeds passed to one call do not share the same native hash width |
| 9 | `StatusCode.BadMac` | Unknown MAC name or key-length violates the primitive's `MinKeyBytes` |
| 10 | `StatusCode.MacFailure` | MAC verification failed — tampered ciphertext or wrong MAC key |
| 11 | `StatusCode.EasyClosed` | Easy Mode encryptor call after `Close()` |
| 12 | `StatusCode.EasyMalformed` | Easy Mode `Import` blob fails JSON parse / structural check |
| 13 | `StatusCode.EasyVersionTooNew` | Easy Mode blob version field higher than this build supports |
| 14 | `StatusCode.EasyUnknownPrimitive` | Easy Mode blob references a primitive this build does not know |
| 15 | `StatusCode.EasyUnknownMac` | Easy Mode blob references a MAC this build does not know |
| 16 | `StatusCode.EasyBadKeyBits` | Easy Mode blob's `key_bits` invalid for its primitive |
| 17 | `StatusCode.EasyMismatch` | Easy Mode blob disagrees with the receiver on `primitive` / `key_bits` / `mode` / `mac`; field name on `ItbEasyMismatchException.Field` |
| 18 | `StatusCode.EasyLockSeedAfterEncrypt` | `SetLockSeed(1)` called after the first encrypt — must precede the first ciphertext |
| 19 | `StatusCode.BlobModeMismatch` | Native Blob importer received a Single blob into a Triple receiver (or vice versa) |
| 20 | `StatusCode.BlobMalformed` | Native Blob payload fails JSON parse / magic / structural check |
| 21 | `StatusCode.BlobVersionTooNew` | Native Blob version field higher than this libitb build supports |
| 22 | `StatusCode.BlobTooManyOpts` | Native Blob export opts mask carries unsupported bits |
| 23 | `StatusCode.StreamTruncated` | Streaming AEAD transcript truncated before the terminator chunk; raised as `ItbStreamTruncatedException` |
| 24 | `StatusCode.StreamAfterFinal` | Streaming AEAD transcript carries chunk bytes after the terminator; raised as `ItbStreamAfterFinalException` |
| 99 | `StatusCode.Internal` | Generic "internal" sentinel for paths the caller cannot recover from at the binding layer |

## Constraints

- **.NET 10 minimum.** Every project file under `bindings/csharp/`
  declares `<TargetFramework>net10.0</TargetFramework>`. Earlier
  runtimes lack the `Span<T>` / `Memory<T>` / `LibraryImport`
  generator ergonomics the wrapper layer depends on.
- **C# `latest` with nullable reference types.** Every project file
  declares `<LangVersion>latest</LangVersion>` and
  `<Nullable>enable</Nullable>`; consumers compile against the
  nullable-annotated public surface.
- **Single assembly.** All consumer-visible declarations live in the
  `Itb` namespace inside `Itb.dll`; the FFI substrate (`Itb.Sys`
  internal class) is kept separate so audits can read it
  independently.
- **libitb.so required at runtime.** The assembly loads
  `dist/<os>-<arch>/libitb.<ext>` via `NativeLibrary.Load`; the
  shared library must be built first and reachable through the
  loader's search path.
- **No external runtime deps beyond the .NET BCL + libitb.so.** The
  package depends only on the .NET 10 base class library; the test
  runner additionally requires `Microsoft.NET.Test.Sdk` + `xunit`.
- **Frozen C ABI.** The `ITB_*` exports declared inside
  `Itb.Sys.NativeMethods` (synced from `dist/<os>-<arch>/libitb.h`)
  are the contract; the binding does not extend or reshape them.

## API Overview

Every public symbol lives in the `Itb` namespace. The wrapper
(format-deniability outer cipher) surface is split into the
`Itb.Wrapper` namespace.

### Library metadata (`Itb.Library`)

| Symbol | Purpose |
|---|---|
| `Library.Version` | Library version `"<major>.<minor>.<patch>"` |
| `Library.MaxKeyBits` | Max supported ITB key width in bits |
| `Library.Channels` | Number of native channel slots |
| `Library.HeaderSize` | Current chunk header size in bytes |
| `Library.ParseChunkLen(ReadOnlySpan<byte> header) -> int` | Parse chunk header, return total on-wire chunk length |
| `Library.ListHashes() -> IReadOnlyList<HashInfo>` / `Library.ListMacs() -> IReadOnlyList<MacInfo>` | Catalogue accessors |
| `Library.LastError` / `Library.LastMismatchField` | Per-thread last-error message / Easy mismatch field name |

### Process-wide configuration (`Itb.Library`)

| Symbol | Purpose |
|---|---|
| `Library.BitSoup { get; set; }` | Bit Soup mode toggle |
| `Library.LockSoup { get; set; }` | Lock Soup mode toggle |
| `Library.MaxWorkers { get; set; }` | Worker pool cap |
| `Library.NonceBits { get; set; }` | Nonce width (128 / 256 / 512) |
| `Library.BarrierFill { get; set; }` | Barrier-fill factor |
| `long Library.SetMemoryLimit(long limit)` | Go runtime heap soft limit in bytes; pass negative to query only |
| `int Library.SetGcPercent(int pct)` | Go GC trigger percentage; pass negative to query only |

### Seeds and MAC

| Symbol | Purpose |
|---|---|
| `new Seed(string hashName, int keyBits)` | CSPRNG-fresh seed |
| `Seed.FromComponents(hashName, keyBits, components)` | Reconstruct from explicit components |
| `seed.Width / HashName / HashNameIntrospect() / GetHashKey() / GetComponents() / AttachLockSeed(lock)` | Introspection + lock-seed attachment |
| `new Mac(string macName, ReadOnlySpan<byte> key)` | Construct MAC handle |

### Low-level cipher (`Itb.Cipher`)

| Symbol | Purpose |
|---|---|
| `Cipher.Encrypt(noise, data, start, pt) -> byte[]` / `Cipher.Decrypt(...)` | Single Message |
| `Cipher.EncryptAuth(noise, data, start, mac, pt)` / `Cipher.DecryptAuth(...)` | MAC-authenticated counterparts |
| `Cipher.EncryptTriple(noise, d1, d2, d3, s1, s2, s3, pt)` / `Cipher.DecryptTriple(...)` | Triple Ouroboros |
| `Cipher.EncryptAuthTriple(...)` / `Cipher.DecryptAuthTriple(...)` | Triple Ouroboros MAC-authenticated |

### Easy Mode encryptor (`Itb.Encryptor`)

| Symbol | Purpose |
|---|---|
| `new Encryptor(primitive, keyBits, mac=null, mode="single")` | Single-primitive constructor |
| `Encryptor.Mixed(primitives, keyBits, mac=null)` / `Encryptor.Mixed3(primitives, keyBits, mac=null)` | Mixed-primitive Single / Triple |
| `enc.Encrypt(pt) / Decrypt(ct) / EncryptAuth(pt) / DecryptAuth(ct)` | Cipher entry points |
| `enc.SetNonceBits / SetBarrierFill / SetBitSoup / SetLockSoup / SetLockSeed / SetChunkSize` | Per-instance setters |
| `enc.Primitive / KeyBits / Mode / MacName / SeedCount / NonceBits / HeaderSize / IsMixed / HasPRFKeys / PrimitiveAt(slot)` | Accessors |
| `enc.PRFKey(slot) / MacKey() / SeedComponents(slot) / ParseChunkLen(header)` | Key-material + per-instance chunk-length parser |
| `enc.Export() / Import(blob)` | State-blob persistence |
| `Encryptor.PeekConfig(blob) -> EncryptorConfig` | Pre-import discriminator |
| `enc.EncryptStreamAuth(...) / DecryptStreamAuth(...)` | Easy Mode Streaming AEAD over `System.IO.Stream` |
| `enc.Close()` / `enc.Dispose()` | Close + release |

### Streaming AEAD (`Itb.Streams`)

| Symbol | Purpose |
|---|---|
| `new StreamEncryptor(noise, data, start, output, opts?)` / `new StreamDecryptor(noise, data, start, output)` | Push-style Low-Level Single |
| `new StreamEncryptorTriple(noise, d1, d2, d3, s1, s2, s3, output, opts?)` / `new StreamDecryptorTriple(...)` | Push-style Low-Level Triple |
| `StreamPipeline.EncryptStream / DecryptStream / EncryptStreamTriple / DecryptStreamTriple` | Free-function bridges (Low-Level No MAC) |
| `StreamPipeline.EncryptStreamAuth / DecryptStreamAuth / EncryptStreamAuthTriple / DecryptStreamAuthTriple` | Free-function bridges (Streaming AEAD) |
| `StreamDefaults.DefaultChunkSize` | Default streaming chunk size in bytes |

### Native Blob

| Symbol | Purpose |
|---|---|
| `new Blob128() / new Blob256() / new Blob512()` | Width-specific Native Blob handles |
| `blob.Width / Mode` | Width + mode accessors |
| `blob.SetKey / SetComponents / SetMacKey / SetMacName(...)` | Field setters |
| `blob.GetKey / GetComponents / GetMacKey / GetMacName(...)` | Field getters |
| `blob.Export(opts) / ExportTriple(opts) / Import(payload) / ImportTriple(payload)` | Serialisation |
| `BlobSlot.N / D / S / L / D1 / D2 / D3 / S1 / S2 / S3` | Slot enum |
| `BlobExportOpts.None / LockSeed / Mac` | Export opt-in flag bits |

### Wrapper (`Itb.Wrapper`)

| Symbol | Purpose |
|---|---|
| `Cipher.Aes128Ctr / ChaCha20 / SipHash24` | Cipher enum |
| `Wrapper.AllCiphers` | Canonical cipher list |
| `Wrapper.KeySize(cipher) / NonceSize(cipher)` | Cipher dimension accessors |
| `Wrapper.GenerateKey(cipher) -> byte[]` | CSPRNG-fresh wrapper key |
| `Wrapper.Wrap(cipher, key, blob) -> byte[]` / `Wrapper.Unwrap(cipher, key, wire) -> byte[]` | Single Message Wrap / Unwrap |
| `Wrapper.WrapInPlace(cipher, key, buf) -> byte[]` / `Wrapper.UnwrapInPlace(cipher, key, wire) -> Span<byte>` | In-place Wrap / Unwrap |
| `new WrapStreamWriter(cipher, key)` / `new UnwrapStreamReader(cipher, key, wireNonce)` | Streaming wrap writer / unwrap reader |
| `InvalidCipherException / InvalidKeyException / InvalidNonceException / WrapperHandleClosedException` | Typed exceptions |

### Error model

| Symbol | Purpose |
|---|---|
| `ItbException` | Base exception class; `.Code` carries the numeric status |
| `ItbEasyMismatchException / ItbBlobModeMismatchException / ItbBlobMalformedException / ItbBlobVersionTooNewException` | Typed subclasses for cold-path discriminators |
| `ItbStreamTruncatedException / ItbStreamAfterFinalException` | Streaming AEAD transcript-shape exceptions |
| `StatusCode` (enum) | Status-code surface |
