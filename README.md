# ITB C# Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). Source-generated P/Invoke (`[LibraryImport]`) with a
`DllImportResolver` — the `.so` / `.dylib` / `.dll` is resolved at
the first FFI call, no compile-time link. Every hash-name / MAC-name
/ cipher-name / profile-name is an opaque string passed through to
Go for validation; the binding carries no ITB construction logic.
The public surface is one `Pipeline` type (Init / Open / Rekey /
Close, Single Message encrypt / decrypt, one-shot and incremental
stream sessions with `System.IO.Stream` pumps), an `Opts`
query-string builder, `Pipeline.RegisterProfile`, and the Go runtime
knobs on `Runtime`. Native handles ride on `SafeHandle` subclasses,
so an undisposed Pipeline or stream session is reclaimed by the
finalizer; `IDisposable` gives the deterministic path.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go dotnet-sdk
```

Generic Linux / macOS: a Go toolchain plus the .NET SDK (net10.0
target framework). Windows: the same; libitb builds as `libitb.dll`.

## Build the shared library

The convenience driver builds `libitb.so` plus the four .NET
projects (library, tests, bench, eitb) in one step:

```bash
./bindings/csharp/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/csharp && dotnet build Itb.sln -c Release
```

## Library lookup order

1. `ITB_LIBITB_PATH` environment variable (path to the shared
   library file).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` located by walking up from
   the assembly directory (in-repo builds).
3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
   `DYLD_LIBRARY_PATH`, `PATH`).

## Usage example

```csharp
using Itb;

using var sender = Pipeline.Init("singlemsg-triple-mac-v1");
using var receiver = Pipeline.Open("singlemsg-triple-mac-v1", sender.Blob);

byte[] wire = sender.EncryptMessage("any text or binary data"u8);
byte[] plain = receiver.DecryptMessage(wire);
```

The `Opts` builder overrides the profile default per call (chunk
size, outer cipher, parallax on/off, wrapper on/off, MAC name,
palette):

```csharp
var opts = new Opts().WithChunkSize(65536).WithWrapper(false);
using var sender = Pipeline.Init("singlemsg-triple-mac-v1", opts);
using var receiver = Pipeline.Open("singlemsg-triple-mac-v1", sender.Blob, opts);
```

`Pipeline.Rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`sender.Blob` handshake:

```csharp
sender.Rekey(new byte[32] { /* fresh perm */ }, new byte[32] { /* fresh wrap */ });
using var receiver2 = Pipeline.Open("singlemsg-triple-mac-v1", sender.Blob);
```

For bounded-memory streaming, `EncryptStreamPump` /
`DecryptStreamPump` move any `System.IO.Stream` source into any
`System.IO.Stream` sink through an incremental session; the explicit
`BeginEncryptStream` / `BeginDecryptStream` sessions expose `Write`
/ `End` / `Read` for caller-driven loops.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as `ItbException` carrying
the `Status` code plus the `ITB_LastError` diagnostic.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```csharp
Itb.Runtime.SetMemoryLimit(512L * 1024 * 1024);
Itb.Runtime.SetGCPercent(20);
```

## Testing

```bash
./bindings/csharp/run_tests.sh
```

The harness builds `libitb.so`, exports `ITB_LIBITB_PATH`, and
invokes `dotnet test -c Release`. Positional arguments are forwarded
to dotnet test (e.g. `./run_tests.sh --filter
FullyQualifiedName~Smoke`). The suite covers Single Message round
trips per shipped profile, stream pumps, incremental sessions with
pathological batch sizes, tampered-wire failure stickiness,
mid-flight cancellation, rekey, profile registration, error mapping,
and Opts query rendering — surface parity checks; the deep suite
lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/csharp/run_bench.sh            # both shapes
./bindings/csharp/run_bench.sh message    # Single Message shape only
./bindings/csharp/run_bench.sh stream     # stream-pump shape only
```

`Stopwatch`-timed micro-benches: `EncryptMessage` and stream-pump
throughput at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven
by the `ITB_*` env vars listed in `Itb.Bench/BenchUtil.cs`; defaults
match the root Go BENCH3.md pin.

## eitb utility

The `Itb.Eitb` console project mirrors the shipped Go `tools/eitb`
scope for shell smoke tests:

```bash
cd bindings/csharp
dotnet run -c Release --project Itb.Eitb -- version
dotnet run -c Release --project Itb.Eitb -- hashes
dotnet run -c Release --project Itb.Eitb -- encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
dotnet run -c Release --project Itb.Eitb -- decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ItbException` may belong to a different
  call under concurrent FFI use. The status code is always
  attributable.
- `Rekey` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- libitb must be reachable at runtime through the lookup order
  above.
