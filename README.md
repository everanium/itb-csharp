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
The public surface is one `Pipeline` type (Init / Load / Save /
Rekey / Close, Single Message encrypt / decrypt, one-shot and
incremental stream sessions with `System.IO.Stream` pumps), an
`Opts` query-string builder, a `Profile` record with the registry
entries `Pipeline.Register` / `Lookup` / `Profiles` and the blob
reader `Pipeline.Inspect`, and the Go runtime knobs on `Runtime`. Native handles ride on `SafeHandle` subclasses,
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
using var receiver = Pipeline.Load(sender.Save());

byte[] wire = sender.EncryptMessage("any text or binary data"u8);
byte[] plain = receiver.DecryptMessage(wire);
// Or persist the session to disk and reopen it later:
//   sender.SaveF("/path/session.blob");
//   using var receiver = Pipeline.LoadF("/path/session.blob");
```

The `Opts` builder overrides the profile default at `Init` (chunk
size, outer cipher, parallax on/off, wrapper on/off, MAC name,
palette, `MaxWorkers`); the blob the receiver loads carries the
resolved shape, so `Load` takes no opts:

```csharp
var opts = new Opts().WithChunkSize(65536).WithWrapper(false);
using var sender = Pipeline.Init("singlemsg-triple-mac-v1", opts);
using var receiver = Pipeline.Load(sender.Save());
```

`Pipeline.Rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design) and returns the refreshed blob; the receiver picks up
the new masters through a fresh `Save()` / `Load` handshake:

```csharp
byte[] rotated = sender.Rekey(new byte[32] { /* fresh perm */ }, new byte[32] { /* fresh wrap */ });
using var receiver2 = Pipeline.Load(rotated);
```

For bounded-memory streaming, `EncryptStreamPump` /
`DecryptStreamPump` move any `System.IO.Stream` source into any
`System.IO.Stream` sink through an incremental session; the explicit
`BeginEncryptStream` / `BeginDecryptStream` sessions expose `Write`
/ `End` / `Read` for caller-driven loops.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as `ItbException` carrying
the `Status` code plus the `ITB_LastError` diagnostic.

## Persisting sessions

The blob `Save()` returns is self-describing: it carries the profile
record (the resolved pipeline shape) alongside the key material, so
a receiver reconstructs the session from the blob alone.

```csharp
byte[] blob = sender.Save();                    // current session blob
sender.SaveF("/path/session.blob");             // same bytes, written by the library (mode 0600)
using var a = Pipeline.Load(blob);              // reopen from bytes
using var b = Pipeline.LoadF("/path/session.blob"); // reopen from a file
using var c = Pipeline.Load(blob, perm, wrap);  // reopen with a master override
Profile p = Pipeline.Inspect(blob);             // metadata only, no Pipeline opened
```

Load works for blobs generated with shipped primitives (every entry
in the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to load such a blob through
this binding surfaces `Status.RecipePrimitiveUnknown`. A blob from an earlier wrap-layer
version surfaces `Status.BadInput`; a record that fails the profile field
rules surfaces `Status.BlobMalformedRecipe`.

The profile registry is reachable through the same `Profile`
record:

```csharp
string[] names = Pipeline.Profiles();           // sorted registry names
Profile shipped = Pipeline.Lookup("singlemsg-triple-nomac-v1");
var custom = new Profile
{
    Mode = "singlemsg-nomac", Width = 512, Hash = "areion512", KeyBits = 1024,
    Wrapper = false, Parallax = false,
};
Pipeline.Register("my-profile", custom);        // validated by Go; duplicate -> ProfileExists
```

`Profile` is a plain record plus JSON codec — no validation happens
on the binding side. `Inspect` / `Lookup` return it; `Register`
accepts it; an unknown name at `Init` / `Lookup` surfaces `Status.UnknownProfile`.

Runtime tuning: `pipeline.MaxWorkers(n)` sets the worker cap for every
subsequent cipher call (`n <= 0` selects auto, `n > 256` is clamped
to 256); the receiver may pick its own worker cap after `Load` — the
cap is per-machine and never written to the blob.

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
mid-flight cancellation, rekey, session persistence (save / load, saveF / loadF, inspect, lookup / profiles / register, maxWorkers), error mapping,
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

## Related — `itb3` CLI

The Go core ships an openssl-style CLI utility
[`itb3`](../../cmd/itb3/) that generates session blobs on disk
(`itb3 genblob <mode> <hash> -o blob.json`); this binding reopens
such blobs via `Pipeline.LoadF`. `itb3` also encrypts / decrypts
payloads directly on disk (`-i` / `-o`) or through stdin / stdout,
rotates outer masters, and inspects stored blobs. See
[`cmd/itb3/README.md`](../../cmd/itb3/README.md) for the full
subcommand reference.

## eitb utility

The `Itb.Eitb` console project mirrors the shipped Go `tools/eitb`
scope for shell smoke tests:

```bash
cd bindings/csharp
dotnet run -c Release --project Itb.Eitb -- version
dotnet run -c Release --project Itb.Eitb -- profiles
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
