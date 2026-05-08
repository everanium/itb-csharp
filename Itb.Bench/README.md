# ITB C# / .NET Binding - Easy Mode Benchmark

A single executable (`Itb.Bench`) covers the Easy Mode encryption /
decryption surface exposed by the C# / .NET binding through a
subcommand dispatcher:

* `dotnet run -- single` — Single Ouroboros (mode=1, 3 seeds + optional
  dedicated lockSeed). Walks the nine PRF-grade primitives plus one
  mixed-primitive variant.
* `dotnet run -- triple` — Triple Ouroboros (mode=3, 7 seeds + optional
  dedicated lockSeed). Same nine + one mixed grid as the single
  subcommand.

Both passes pin **1024-bit ITB key width** and **16 MiB CSPRNG-filled
payload**, run four ops per case (`Encrypt`, `Decrypt`, `EncryptAuth`,
`DecryptAuth`), and emit a Go-bench-style line per case
(`name iters ns/op MB/s`).

The harness is a custom Go-bench-style runner in `Common.cs` (no
`BenchmarkDotNet` dependency — `System.Diagnostics.Stopwatch` and
`System.Security.Cryptography.RandomNumberGenerator` cover the
random-fill and timing surfaces). The `Program.cs` entry point
dispatches to `BenchSingle.Run` or `BenchTriple.Run`. The bench
project references the binding via `<ProjectReference Include="..\Itb\Itb.csproj" />`,
so the same `Itb.Native.SetDllImportResolver` runtime path resolution
that ships with the binding is in scope here.

## Prerequisites

Build the shared library once and restore the .NET dependencies (see
the binding [README](../README.md)):

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/csharp && dotnet restore
```

A project-private opt-out tag is available when the 4-lane
chain-absorb wrapper is dead weight (hosts without AVX-512+VL). The
tag disables only the chain-absorb asm; upstream stdlib asm stays
engaged so the per-pixel single Func runs at upstream-asm speed via
`process_cgo`'s nil-`BatchHash` fallback:

```bash
go build -trimpath -tags=noitbasm -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

The C# binding loads `libitb.so` / `.dll` / `.dylib` at runtime
through `NativeLibrary.SetDllImportResolver`, picking it up from
`ITB_LIBRARY_PATH`, `<repo>/dist/<os>-<arch>/`, or the system loader
path; see `bindings/csharp/Itb/Native/NativeLibraryLoader.cs` for the
full search list.

## Run

From the binding root (`bindings/csharp/`):

```bash
dotnet run --project Itb.Bench -c Release -- single
dotnet run --project Itb.Bench -c Release -- triple
```

`-c Release` is mandatory — the JIT's debug-mode bounds checks /
loss of inlining shifts every per-iter wall-clock measurement by
2–3×, so the default Debug configuration would systematically
under-report throughput.

## Environment variables

| Variable             | Default | Purpose |
|----------------------|---------|---------|
| `ITB_NONCE_BITS`     | `128`   | Process-wide nonce width — `128`, `256`, or `512`. Maps to `Library.NonceBits` before any `Encryptor` is constructed. Mirrors `ITB_NONCE_BITS` from `bitbyte_test.go`. |
| `ITB_LOCKSEED`       | unset   | When set to a non-empty / non-`0` value, every encryptor in the run calls `Encryptor.SetLockSeed(1)` AND `Library.LockSoup` is set to `1` at start. Easy Mode auto-couples `SetBitSoup(1)` + `SetLockSoup(1)`, so no separate flags are needed. The mixed-primitive cases attach a dedicated lockSeed primitive (via `primL`) only under this flag; otherwise `primL` is `null` so the no-LockSeed bench arm measures the plain mixed-primitive cost. |
| `ITB_BENCH_FILTER`   | unset   | Case-insensitive substring filter on bench-case names — only cases whose name contains the filter are run. Useful when iterating on one primitive / op. |
| `ITB_BENCH_MIN_SEC`  | `5.0`   | Minimum measured wall-clock seconds per case. The runner keeps doubling iteration count until the measured batch reaches the threshold, mirroring Go's `-benchtime=Ns`. The 5-second default absorbs the cold-cache / warm-up transient that distorts shorter measurement windows on the 16 MiB encrypt / decrypt path. |

Worker count is fixed at `Library.MaxWorkers = 0` (auto-detect),
matching the Go bench default.

## Examples

Whole grid, default settings (128-bit nonces, no lockSeed):

```bash
dotnet run --project Itb.Bench -c Release -- single
```

512-bit nonces with the dedicated lockSeed channel + auto-coupled
overlay:

```bash
ITB_NONCE_BITS=512 ITB_LOCKSEED=1 \
    dotnet run --project Itb.Bench -c Release -- triple
```

Just the BLAKE3 row of the Single grid:

```bash
ITB_BENCH_FILTER=blake3_1024bit \
    dotnet run --project Itb.Bench -c Release -- single
```

Only the encrypt-with-MAC ops across every primitive in the Triple
grid, with a longer 10-second per-case budget for tighter
confidence intervals:

```bash
ITB_BENCH_FILTER=encrypt_auth_16mb ITB_BENCH_MIN_SEC=10 \
    dotnet run --project Itb.Bench -c Release -- triple
```

Just the mixed-primitive cases on the Single side:

```bash
ITB_BENCH_FILTER=mixed \
    dotnet run --project Itb.Bench -c Release -- single
```

## Output format

```
# easy_single primitives=9 key_bits=1024 mac=hmac-blake3 nonce_bits=128 lockseed=off workers=auto
# benchmarks=40 payload_bytes=16777216 min_seconds=5
bench_single_aescmac_1024bit_encrypt_16mb               4    493210110.0 ns/op    32.44 MB/s
bench_single_aescmac_1024bit_decrypt_16mb               4    488104225.0 ns/op    32.78 MB/s
...
```

The four columns are:

1. Bench-case name (matches the `BenchmarkSingle*` / `BenchmarkTriple*`
   Go cohort, snake-cased and without the `Ext` infix that the Go
   side carries for namespace reasons).
2. Iteration count chosen to reach `ITB_BENCH_MIN_SEC`.
3. Per-iter wall-clock cost in nanoseconds.
4. Throughput in MiB/s, derived from `payload_bytes / ns_per_op`.

Comparison with the Go bench cohort goes via `(MB/s ratio)` — the
throughput column is the most direct cross-language signal for how
much overhead the C# binding adds on top of the underlying libitb
call path.

## Expected runtime

At the default `ITB_BENCH_MIN_SEC=5`, each pass walks 40 cases (9
single-primitive + 1 mixed × 4 ops) and converges per case in 5–15
wall-clock seconds depending on the primitive's per-byte cost. A
full pass therefore lands at 5–10 minutes; the four canonical
passes (Single ±LockSeed, Triple ±LockSeed) fill BENCH.md in
~30 minutes of total wall-clock time. Filter to a single primitive
(`ITB_BENCH_FILTER=blake3_1024bit`) for ~1-minute spot-check runs.

## Recorded results

A snapshot of the four canonical pass results (Single + Triple,
each with and without `ITB_LOCKSEED=1`) on Intel Core i7-11700K is
collected in [BENCH.md](BENCH.md). The same file briefly discusses
the FFI overhead the binding leaves on top of the native Go path
through `[LibraryImport]` source-generated marshalling.
