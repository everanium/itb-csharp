# ITB C# / .NET Binding - Easy Mode Benchmark Results

Throughput (MB/s) of `Itb.Encryptor.Encrypt` / `Decrypt` /
`EncryptAuth` / `DecryptAuth` over the libitb c-shared library
through the `[LibraryImport]` + `NativeLibrary.SetDllImportResolver`
runtime FFI on .NET 10. Single + Triple Ouroboros at 1024-bit
ITB key width on a 16 MiB non-deterministic-fill payload, four
ops per primitive. The MAC slot is bound to **HMAC-BLAKE3** —
the lightest authenticated-mode overhead among the three shipping
MACs (the `EncryptAuth` row sits within a few percent of the
matching `Encrypt` row, and well below HMAC-SHA256's ~15 % and
KMAC-256's ~44 % overheads).

The harness lives in this directory; reproduction:

```bash
cd bindings/csharp
dotnet build -c Release
ITB_BENCH_MIN_SEC=5 dotnet run --project Itb.Bench -c Release -- single
ITB_BENCH_MIN_SEC=5 ITB_LOCKSEED=1 dotnet run --project Itb.Bench -c Release -- single
ITB_BENCH_MIN_SEC=5 dotnet run --project Itb.Bench -c Release -- triple
ITB_BENCH_MIN_SEC=5 ITB_LOCKSEED=1 dotnet run --project Itb.Bench -c Release -- triple
```

The default measurement window is 5 seconds per case
(`ITB_BENCH_MIN_SEC=5`), wide enough to absorb the cold-cache /
warm-up transient that distorts shorter windows on the 16 MiB
encrypt / decrypt path. `ITB_BENCH_FILTER=<substring>` narrows
the matrix to a single primitive when re-running an outlier in
isolation.

## FFI overhead vs. native Go

The C# path adds a `[LibraryImport]` source-generated marshalling
trampoline, the C ABI crossing into Go, and a result-copy from the
c-shared output buffer back into a `byte[]`. The binding caches a
per-encryptor output buffer and pre-allocates from a 1.25× upper
bound on the empirical ITB ciphertext-expansion factor (≤ 1.155
across every primitive / mode / nonce / payload-size combination)
so the hot loop avoids the size-probe round-trip the
process-global FFI helpers use. The cache is wiped on grow and on
`Dispose`, so residual ciphertext / plaintext cannot linger in
heap garbage between cipher calls.

The numbers below ride the default build (no opt-out tags). On
hosts without AVX-512+VL the Go side automatically nil-routes the
4-lane batched chain-absorb arm so the per-pixel hash falls
through to the upstream stdlib asm via the single Func — see the
build-tag table in [`../README.md`](../README.md) for the
`-tags=purego` / `-tags=noitbasm` opt-outs.

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode)

Recorded on Intel Core i7-11700K (Rocket Lake, AVX-512 + VAES,
8 cores / 16 threads, native Linux), .NET SDK 10.0.104, libitb
0.1.0 in c-shared mode.

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 71 | 175 | 170 | 257 |
| **Areion-SoEM-512** | 512 | PRF | 205 | 302 | 187 | 278 |
| **SipHash-2-4** | 128 | PRF | 152 | 196 | 144 | 189 |
| **AES-CMAC** | 128 | PRF | 190 | 265 | 174 | 246 |
| **BLAKE2b-512** | 512 | PRF | 138 | 168 | 127 | 163 |
| **BLAKE2b-256** | 256 | PRF | 96 | 111 | 91 | 107 |
| **BLAKE2s** | 256 | PRF | 101 | 118 | 94 | 117 |
| **BLAKE3** | 256 | PRF | 124 | 149 | 118 | 144 |
| **ChaCha20** | 256 | PRF | 111 | 132 | 107 | 125 |
| **Mixed** | 256 | PRF | 154 | 197 | 145 | 186 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 259 | 315 | 236 | 297 |
| **Areion-SoEM-512** | 512 | PRF | 275 | 323 | 248 | 311 |
| **SipHash-2-4** | 128 | PRF | 187 | 207 | 173 | 200 |
| **AES-CMAC** | 128 | PRF | 248 | 288 | 190 | 273 |
| **BLAKE2b-512** | 512 | PRF | 162 | 176 | 151 | 169 |
| **BLAKE2b-256** | 256 | PRF | 104 | 111 | 99 | 108 |
| **BLAKE2s** | 256 | PRF | 115 | 122 | 109 | 120 |
| **BLAKE3** | 256 | PRF | 142 | 154 | 134 | 149 |
| **ChaCha20** | 256 | PRF | 125 | 134 | 118 | 130 |
| **Mixed** | 256 | PRF | 140 | 152 | 132 | 143 |

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, LockSeed mode)

The dedicated lockSeed channel (`Encryptor.SetLockSeed(1)` /
`ITB_LOCKSEED=1`) auto-couples bit-soup + lock-soup on the
on-direction. Numbers below run with all three overlays active.

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 60 | 72 | 62 | 71 |
| **Areion-SoEM-512** | 512 | PRF | 52 | 58 | 50 | 57 |
| **SipHash-2-4** | 128 | PRF | 69 | 76 | 64 | 72 |
| **AES-CMAC** | 128 | PRF | 73 | 84 | 72 | 83 |
| **BLAKE2b-512** | 512 | PRF | 46 | 49 | 45 | 49 |
| **BLAKE2b-256** | 256 | PRF | 41 | 45 | 40 | 44 |
| **BLAKE2s** | 256 | PRF | 43 | 46 | 42 | 46 |
| **BLAKE3** | 256 | PRF | 43 | 46 | 42 | 45 |
| **ChaCha20** | 256 | PRF | 45 | 48 | 36 | 42 |
| **Mixed** | 256 | PRF | 45 | 48 | 43 | 47 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 59 | 64 | 60 | 62 |
| **Areion-SoEM-512** | 512 | PRF | 52 | 53 | 50 | 53 |
| **SipHash-2-4** | 128 | PRF | 69 | 73 | 67 | 72 |
| **AES-CMAC** | 128 | PRF | 76 | 68 | 67 | 72 |
| **BLAKE2b-512** | 512 | PRF | 44 | 46 | 43 | 45 |
| **BLAKE2b-256** | 256 | PRF | 39 | 41 | 40 | 41 |
| **BLAKE2s** | 256 | PRF | 43 | 43 | 42 | 43 |
| **BLAKE3** | 256 | PRF | 41 | 42 | 40 | 41 |
| **ChaCha20** | 256 | PRF | 46 | 47 | 38 | 40 |
| **Mixed** | 256 | PRF | 34 | 42 | 38 | 41 |

## Notes

- The first row in every Single-Ouroboros pass shows a transient
  asymmetry between encrypt and decrypt (e.g., Areion-SoEM-256
  encrypt 71 MB/s vs decrypt 175 MB/s in the no-LockSeed pass).
  This is the cold-cache + first-iteration warmup absorbed
  imperfectly even at 5-second windows; subsequent rows in the
  same pass run on warm caches and report symmetric
  encrypt-vs-decrypt numbers. Re-running the same primitive in
  isolation
  (`ITB_BENCH_FILTER=areion256 ITB_BENCH_MIN_SEC=20 dotnet run -- single`)
  normalises the asymmetry.
- The LockSeed arms cap throughput in the 40-80 MB/s band because
  the dedicated lockseed slot auto-engages BitSoup + LockSoup; the
  bit-level split + per-chunk PRF-keyed bit-permutation overlay
  together dominate the per-byte cost.
- Triple Ouroboros exceeds Single Ouroboros throughput on most
  primitives because the seven-seed split exposes additional
  internal parallelism opportunities to libitb's worker pool while
  the on-the-wire chunk count remains the same.
- Bench cases run sequentially per pass; libitb's internal worker
  pool (`Library.MaxWorkers = 0` → all CPUs) processes each case's
  chunk-level parallelism within the case's wall-clock window.
