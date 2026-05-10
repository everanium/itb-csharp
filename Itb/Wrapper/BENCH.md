# ITB C# Binding — Format-Deniability Wrapper Benchmark Results

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of three outer keystream ciphers — AES-128-CTR (libitb-side stdlib AES-NI path), ChaCha20 (RFC8439) (`golang.org/x/crypto/chacha20`), or SipHash-2-4 in CTR mode (`dchest/siphash` PRF + custom counter loop). The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `WrapInPlace` row mutates the caller's `Span<byte>` (zero-allocation steady state on the wrap path); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's streaming AEAD entry points or a User-Driven Loop emitting framed chunks through the wrapped writer.

Outer-cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `WrapInPlace` path adds no allocation pressure. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR runs single-threaded on one core. ChaCha20 (~700 MB/s peak on a single core via `x/crypto/chacha20`) and SipHash-CTR (~250-280 MB/s peak via the `dchest/siphash` PRF + 8-byte refill loop) become the bottleneck once ITB's Triple decrypt path approaches ~1 GB/s on big-iron. AES-128-CTR retains hardware acceleration on every HT thread the goroutine lands on and stays out of the critical path even there.

The C# binding adds the per-call P/Invoke crossing and a fresh `byte[]` materialisation on the helper return path. The wrapper only row therefore reads slightly under the matching Go-native row at 16 MiB; the gap closes on the full ITB + wrapper rows, where the ITB encrypt / decrypt time dominates over the keystream XOR + P/Invoke overhead.

## Binding asymmetry note

The C# binding's Streaming No MAC arm covers the User-Driven Loop variant only — there is no `System.IO.Stream` adapter for the wrap layer in the Non-AEAD path. The Streaming AEAD path covers IO-Driven for both Easy and Low-Level. See the "Binding asymmetry" section in [README.md](README.md).

## Reproduction

```sh
# Build libitb.so:
go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared

# Run the full 102-case sub-bench matrix:
cd bindings/csharp
LD_LIBRARY_PATH="$(cd ../.. && pwd)/dist/linux-amd64" \
    dotnet run --project Itb.Bench -c Release -- wrapper
```

Filter examples:

```sh
ITB_BENCH_FILTER=BenchmarkWrapperOnly \
    LD_LIBRARY_PATH="$(cd ../.. && pwd)/dist/linux-amd64" \
    dotnet run --project Itb.Bench -c Release -- wrapper

ITB_BENCH_FILTER=BenchmarkMessageSingle/easy-nomac \
    LD_LIBRARY_PATH="$(cd ../.. && pwd)/dist/linux-amd64" \
    dotnet run --project Itb.Bench -c Release -- wrapper

ITB_BENCH_FILTER=BenchmarkStreamingTriple \
    LD_LIBRARY_PATH="$(cd ../.. && pwd)/dist/linux-amd64" \
    dotnet run --project Itb.Bench -c Release -- wrapper
```

## Configuration

* Outer cipher path: AES-128-CTR / ChaCha20 (RFC8439) / SipHash-2-4 in CTR mode (libitb-side).
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `nonce_bits=128`, `barrier_fill=1`, `bit_soup=0`, `lock_soup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `Library.MaxWorkers = 0` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine pre-built copy each iteration via the `Wrap` (alloc) path; the cost is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (zero alloc) MB/s |
|---|---|---|
| **AES-128-CTR** | 2036 | **2948** |
| **ChaCha20** | 310 | **322** |
| **SipHash-CTR** | 264 | **268** |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 182 | 257 | 141 | 186 | 135 | 173 |
| **Easy** MAC Authenticated | 170 | 247 | 134 | 177 | 128 | 164 |
| **Low-Level** No MAC | 177 | 252 | 140 | 180 | 134 | 171 |
| **Low-Level** MAC Authenticated | 169 | 235 | 131 | 174 | 129 | 164 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 245 | 290 | 177 | 199 | 167 | 188 |
| **Easy** MAC Authenticated | 221 | 268 | 164 | 194 | 156 | 180 |
| **Low-Level** No MAC | 240 | 280 | 169 | 198 | 165 | 173 |
| **Low-Level** MAC Authenticated | 218 | 264 | 164 | 189 | 155 | 176 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 147 | 185 | 123 | 147 | 121 | 140 |
| **Streaming AEAD Low-Level** IO-Driven | 150 | 191 | 120 | 145 | 117 | 139 |
| **Streaming Easy** No MAC, User-Driven Loop | 168 | 230 | 125 | 161 | 124 | 155 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 163 | 225 | 130 | 167 | 123 | 154 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 195 | 217 | 143 | 165 | 144 | 153 |
| **Streaming AEAD Low-Level** IO-Driven | 195 | 218 | 149 | 158 | 140 | 151 |
| **Streaming Easy** No MAC, User-Driven Loop | 211 | 253 | 159 | 181 | 148 | 168 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 210 | 251 | 158 | 179 | 152 | 168 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
