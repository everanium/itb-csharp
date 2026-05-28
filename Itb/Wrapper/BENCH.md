# ITB C# Binding — Format-Deniability Wrapper Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of outer keystream ciphers, one per PRF-grade ITB registry primitive in CTR mode. The keystream construction is delegated libitb-side to the `ctr` package. The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `WrapInPlace` row mutates the caller's `Span<byte>` (no output-buffer allocation); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's streaming AEAD entry points or a User-Driven Loop emitting framed chunks through the wrapped writer.

The wrapper bench covers all outer ciphers — each in CTR mode.

Outer-cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `WrapInPlace` path avoids output-buffer allocation. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR splits across up to 32 worker goroutines (`min(32, GOMAXPROCS, chunks)`) inside libitb for buffers at or above the 256 KiB threshold, each worker seeking its own keystream to its chunk offset via `ctr.NewAt`; buffers below the threshold run serially.

The C# binding adds the per-call P/Invoke crossing and a fresh `byte[]` materialisation on the helper return path. The wrapper only row therefore reads slightly under the matching Go-native row at 16 MiB; the gap closes on the full ITB + wrapper rows, where the ITB encrypt / decrypt time dominates over the keystream XOR + P/Invoke overhead.

## Binding asymmetry note

The C# binding's Streaming No MAC arm covers the User-Driven Loop variant only — there is no `System.IO.Stream` adapter for the wrap layer in the Non-AEAD path. The Streaming AEAD path covers IO-Driven for both Easy and Low-Level.

## Reproduction

```sh
# Build libitb.so:
go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared

# Run the full 306-case sub-bench matrix:
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

* Outer cipher path: all PRF-grade registry primitives, keystream built libitb-side via the `ctr` package.
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `nonce_bits=128`, `barrier_fill=1`, `bit_soup=0`, `lock_soup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `Library.MaxWorkers = 0` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine pre-built copy each iteration via the `Wrap` (alloc) path; the cost is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware.

Column abbreviations in the Full ITB + wrapper tables: **LL** = Low-Level, **Loop** = User-Driven Loop, **IO** = IO-Driven, **NoMAC** = No MAC, **MAC** = MAC Authenticated, **Enc** / **Dec** = encrypt / decrypt direction. All throughput is MB/s, rounded.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (no output-buffer alloc) MB/s |
|---|---|---|
| **Areion-SoEM-256** | 1669 | 1736 |
| **Areion-SoEM-512** | 1696 | 1758 |
| **BLAKE2b-256** | 603 | 614 |
| **BLAKE2b-512** | 797 | 1054 |
| **BLAKE2s** | 650 | 652 |
| **BLAKE3** | 1096 | 1207 |
| **AES-128-CTR** | 2975 | 4279 |
| **SipHash-2-4** | 2230 | 2379 |
| **ChaCha20** | 2008 | 2232 |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 164 | 255 | 169 | 248 | 189 | 267 | 159 | 248 |
| **Areion-SoEM-512** | 189 | 271 | 174 | 253 | 190 | 269 | 168 | 245 |
| **BLAKE2b-256** | 168 | 232 | 159 | 214 | 170 | 229 | 159 | 215 |
| **BLAKE2b-512** | 184 | 255 | 166 | 241 | 183 | 243 | 167 | 233 |
| **BLAKE2s** | 176 | 237 | 159 | 222 | 167 | 234 | 160 | 220 |
| **BLAKE3** | 187 | 263 | 169 | 239 | 184 | 251 | 168 | 236 |
| **AES-128-CTR** | 198 | 285 | 180 | 261 | 195 | 277 | 179 | 255 |
| **SipHash-2-4** | 195 | 275 | 177 | 255 | 194 | 273 | 178 | 255 |
| **ChaCha20** | 191 | 265 | 175 | 258 | 187 | 265 | 174 | 252 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 259 | 295 | 225 | 286 | 246 | 285 | 224 | 272 |
| **Areion-SoEM-512** | 249 | 303 | 227 | 278 | 247 | 294 | 224 | 273 |
| **BLAKE2b-256** | 216 | 252 | 199 | 236 | 215 | 242 | 199 | 223 |
| **BLAKE2b-512** | 235 | 276 | 207 | 249 | 232 | 265 | 206 | 248 |
| **BLAKE2s** | 219 | 251 | 178 | 212 | 210 | 244 | 197 | 238 |
| **BLAKE3** | 242 | 289 | 173 | 261 | 239 | 281 | 207 | 268 |
| **AES-128-CTR** | 259 | 311 | 235 | 297 | 259 | 307 | 231 | 282 |
| **SipHash-2-4** | 256 | 311 | 230 | 292 | 254 | 304 | 227 | 281 |
| **ChaCha20** | 253 | 307 | 218 | 286 | 252 | 300 | 229 | 273 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 150 | 196 | 144 | 193 |
| **Areion-SoEM-512** | 147 | 183 | 145 | 197 |
| **BLAKE2b-256** | 136 | 169 | 141 | 176 |
| **BLAKE2b-512** | 151 | 194 | 149 | 190 |
| **BLAKE2s** | 144 | 161 | 141 | 175 |
| **BLAKE3** | 154 | 191 | 147 | 189 |
| **AES-128-CTR** | 155 | 201 | 146 | 200 |
| **SipHash-2-4** | 152 | 189 | 144 | 198 |
| **ChaCha20** | 155 | 196 | 151 | 195 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 177 | 243 | 168 | 232 |
| **Areion-SoEM-512** | 175 | 238 | 169 | 232 |
| **BLAKE2b-256** | 150 | 206 | 141 | 163 |
| **BLAKE2b-512** | 158 | 225 | 143 | 213 |
| **BLAKE2s** | 154 | 208 | 142 | 189 |
| **BLAKE3** | 162 | 228 | 149 | 222 |
| **AES-128-CTR** | 170 | 246 | 160 | 247 |
| **SipHash-2-4** | 168 | 242 | 172 | 243 |
| **ChaCha20** | 167 | 239 | 154 | 216 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 204 | 225 | 187 | 218 |
| **Areion-SoEM-512** | 199 | 232 | 189 | 220 |
| **BLAKE2b-256** | 176 | 200 | 169 | 192 |
| **BLAKE2b-512** | 190 | 220 | 177 | 209 |
| **BLAKE2s** | 175 | 202 | 171 | 194 |
| **BLAKE3** | 195 | 226 | 184 | 214 |
| **AES-128-CTR** | 203 | 241 | 193 | 225 |
| **SipHash-2-4** | 200 | 235 | 191 | 226 |
| **ChaCha20** | 202 | 234 | 193 | 224 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 216 | 251 | 187 | 256 |
| **Areion-SoEM-512** | 215 | 260 | 188 | 260 |
| **BLAKE2b-256** | 188 | 225 | 175 | 225 |
| **BLAKE2b-512** | 206 | 249 | 189 | 246 |
| **BLAKE2s** | 194 | 229 | 177 | 226 |
| **BLAKE3** | 200 | 255 | 191 | 250 |
| **AES-128-CTR** | 221 | 271 | 203 | 271 |
| **SipHash-2-4** | 216 | 265 | 200 | 266 |
| **ChaCha20** | 220 | 267 | 199 | 268 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
