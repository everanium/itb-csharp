# ITB C# Binding — Format-Deniability Wrapper

C#-idiomatic surface over the format-deniability wrapper exposed by libitb. Mirrors `github.com/everanium/itb/wrapper` structurally; the wire bytes produced by the C# helpers are byte-identical to the Go-native helpers under the same `(cipher, key, nonce)` tuple.

The runtime types live in the `Itb.Wrapper` namespace (`Wrapper.Wrap` / `Wrapper.Unwrap` / `WrapStreamWriter` / `UnwrapStreamReader`); this directory carries the example utility (`Itb.Eitb`), the benchmark sub-harness (`Itb.Bench/Wrapper/`), and the BENCH.md result table.

## Threat model

ITB encrypts content into RGBWYOPA pixel containers. The construction provides **content-deniability** unconditionally — no plaintext bit can be extracted from the wire. The wire pattern itself, however, is parseable by an observer who knows the ITB format:

- Non-AEAD path: per-chunk header carries width / height / container layout.
- Streaming AEAD path: a once per-stream 32-byte streamID prefix plus per-chunk `nonce || W || H || container || flag_byte`.

A passive observer who knows ITB ships with an 8-channel pixel container and a 32-byte streamID prefix can pattern-match the bytes. The format-deniability wrap hides that surface under a generic outer cipher: AES-128-CTR, ChaCha20 (RFC 8439), or SipHash-2-4 in CTR mode. After wrapping, the wire is `nonce || keystream-XOR(bytestream)` — the same shape used by countless other protocols. An observer sees a small leading nonce followed by pseudorandom-looking bytes; pattern-matching does not distinguish ITB from any other stream cipher payload.

This is **not** a random-oracle indistinguishability claim. It is a "looks like a different well-known cipher" claim. The wrap exists for format-deniability ONLY; ITB already provides confidentiality (content-deniability) and the AEAD path already provides per-stream and per-chunk integrity. The Non-AEAD streaming path has no integrity by design and the wrap does not add any.

## Wrapper API

The C# surface exposes Single Message helpers (immutable + in-place mutation) and a streaming class pair:

| Helper | Wire format | Use case |
|---|---|---|
| `Wrapper.Wrap` / `Wrapper.Unwrap` | `nonce \|\| keystream-XOR(blob)` | Single Message Encrypt / EncryptAuth output, immutable plaintext path. |
| `Wrapper.WrapInPlace` / `Wrapper.UnwrapInPlace` | same as `Wrap` / `Unwrap` | Single Message, zero-allocation steady state. Mutates the caller's `Span<byte>`. |
| `WrapStreamWriter` / `UnwrapStreamReader` | `nonce` + keystream-XOR(continuous bytestream) | streaming use — Streaming AEAD wraps the entire bytestream end-to-end; User-Driven Loop emits per-chunk caller-side framing (`u32_LE` length prefix) through the wrap-writer so the framing bytes also pass through the keystream XOR. |

The single keystream advances monotonically across all bytes within one wrap session. A fresh CSPRNG nonce is generated per session; emitted once at stream start; never reused across sessions. This is standard CTR mode usage — within one stream, one nonce + counter is correct.

No length-prefix or other framing byte appears in cleartext on the wire in any wrap shape. The User-Driven Loop emits length prefixes through the wrap-writer so they get XORed into the keystream alongside the chunk bodies.

### Binding asymmetry

The C# binding exposes Streaming AEAD via the `Encryptor.EncryptStreamAuth` / `DecryptStreamAuth` pair (Easy) and `StreamPipeline.EncryptStreamAuth` / `DecryptStreamAuth` (Low-Level), both consuming `System.IO.Stream` arguments. The Streaming No MAC path has **no** `System.IO.Stream` adapter for the wrap layer. This asymmetry is intentional. The Non-AEAD streaming arm in the C# wrapper covers the **User-Driven Loop** variant only — caller produces an ITB ciphertext per chunk via `enc.Encrypt(chunk)`, frames `u32_LE_len || ct`, and pushes through the streaming wrapper handle. See CLAUDE.md.

## Outer ciphers

| Cipher | Enum | Key | Nonce | Notes |
|---|---|---|---|---|
| AES-128-CTR | `Cipher.Aes128Ctr` (`"aes"`) | 16 B | 16 B | libitb stdlib path with AES-NI. |
| ChaCha20 (RFC 8439) | `Cipher.ChaCha20` (`"chacha"`) | 32 B | 12 B | `golang.org/x/crypto/chacha20`. No AES-NI dependency. |
| SipHash-2-4 in CTR mode | `Cipher.SipHash24` (`"siphash"`) | 16 B | 16 B | `github.com/dchest/siphash` PRF. Custom CTR construction; sound under standard PRF assumption. |

The SipHash-CTR construction:

- 16-byte SipHash key = wrapper key.
- 16-byte nonce split into `(nonce_hi, nonce_lo)` 64-bit halves.
- Each keystream block: `siphash.Hash(key, nonce_hi || (nonce_lo XOR counter_LE))` — 8-byte output, XORed with plaintext.
- Counter increments per block; nonce stays fixed for the stream.

## Quick Start

Code paths under `bindings/csharp/Itb.Eitb/Program.cs`. Run the matrix:

```sh
dotnet run --project Itb.Eitb -c Release
dotnet run --project Itb.Eitb -c Release -- --help
```

Below: `using Itb;` plus `using Itb.Wrapper;` (with `OuterCipher = Itb.Wrapper.Cipher`) is assumed. The `cipher` variable holds one of `Cipher.Aes128Ctr` / `Cipher.ChaCha20` / `Cipher.SipHash24`.

### 1. Streaming AEAD Easy (MAC Authenticated, IO-Driven)

ITB Call: `Encryptor.EncryptStreamAuth` / `DecryptStreamAuth`. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader` over the continuous bytestream ITB emits.

```csharp
using var enc = new Encryptor("areion512", 1024, "hmac-blake3", "single");
enc.SetNonceBits(512); enc.SetBarrierFill(4);
enc.SetBitSoup(1); enc.SetLockSoup(1);

var outerKey = Wrapper.GenerateKey(cipher);

// Sender
using var inner = new MemoryStream();
enc.EncryptStreamAuth(new MemoryStream(plaintext), inner, chunkSize: 16 * 1024);
using var ww = new WrapStreamWriter(cipher, outerKey);
using var wireBuf = new MemoryStream();
wireBuf.Write(ww.Nonce);
wireBuf.Write(ww.Update(inner.ToArray()));
var wire = wireBuf.ToArray();

// Receiver
var nlen = Wrapper.NonceSize(cipher);
using var ur = new UnwrapStreamReader(cipher, outerKey, wire.AsSpan(0, nlen));
var innerWire = ur.Update(wire.AsSpan(nlen));
using var outBuf = new MemoryStream();
enc.DecryptStreamAuth(new MemoryStream(innerWire), outBuf);
```

### 2. Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)

ITB Call: `StreamPipeline.EncryptStreamAuth` / `DecryptStreamAuth` with three explicit `Seed` handles plus a `Mac("hmac-blake3", key)` instance. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader`.

```csharp
var seeds = new[] { new Seed("areion512", 1024), new Seed("areion512", 1024), new Seed("areion512", 1024) };
using var mac = new Mac("hmac-blake3", RandomBytes(32));

var outerKey = Wrapper.GenerateKey(cipher);
using var inner = new MemoryStream();
StreamPipeline.EncryptStreamAuth(seeds[0], seeds[1], seeds[2], mac,
    new MemoryStream(plaintext), inner, chunkSize: 16 * 1024);
using var ww = new WrapStreamWriter(cipher, outerKey);
using var wireBuf = new MemoryStream();
wireBuf.Write(ww.Nonce);
wireBuf.Write(ww.Update(inner.ToArray()));
var wire = wireBuf.ToArray();

// Receiver
var nlen = Wrapper.NonceSize(cipher);
using var ur = new UnwrapStreamReader(cipher, outerKey, wire.AsSpan(0, nlen));
var innerWire = ur.Update(wire.AsSpan(nlen));
using var outBuf = new MemoryStream();
StreamPipeline.DecryptStreamAuth(seeds[0], seeds[1], seeds[2], mac,
    new MemoryStream(innerWire), outBuf);
```

### 3. Streaming Easy (No MAC, User-Driven Loop)

The "Alternative — User-Driven Loop" pattern: each chunk is one independent `enc.Encrypt(buf)` call. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader` driven by a caller loop that emits `u32_LE_len || ct` per chunk through the wrapped writer. Length prefix and chunk body both pass through the keystream XOR — no length appears in cleartext on the wire.

```csharp
using var enc = new Encryptor("areion512", 1024, mac: null, "single");
enc.SetNonceBits(512); enc.SetBarrierFill(4);
enc.SetBitSoup(1); enc.SetLockSoup(1);

var outerKey = Wrapper.GenerateKey(cipher);
using var ww = new WrapStreamWriter(cipher, outerKey);
using var wireBuf = new MemoryStream();
wireBuf.Write(ww.Nonce);
var off = 0;
while (off < plaintext.Length)
{
    var take = Math.Min(chunkSize, plaintext.Length - off);
    var ct = enc.Encrypt(plaintext.AsSpan(off, take));
    wireBuf.Write(ww.Update(BitConverter.GetBytes((uint)ct.Length)));
    wireBuf.Write(ww.Update(ct));
    off += take;
}
var wire = wireBuf.ToArray();

// Receiver — read u32_LE length then body through the unwrap-reader, looping until exhausted.
var nlen = Wrapper.NonceSize(cipher);
using var ur = new UnwrapStreamReader(cipher, outerKey, wire.AsSpan(0, nlen));
var decrypted = ur.Update(wire.AsSpan(nlen));
var pos = 0;
using var outBuf = new MemoryStream();
while (pos < decrypted.Length)
{
    var clen = (int)BitConverter.ToUInt32(decrypted, pos);
    pos += 4;
    var pt = enc.Decrypt(decrypted.AsSpan(pos, clen));
    outBuf.Write(pt);
    pos += clen;
}
```

### 4. Streaming Low-Level (No MAC, User-Driven Loop)

Per-chunk `Cipher.Encrypt` / `Cipher.Decrypt` with caller-side framing. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader`. Each chunk is emitted as `u32_LE_len || ct` through the wrap-writer; the length and the body both pass through the keystream XOR.

```csharp
var seeds = new[] { new Seed("areion512", 1024), new Seed("areion512", 1024), new Seed("areion512", 1024) };

var outerKey = Wrapper.GenerateKey(cipher);
using var ww = new WrapStreamWriter(cipher, outerKey);
using var wireBuf = new MemoryStream();
wireBuf.Write(ww.Nonce);
var off = 0;
while (off < plaintext.Length)
{
    var take = Math.Min(chunkSize, plaintext.Length - off);
    var ct = Itb.Cipher.Encrypt(seeds[0], seeds[1], seeds[2], plaintext.AsSpan(off, take));
    wireBuf.Write(ww.Update(BitConverter.GetBytes((uint)ct.Length)));
    wireBuf.Write(ww.Update(ct));
    off += take;
}
var wire = wireBuf.ToArray();
```

(Receiver mirrors example 3, swapping `enc.Decrypt` for `Itb.Cipher.Decrypt(seeds[0], seeds[1], seeds[2], …)`.)

### 5. Easy: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `enc.Encrypt(plaintext)` returns one ITB blob. Wrap shape: `Wrap` — `nonce || ks-XOR(blob)`. The `WrapInPlace` / `UnwrapInPlace` variant is shown — mutates the caller's `Span<byte>` in place to skip the steady-state allocation.

```csharp
using var enc = new Encryptor("areion512", 2048, mac: null, "single");
enc.SetNonceBits(512); enc.SetBarrierFill(4);
enc.SetBitSoup(1); enc.SetLockSoup(1);

var encrypted = enc.Encrypt(plaintext);

var outerKey = Wrapper.GenerateKey(cipher);
// Wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
// var wire = Wrapper.Wrap(cipher, outerKey, encrypted);
var nonce = Wrapper.WrapInPlace(cipher, outerKey, encrypted);
var wire = new byte[nonce.Length + encrypted.Length];
Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
Buffer.BlockCopy(encrypted, 0, wire, nonce.Length, encrypted.Length);

// Receiver — Unwrap respects immutability of `wire` (allocates a fresh recovered buffer):
// var recovered = Wrapper.Unwrap(cipher, outerKey, wire);
var recoveredSpan = Wrapper.UnwrapInPlace(cipher, outerKey, wire);
var pt = enc.Decrypt(recoveredSpan);
```

### 6. Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `enc.EncryptAuth` / `enc.DecryptAuth`. Wrap shape: `Wrap` (or `WrapInPlace`). The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

```csharp
using var enc = new Encryptor("areion512", 2048, "hmac-blake3", "single");
enc.SetNonceBits(512); enc.SetBarrierFill(4);
enc.SetBitSoup(1); enc.SetLockSoup(1);

var encrypted = enc.EncryptAuth(plaintext);

var outerKey = Wrapper.GenerateKey(cipher);
var nonce = Wrapper.WrapInPlace(cipher, outerKey, encrypted);
var wire = new byte[nonce.Length + encrypted.Length];
Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
Buffer.BlockCopy(encrypted, 0, wire, nonce.Length, encrypted.Length);

// Receiver
var recoveredSpan = Wrapper.UnwrapInPlace(cipher, outerKey, wire);
var pt = enc.DecryptAuth(recoveredSpan);
```

### 7. Low-Level: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `Itb.Cipher.Encrypt(seeds[0], seeds[1], seeds[2], plaintext)` / `Itb.Cipher.Decrypt(...)` with three explicit `Seed` handles. Wrap shape: `Wrap` (or `WrapInPlace`). Wire shape matches example 5; the difference is that the seed material is held by caller-side `Seed` handles rather than by an `Encryptor` instance.

```csharp
var seeds = new[] { new Seed("areion512", 2048), new Seed("areion512", 2048), new Seed("areion512", 2048) };

var encrypted = Itb.Cipher.Encrypt(seeds[0], seeds[1], seeds[2], plaintext);

var outerKey = Wrapper.GenerateKey(cipher);
var nonce = Wrapper.WrapInPlace(cipher, outerKey, encrypted);
var wire = new byte[nonce.Length + encrypted.Length];
Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
Buffer.BlockCopy(encrypted, 0, wire, nonce.Length, encrypted.Length);

// Receiver
var recoveredSpan = Wrapper.UnwrapInPlace(cipher, outerKey, wire);
var pt = Itb.Cipher.Decrypt(seeds[0], seeds[1], seeds[2], recoveredSpan);
```

### 8. Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `Itb.Cipher.EncryptAuth(*seeds, mac, plaintext)` / `Itb.Cipher.DecryptAuth(...)`. Wrap shape: `Wrap` (or `WrapInPlace`). The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

```csharp
var seeds = new[] { new Seed("areion512", 2048), new Seed("areion512", 2048), new Seed("areion512", 2048) };
using var mac = new Mac("hmac-blake3", RandomBytes(32));

var encrypted = Itb.Cipher.EncryptAuth(seeds[0], seeds[1], seeds[2], mac, plaintext);

var outerKey = Wrapper.GenerateKey(cipher);
var nonce = Wrapper.WrapInPlace(cipher, outerKey, encrypted);
var wire = new byte[nonce.Length + encrypted.Length];
Buffer.BlockCopy(nonce, 0, wire, 0, nonce.Length);
Buffer.BlockCopy(encrypted, 0, wire, nonce.Length, encrypted.Length);

// Receiver
var recoveredSpan = Wrapper.UnwrapInPlace(cipher, outerKey, wire);
var pt = Itb.Cipher.DecryptAuth(seeds[0], seeds[1], seeds[2], mac, recoveredSpan);
```

## Verification matrix

Every example × cipher combination round-trips against random plaintext (1 KiB for Single Message, 64 KiB for streaming) with sha256 byte-equality. Sample run:

```
[PASS] aead-easy-io               + aes        pt=65536 wire=90208
[PASS] aead-easy-io               + chacha     pt=65536 wire=90204
[PASS] aead-easy-io               + siphash    pt=65536 wire=90208
[PASS] aead-lowlevel-io           + aes        pt=65536 wire=90208
[PASS] aead-lowlevel-io           + chacha     pt=65536 wire=90204
[PASS] aead-lowlevel-io           + siphash    pt=65536 wire=90208
[PASS] noaead-easy-userloop       + aes        pt=65536 wire=90192
[PASS] noaead-easy-userloop       + chacha     pt=65536 wire=90188
[PASS] noaead-easy-userloop       + siphash    pt=65536 wire=90192
[PASS] noaead-lowlevel-userloop   + aes        pt=65536 wire=90192
[PASS] noaead-lowlevel-userloop   + chacha     pt=65536 wire=90188
[PASS] noaead-lowlevel-userloop   + siphash    pt=65536 wire=90192
[PASS] message-easy-nomac         + aes        pt=1024 wire=4316
[PASS] message-easy-nomac         + chacha     pt=1024 wire=4312
[PASS] message-easy-nomac         + siphash    pt=1024 wire=4316
[PASS] message-easy-auth          + aes        pt=1024 wire=8276
[PASS] message-easy-auth          + chacha     pt=1024 wire=8272
[PASS] message-easy-auth          + siphash    pt=1024 wire=8276
[PASS] message-lowlevel-nomac     + aes        pt=1024 wire=4316
[PASS] message-lowlevel-nomac     + chacha     pt=1024 wire=4312
[PASS] message-lowlevel-nomac     + siphash    pt=1024 wire=4316
[PASS] message-lowlevel-auth      + aes        pt=1024 wire=8276
[PASS] message-lowlevel-auth      + chacha     pt=1024 wire=8272
[PASS] message-lowlevel-auth      + siphash    pt=1024 wire=8276

=== Summary: 24 PASS, 0 FAIL ===
```

The wire-byte difference between cipher columns is exactly the per-stream nonce-size delta (16 vs 12 vs 16 bytes); the User-Driven Loop variants additionally include 4 bytes of keystream-XORed length prefix per chunk.

## Performance

Bench numbers across Single Ouroboros and Triple Ouroboros, message and streaming, encrypt and decrypt (split sub-benches) are tracked in [BENCH.md](BENCH.md).

## Notes on outer cipher key management

The wrapper itself does not address outer key distribution; the example utility generates a fresh CSPRNG outer key per run for self-test purposes. In a real deployment the outer key is shared out-of-band (or derived via a separate key-exchange step) and is independent of the ITB seed material. The ITB state blob already carries the inner cipher's keying material; the outer key is the additional piece both endpoints need.

The outer key MAY be reused across many streams provided each stream uses a fresh CSPRNG nonce — this is the standard CTR mode safety contract. The wrapper helpers always generate a fresh nonce internally, so caller-side discipline is reduced to "do not reuse the same `(key, nonce)` across distinct streams" — a contract the helper enforces by construction.

## What this is not

- Not an integrity layer. The outer cipher is unauthenticated by design — adding a MAC at this layer would defeat the format-deniability goal (the resulting wire would pattern-match an AEAD construction's tag-bearing format, not a generic stream cipher). Use the ITB AEAD path when integrity is required.
- Not a substitute for ITB's content-deniability. ITB still provides the unconditional content-deniability; the wrap adds format-deniability on top.
