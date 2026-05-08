// File-like streaming wrappers over the one-shot ITB encrypt / decrypt
// API.
//
// ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
// container size limit). Streaming larger payloads simply means slicing
// the input into chunks at the binding layer, encrypting each chunk
// through the regular FFI path, and concatenating the results. The
// reverse operation walks a concatenated chunk stream by reading the
// chunk header, calling <see cref="Library.ParseChunkLen"/> to learn
// the chunk's body length, reading that many bytes, and decrypting the
// single chunk.
//
// Both class-based wrappers (<see cref="StreamEncryptor"/> /
// <see cref="StreamDecryptor"/> and their Triple Ouroboros counterparts
// <see cref="StreamEncryptorTriple"/> / <see cref="StreamDecryptorTriple"/>)
// and the convenience helpers (<see cref="EncryptStream"/> /
// <see cref="DecryptStream"/> plus the Triple variants) are provided.
// Memory peak per call is bounded by <c>chunkSize</c> (default 16 MiB
// — see <see cref="DefaultChunkSize"/>), regardless of the total
// payload length.
//
// The Triple Ouroboros (7-seed) variants share the same I/O contract
// and only differ in the seed list passed to the constructor.
//
// Threading caveat. Do not change <see cref="Library.NonceBits"/>
// between writes on the same stream. The chunks are encrypted under
// the active nonce-size at the moment each chunk is flushed; switching
// nonce-bits mid-stream produces a chunk header layout the paired
// decryptor (which snapshots <see cref="Library.HeaderSize"/> at
// construction) cannot parse.
//
// Lifecycle. Stream wrappers do NOT take ownership of the underlying
// <see cref="System.IO.Stream"/>. The caller retains responsibility for
// closing / disposing the wrapped stream after the wrapper is itself
// disposed.

using System.IO;
using Itb.Native;

namespace Itb;

/// <summary>
/// Streaming-related defaults and convenience helpers.
/// </summary>
public static class StreamDefaults
{
    /// <summary>
    /// Default chunk size — matches <c>itb.DefaultChunkSize</c> on the
    /// Go side (16 MiB), the size at which ITB's barrier-encoded
    /// container layout stays well within the per-chunk pixel cap.
    /// </summary>
    public const int DefaultChunkSize = 16 * 1024 * 1024;
}

/// <summary>
/// Chunked encrypt writer over a Single Ouroboros seed trio. Buffers
/// plaintext until at least <c>chunkSize</c> bytes are available, then
/// encrypts and emits one chunk to the wrapped output stream. The
/// trailing partial buffer is flushed as a final chunk on
/// <see cref="Close"/> / <see cref="Dispose"/>, so the on-the-wire
/// chunk count is <c>ceil(total / chunkSize)</c>.
/// </summary>
/// <remarks>
/// <para>The wrapped <see cref="Stream"/> is NOT disposed when this
/// writer is disposed; the caller retains ownership of the underlying
/// stream's lifecycle.</para>
/// <para><b>Thread-safety contract.</b> The buffer-and-emit state
/// machine is not safe to invoke concurrently from multiple threads.
/// Sharing one <see cref="StreamEncryptor"/> across threads requires
/// external synchronisation.</para>
/// </remarks>
public sealed class StreamEncryptor : IDisposable
{
    private readonly Seed _noise;
    private readonly Seed _data;
    private readonly Seed _start;
    private readonly Stream _output;
    private readonly int _chunkSize;
    private readonly List<byte> _buf = new();
    private bool _closed;

    /// <summary>
    /// Constructs a fresh stream encryptor wrapping the given output
    /// stream. <paramref name="chunkSize"/> must be positive.
    /// </summary>
    public StreamEncryptor(Seed noise, Seed data, Seed start, Stream output,
        int chunkSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(output);
        if (chunkSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "chunkSize must be positive");
        }
        _noise = noise;
        _data = data;
        _start = start;
        _output = output;
        _chunkSize = chunkSize;
    }

    /// <summary>
    /// Appends <paramref name="data"/> to the internal buffer,
    /// encrypting and emitting every full <c>chunkSize</c>-sized slice
    /// that becomes available. Returns the number of bytes consumed
    /// (always equal to <c>data.Length</c> on success).
    /// </summary>
    public int Write(ReadOnlySpan<byte> data)
    {
        if (_closed)
        {
            throw new ItbException(StatusCode.EasyClosed, "write on closed StreamEncryptor");
        }
        for (var i = 0; i < data.Length; i++)
        {
            _buf.Add(data[i]);
        }
        while (_buf.Count >= _chunkSize)
        {
            var chunk = new byte[_chunkSize];
            _buf.CopyTo(0, chunk, 0, _chunkSize);
            // Zero the consumed prefix so plaintext does not linger in
            // the List's backing-array region the RemoveRange slide
            // vacates.
            for (var i = 0; i < _chunkSize; i++) { _buf[i] = 0; }
            _buf.RemoveRange(0, _chunkSize);
            var ct = Cipher.Encrypt(_noise, _data, _start, chunk);
            _output.Write(ct, 0, ct.Length);
            Array.Clear(chunk, 0, chunk.Length);
        }
        return data.Length;
    }

    /// <summary>
    /// Encrypts and emits any remaining buffered bytes as the final
    /// chunk. Idempotent — a second call is a no-op.
    /// </summary>
    public void Close()
    {
        if (_closed)
        {
            return;
        }
        if (_buf.Count > 0)
        {
            var chunk = _buf.ToArray();
            for (var i = 0; i < _buf.Count; i++) { _buf[i] = 0; }
            _buf.Clear();
            var ct = Cipher.Encrypt(_noise, _data, _start, chunk);
            _output.Write(ct, 0, ct.Length);
            Array.Clear(chunk, 0, chunk.Length);
        }
        _closed = true;
    }

    /// <summary>
    /// Calls <see cref="Close"/> if it has not been called yet.
    /// Releases nothing else — the wrapped output stream remains the
    /// caller's responsibility.
    /// </summary>
    public void Dispose()
    {
        Close();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Chunked decrypt writer over a Single Ouroboros seed trio.
/// Accumulates ciphertext bytes via <see cref="Feed"/> until a full
/// chunk (header plus body) is available, then decrypts the chunk and
/// writes the plaintext to the wrapped output stream. Multiple full
/// chunks in one feed call are processed sequentially.
/// </summary>
/// <remarks>
/// <para>The wrapped <see cref="Stream"/> is NOT disposed when this
/// writer is disposed.</para>
/// <para><b>Thread-safety contract.</b> The buffer-and-emit state
/// machine is not safe to invoke concurrently from multiple threads.
/// Sharing one <see cref="StreamDecryptor"/> across threads requires
/// external synchronisation.</para>
/// </remarks>
public sealed class StreamDecryptor : IDisposable
{
    private readonly Seed _noise;
    private readonly Seed _data;
    private readonly Seed _start;
    private readonly Stream _output;
    private readonly List<byte> _buf = new();
    private readonly int _headerSize;
    private bool _closed;

    /// <summary>
    /// Constructs a fresh stream decryptor wrapping the given output
    /// stream. The chunk-header size is snapshotted at construction so
    /// the decryptor uses the same header layout the matching encryptor
    /// saw — changing <see cref="Library.NonceBits"/> mid-stream would
    /// break decoding anyway.
    /// </summary>
    public StreamDecryptor(Seed noise, Seed data, Seed start, Stream output)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(output);
        _noise = noise;
        _data = data;
        _start = start;
        _output = output;
        _headerSize = Library.HeaderSize;
    }

    /// <summary>
    /// Appends <paramref name="data"/> to the internal buffer and
    /// drains every complete chunk that has become available, writing
    /// decrypted plaintext to the output stream. Returns the number of
    /// bytes consumed (always equal to <c>data.Length</c> on success).
    /// </summary>
    public int Feed(ReadOnlySpan<byte> data)
    {
        if (_closed)
        {
            throw new ItbException(StatusCode.EasyClosed, "feed on closed StreamDecryptor");
        }
        for (var i = 0; i < data.Length; i++)
        {
            _buf.Add(data[i]);
        }
        Drain();
        return data.Length;
    }

    private void Drain()
    {
        // Header buffer is allocated once on the heap to keep the
        // stack-frame footprint independent of how many chunks are
        // drained per call (analyser CA2014 — no stackalloc in a loop).
        var header = new byte[_headerSize];
        while (true)
        {
            if (_buf.Count < _headerSize)
            {
                return;
            }
            for (var i = 0; i < _headerSize; i++)
            {
                header[i] = _buf[i];
            }
            var chunkLen = Library.ParseChunkLen(header);
            if (_buf.Count < chunkLen)
            {
                return;
            }
            var chunk = new byte[chunkLen];
            _buf.CopyTo(0, chunk, 0, chunkLen);
            _buf.RemoveRange(0, chunkLen);
            var pt = Cipher.Decrypt(_noise, _data, _start, chunk);
            _output.Write(pt, 0, pt.Length);
            Array.Clear(pt, 0, pt.Length);
        }
    }

    /// <summary>
    /// Finalises the decryptor. Throws when leftover bytes do not form
    /// a complete chunk — streaming ITB ciphertext cannot have a
    /// half-chunk tail.
    /// </summary>
    public void Close()
    {
        if (_closed)
        {
            return;
        }
        if (_buf.Count > 0)
        {
            throw new InvalidOperationException(
                $"StreamDecryptor: trailing {_buf.Count} bytes do not form a complete chunk");
        }
        _closed = true;
    }

    /// <summary>
    /// Marks the decryptor closed. Suppresses the half-chunk-tail check
    /// performed by <see cref="Close"/> because <see cref="IDisposable"/>
    /// has no path to surface errors; callers who need to detect a
    /// half-chunk tail must call <see cref="Close"/> explicitly.
    /// </summary>
    public void Dispose()
    {
        _closed = true;
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Triple Ouroboros (7-seed) counterpart of
/// <see cref="StreamEncryptor"/>.
/// </summary>
/// <remarks>
/// <para>The wrapped <see cref="Stream"/> is NOT disposed when this
/// writer is disposed.</para>
/// <para><b>Thread-safety contract.</b> The buffer-and-emit state
/// machine is not safe to invoke concurrently from multiple threads.
/// Sharing one <see cref="StreamEncryptorTriple"/> across threads
/// requires external synchronisation.</para>
/// </remarks>
public sealed class StreamEncryptorTriple : IDisposable
{
    private readonly Seed _noise;
    private readonly Seed _data1;
    private readonly Seed _data2;
    private readonly Seed _data3;
    private readonly Seed _start1;
    private readonly Seed _start2;
    private readonly Seed _start3;
    private readonly Stream _output;
    private readonly int _chunkSize;
    private readonly List<byte> _buf = new();
    private bool _closed;

    /// <summary>Constructs a fresh Triple Ouroboros stream encryptor.
    /// <paramref name="chunkSize"/> must be positive.</summary>
    public StreamEncryptorTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Stream output,
        int chunkSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data1);
        ArgumentNullException.ThrowIfNull(data2);
        ArgumentNullException.ThrowIfNull(data3);
        ArgumentNullException.ThrowIfNull(start1);
        ArgumentNullException.ThrowIfNull(start2);
        ArgumentNullException.ThrowIfNull(start3);
        ArgumentNullException.ThrowIfNull(output);
        if (chunkSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "chunkSize must be positive");
        }
        _noise = noise;
        _data1 = data1;
        _data2 = data2;
        _data3 = data3;
        _start1 = start1;
        _start2 = start2;
        _start3 = start3;
        _output = output;
        _chunkSize = chunkSize;
    }

    /// <summary>Appends <paramref name="data"/> to the internal buffer,
    /// encrypting and emitting every full <c>chunkSize</c>-sized slice
    /// that becomes available.</summary>
    public int Write(ReadOnlySpan<byte> data)
    {
        if (_closed)
        {
            throw new ItbException(StatusCode.EasyClosed, "write on closed StreamEncryptorTriple");
        }
        for (var i = 0; i < data.Length; i++)
        {
            _buf.Add(data[i]);
        }
        while (_buf.Count >= _chunkSize)
        {
            var chunk = new byte[_chunkSize];
            _buf.CopyTo(0, chunk, 0, _chunkSize);
            for (var i = 0; i < _chunkSize; i++) { _buf[i] = 0; }
            _buf.RemoveRange(0, _chunkSize);
            var ct = Cipher.EncryptTriple(_noise, _data1, _data2, _data3,
                _start1, _start2, _start3, chunk);
            _output.Write(ct, 0, ct.Length);
            Array.Clear(chunk, 0, chunk.Length);
        }
        return data.Length;
    }

    /// <summary>Encrypts and emits any remaining buffered bytes as the
    /// final chunk. Idempotent.</summary>
    public void Close()
    {
        if (_closed)
        {
            return;
        }
        if (_buf.Count > 0)
        {
            var chunk = _buf.ToArray();
            for (var i = 0; i < _buf.Count; i++) { _buf[i] = 0; }
            _buf.Clear();
            var ct = Cipher.EncryptTriple(_noise, _data1, _data2, _data3,
                _start1, _start2, _start3, chunk);
            _output.Write(ct, 0, ct.Length);
            Array.Clear(chunk, 0, chunk.Length);
        }
        _closed = true;
    }

    /// <summary>Calls <see cref="Close"/> if not already called.</summary>
    public void Dispose()
    {
        Close();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Triple Ouroboros (7-seed) counterpart of
/// <see cref="StreamDecryptor"/>.
/// </summary>
/// <remarks>
/// <para>The wrapped <see cref="Stream"/> is NOT disposed when this
/// writer is disposed.</para>
/// <para><b>Thread-safety contract.</b> The buffer-and-emit state
/// machine is not safe to invoke concurrently from multiple threads.
/// Sharing one <see cref="StreamDecryptorTriple"/> across threads
/// requires external synchronisation.</para>
/// </remarks>
public sealed class StreamDecryptorTriple : IDisposable
{
    private readonly Seed _noise;
    private readonly Seed _data1;
    private readonly Seed _data2;
    private readonly Seed _data3;
    private readonly Seed _start1;
    private readonly Seed _start2;
    private readonly Seed _start3;
    private readonly Stream _output;
    private readonly List<byte> _buf = new();
    private readonly int _headerSize;
    private bool _closed;

    /// <summary>Constructs a fresh Triple Ouroboros stream
    /// decryptor.</summary>
    public StreamDecryptorTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Stream output)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data1);
        ArgumentNullException.ThrowIfNull(data2);
        ArgumentNullException.ThrowIfNull(data3);
        ArgumentNullException.ThrowIfNull(start1);
        ArgumentNullException.ThrowIfNull(start2);
        ArgumentNullException.ThrowIfNull(start3);
        ArgumentNullException.ThrowIfNull(output);
        _noise = noise;
        _data1 = data1;
        _data2 = data2;
        _data3 = data3;
        _start1 = start1;
        _start2 = start2;
        _start3 = start3;
        _output = output;
        _headerSize = Library.HeaderSize;
    }

    /// <summary>Appends <paramref name="data"/> to the internal buffer
    /// and drains every complete chunk that has become available.</summary>
    public int Feed(ReadOnlySpan<byte> data)
    {
        if (_closed)
        {
            throw new ItbException(StatusCode.EasyClosed, "feed on closed StreamDecryptorTriple");
        }
        for (var i = 0; i < data.Length; i++)
        {
            _buf.Add(data[i]);
        }
        Drain();
        return data.Length;
    }

    private void Drain()
    {
        // Header buffer is allocated once on the heap to keep the
        // stack-frame footprint independent of how many chunks are
        // drained per call (analyser CA2014 — no stackalloc in a loop).
        var header = new byte[_headerSize];
        while (true)
        {
            if (_buf.Count < _headerSize)
            {
                return;
            }
            for (var i = 0; i < _headerSize; i++)
            {
                header[i] = _buf[i];
            }
            var chunkLen = Library.ParseChunkLen(header);
            if (_buf.Count < chunkLen)
            {
                return;
            }
            var chunk = new byte[chunkLen];
            _buf.CopyTo(0, chunk, 0, chunkLen);
            _buf.RemoveRange(0, chunkLen);
            var pt = Cipher.DecryptTriple(_noise, _data1, _data2, _data3,
                _start1, _start2, _start3, chunk);
            _output.Write(pt, 0, pt.Length);
            Array.Clear(pt, 0, pt.Length);
        }
    }

    /// <summary>Finalises the decryptor. Throws when leftover bytes do
    /// not form a complete chunk.</summary>
    public void Close()
    {
        if (_closed)
        {
            return;
        }
        if (_buf.Count > 0)
        {
            throw new InvalidOperationException(
                $"StreamDecryptorTriple: trailing {_buf.Count} bytes do not form a complete chunk");
        }
        _closed = true;
    }

    /// <summary>Marks the decryptor closed without raising on partial
    /// input.</summary>
    public void Dispose()
    {
        _closed = true;
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Convenience helpers wrapping the streaming class APIs as one-shot
/// read-encrypt-write / read-decrypt-write pipelines.
/// </summary>
public static class StreamPipeline
{
    /// <summary>
    /// Reads plaintext from <paramref name="input"/> until end of
    /// stream, encrypts in chunks of <paramref name="chunkSize"/>, and
    /// writes concatenated ITB chunks to <paramref name="output"/>.
    /// Neither stream is disposed by this method.
    /// </summary>
    public static void EncryptStream(
        Seed noise, Seed data, Seed start,
        Stream input, Stream output,
        int chunkSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (chunkSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "chunkSize must be positive");
        }
        using var enc = new StreamEncryptor(noise, data, start, output, chunkSize);
        var buf = new byte[chunkSize];
        while (true)
        {
            var n = input.Read(buf, 0, buf.Length);
            if (n == 0)
            {
                break;
            }
            enc.Write(buf.AsSpan(0, n));
        }
        enc.Close();
        Array.Clear(buf, 0, buf.Length);
    }

    /// <summary>
    /// Reads concatenated ITB chunks from <paramref name="input"/>
    /// until end of stream and writes the recovered plaintext to
    /// <paramref name="output"/>. Neither stream is disposed by this
    /// method.
    /// </summary>
    public static void DecryptStream(
        Seed noise, Seed data, Seed start,
        Stream input, Stream output,
        int readSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (readSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "readSize must be positive");
        }
        using var dec = new StreamDecryptor(noise, data, start, output);
        var buf = new byte[readSize];
        while (true)
        {
            var n = input.Read(buf, 0, buf.Length);
            if (n == 0)
            {
                break;
            }
            dec.Feed(buf.AsSpan(0, n));
        }
        dec.Close();
    }

    /// <summary>Triple Ouroboros (7-seed) counterpart of
    /// <see cref="EncryptStream"/>.</summary>
    public static void EncryptStreamTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Stream input, Stream output,
        int chunkSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (chunkSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "chunkSize must be positive");
        }
        using var enc = new StreamEncryptorTriple(noise, data1, data2, data3,
            start1, start2, start3, output, chunkSize);
        var buf = new byte[chunkSize];
        while (true)
        {
            var n = input.Read(buf, 0, buf.Length);
            if (n == 0)
            {
                break;
            }
            enc.Write(buf.AsSpan(0, n));
        }
        enc.Close();
        Array.Clear(buf, 0, buf.Length);
    }

    /// <summary>Triple Ouroboros (7-seed) counterpart of
    /// <see cref="DecryptStream"/>.</summary>
    public static void DecryptStreamTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Stream input, Stream output,
        int readSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (readSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "readSize must be positive");
        }
        using var dec = new StreamDecryptorTriple(noise, data1, data2, data3,
            start1, start2, start3, output);
        var buf = new byte[readSize];
        while (true)
        {
            var n = input.Read(buf, 0, buf.Length);
            if (n == 0)
            {
                break;
            }
            dec.Feed(buf.AsSpan(0, n));
        }
        dec.Close();
    }

    // ----------------------------------------------------------------
    // Authenticated streaming (Streaming AEAD)
    // ----------------------------------------------------------------

    /// <summary>
    /// Reads plaintext from <paramref name="input"/> until end of
    /// stream, encrypts each chunk under the Streaming AEAD
    /// construction (Single Ouroboros + MAC), and writes the
    /// concatenated <c>stream_id || chunk_0 || chunk_1 || ...</c>
    /// transcript to <paramref name="output"/>. Neither stream is
    /// disposed by this method.
    /// </summary>
    public static void EncryptStreamAuth(
        Seed noise, Seed data, Seed start, Mac mac,
        Stream input, Stream output,
        int chunkSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (chunkSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "chunkSize must be positive");
        }
        using var enc = new StreamEncryptorAuth(noise, data, start, mac, output, chunkSize);
        var buf = new byte[chunkSize];
        while (true)
        {
            var n = input.Read(buf, 0, buf.Length);
            if (n == 0)
            {
                break;
            }
            enc.Write(buf.AsSpan(0, n));
        }
        enc.Close();
        Array.Clear(buf, 0, buf.Length);
    }

    /// <summary>
    /// Reads a Streaming AEAD transcript from <paramref name="input"/>
    /// until end of stream and writes the recovered plaintext to
    /// <paramref name="output"/>. Surfaces <see cref="ItbException"/>
    /// with status <see cref="StatusCode.BadInput"/> when the input
    /// exhausts mid-prefix (incomplete 32-byte stream-id header),
    /// <see cref="ItbStreamTruncatedException"/> when the prefix is
    /// fully observed but no terminating chunk arrives,
    /// <see cref="ItbStreamAfterFinalException"/> when bytes follow
    /// the terminator, and <see cref="ItbException"/> with status
    /// <see cref="StatusCode.MacFailure"/> on any per-chunk MAC
    /// mismatch. Neither stream is disposed by this method.
    /// </summary>
    public static void DecryptStreamAuth(
        Seed noise, Seed data, Seed start, Mac mac,
        Stream input, Stream output,
        int readSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (readSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "readSize must be positive");
        }
        using var dec = new StreamDecryptorAuth(noise, data, start, mac, output);
        var buf = new byte[readSize];
        while (true)
        {
            var n = input.Read(buf, 0, buf.Length);
            if (n == 0)
            {
                break;
            }
            dec.Feed(buf.AsSpan(0, n));
        }
        dec.Close();
    }

    /// <summary>Triple Ouroboros (7-seed) counterpart of
    /// <see cref="EncryptStreamAuth"/>.</summary>
    public static void EncryptStreamAuthTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Mac mac,
        Stream input, Stream output,
        int chunkSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (chunkSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "chunkSize must be positive");
        }
        using var enc = new StreamEncryptorAuthTriple(
            noise, data1, data2, data3, start1, start2, start3, mac, output, chunkSize);
        var buf = new byte[chunkSize];
        while (true)
        {
            var n = input.Read(buf, 0, buf.Length);
            if (n == 0)
            {
                break;
            }
            enc.Write(buf.AsSpan(0, n));
        }
        enc.Close();
        Array.Clear(buf, 0, buf.Length);
    }

    /// <summary>Triple Ouroboros (7-seed) counterpart of
    /// <see cref="DecryptStreamAuth"/>.</summary>
    public static void DecryptStreamAuthTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Mac mac,
        Stream input, Stream output,
        int readSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (readSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "readSize must be positive");
        }
        using var dec = new StreamDecryptorAuthTriple(
            noise, data1, data2, data3, start1, start2, start3, mac, output);
        var buf = new byte[readSize];
        while (true)
        {
            var n = input.Read(buf, 0, buf.Length);
            if (n == 0)
            {
                break;
            }
            dec.Feed(buf.AsSpan(0, n));
        }
        dec.Close();
    }
}

// --------------------------------------------------------------------
// Streaming AEAD class wrappers — Single + Triple Ouroboros + MAC.
// --------------------------------------------------------------------

/// <summary>
/// Internal helpers for the authenticated streaming wrappers — CSPRNG
/// stream_id generation, per-chunk dispatch, big-endian header parse.
/// </summary>
internal static unsafe class StreamAuthInternal
{
    public const int StreamIdLen = 32;

    /// <summary>
    /// Generates a CSPRNG-fresh 32-byte Streaming AEAD anchor by
    /// piggybacking on libitb's own CSPRNG: <c>ITB_NewSeedFromComponents</c>
    /// with hashKey=null triggers a CSPRNG draw on the Go side, and
    /// <c>ITB_GetSeedHashKey</c> reads back the 32-byte fixed key
    /// under the blake3 primitive. The seed handle is freed before
    /// returning; only the 32 random bytes survive.
    /// </summary>
    public static byte[] GenerateStreamId()
    {
        var comps = stackalloc ulong[8] { 1, 2, 3, 4, 5, 6, 7, 8 };
        nuint handle;
        int rc = ItbNative.ITB_NewSeedFromComponents(
            "blake3", comps, 8, null, 0, out handle);
        ItbException.Check(rc);
        var sid = new byte[StreamIdLen];
        try
        {
            nuint outLen;
            int rc2;
            fixed (byte* p = sid)
            {
                rc2 = ItbNative.ITB_GetSeedHashKey(handle, p, (nuint)StreamIdLen, out outLen);
            }
            int freeRc = ItbNative.ITB_FreeSeed(handle);
            ItbException.Check(rc2);
            ItbException.Check(freeRc);
            if ((int)outLen != StreamIdLen)
            {
                throw new ItbException(StatusCode.Internal,
                    "stream_id CSPRNG draw returned wrong byte count");
            }
        }
        catch
        {
            // Best-effort handle release on failure path.
            _ = ItbNative.ITB_FreeSeed(handle);
            throw;
        }
        return sid;
    }

    public static int ReadBe16(byte[] buf, int off)
    {
        return ((int)buf[off] << 8) | (int)buf[off + 1];
    }
}

/// <summary>
/// Authenticated chunked-encrypt writer (Single Ouroboros + MAC).
/// Buffers plaintext until at least <c>chunkSize</c> bytes are
/// available, then drains one full chunk per FFI call. Each chunk is
/// bound to the running
/// <c>(stream_id, cumulative_pixel_offset, final_flag)</c> tuple
/// inside the MAC closure. The 32-byte CSPRNG <c>stream_id</c> prefix
/// is generated at construction and emitted to the wrapped output on
/// the first <see cref="Write"/> / <see cref="Close"/> call.
/// </summary>
/// <remarks>
/// <para>The wrapped <see cref="Stream"/> is NOT disposed when this
/// writer is disposed.</para>
/// <para><b>Thread-safety contract.</b> The buffer-and-emit state
/// machine is not safe to invoke concurrently from multiple
/// threads.</para>
/// </remarks>
public sealed class StreamEncryptorAuth : IDisposable
{
    private readonly Seed _noise;
    private readonly Seed _data;
    private readonly Seed _start;
    private readonly Mac _mac;
    private readonly Stream _output;
    private readonly int _chunkSize;
    private readonly int _width;
    private readonly int _headerSize;
    private readonly byte[] _streamId;
    // Contiguous staging buffer — sized to chunkSize + 1 so a single
    // byte beyond the chunk boundary can sit there as the deferred-final
    // probe. When _filled exceeds _chunkSize the leading _chunkSize
    // bytes are emitted as non-terminal and the trailing residue
    // (_filled - _chunkSize bytes) is shifted to staging[0]. On Close
    // the residue is emitted as the terminating chunk.
    private readonly byte[] _staging;
    private int _filled;
    private ulong _cumPixels;
    private bool _closed;
    private bool _prefixEmitted;
    // Per-stream output buffer cache for the per-chunk dispatcher
    // (Bonus 1b in .NEXTBIND.md §7.1) — mirrors the per-encryptor
    // _outputBuffer field on Encryptor but lives on the streaming
    // class instance. Grown on demand by StreamAuthCipher.EmitSingle
    // with the same wipe-on-grow + 1.25× + 128 KiB envelope shape as
    // Encryptor.CipherCall; reused across every chunk's invocation.
    private byte[] _outBuf = Array.Empty<byte>();

    /// <summary>
    /// Constructs a fresh authenticated stream encryptor.
    /// <paramref name="chunkSize"/> must be positive. The 32-byte
    /// CSPRNG <c>stream_id</c> prefix is generated here; it is
    /// emitted on the first <see cref="Write"/> / <see cref="Close"/>
    /// call.
    /// </summary>
    public StreamEncryptorAuth(
        Seed noise, Seed data, Seed start, Mac mac,
        Stream output,
        int chunkSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(mac);
        ArgumentNullException.ThrowIfNull(output);
        if (chunkSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "chunkSize must be positive");
        }
        _noise = noise;
        _data = data;
        _start = start;
        _mac = mac;
        _output = output;
        _chunkSize = chunkSize;
        _width = noise.Width;
        _headerSize = Library.HeaderSize;
        _streamId = StreamAuthInternal.GenerateStreamId();
        // chunkSize + 1 holds the deferred-final probe byte.
        _staging = new byte[chunkSize + 1];
    }

    private void EmitPrefix()
    {
        if (!_prefixEmitted)
        {
            _output.Write(_streamId, 0, _streamId.Length);
            _prefixEmitted = true;
        }
    }

    private void EmitOne(int plaintextLen, bool finalFlag)
    {
        var (ctBuf, ctLen) = StreamAuthCipher.EmitSingle(
            _width, _noise, _data, _start, _mac,
            _staging, plaintextLen, _streamId, _cumPixels, finalFlag,
            ref _outBuf);
        if (ctLen >= _headerSize)
        {
            var w = StreamAuthInternal.ReadBe16(ctBuf, _headerSize - 4);
            var h = StreamAuthInternal.ReadBe16(ctBuf, _headerSize - 2);
            _cumPixels += (ulong)w * (ulong)h;
        }
        _output.Write(ctBuf, 0, ctLen);
    }

    /// <summary>
    /// Wipes the per-stream output buffer cache. Mirrors the
    /// wipe-on-Dispose discipline on
    /// <see cref="Encryptor.WipeOutputBuffer"/>; called from
    /// <see cref="Close"/> / <see cref="Dispose"/> so the most recent
    /// chunk's ciphertext does not linger in heap garbage past stream
    /// teardown.
    /// </summary>
    private void WipeOutBuf()
    {
        if (_outBuf.Length > 0)
        {
            Array.Clear(_outBuf, 0, _outBuf.Length);
        }
    }

    /// <summary>
    /// Appends <paramref name="data"/> to the internal buffer.
    /// Drains every completed-but-not-final chunk to the sink. The
    /// terminating chunk is emitted only by <see cref="Close"/>.
    /// </summary>
    public int Write(ReadOnlySpan<byte> data)
    {
        if (_closed)
        {
            throw new ItbException(StatusCode.EasyClosed,
                "write on closed StreamEncryptorAuth");
        }
        EmitPrefix();
        var consumed = 0;
        while (consumed < data.Length)
        {
            // Fill staging up to chunkSize + 1 bytes (the +1 is the
            // deferred-final probe).
            var room = _staging.Length - _filled;
            var take = Math.Min(room, data.Length - consumed);
            data.Slice(consumed, take).CopyTo(
                new Span<byte>(_staging, _filled, take));
            _filled += take;
            consumed += take;
            // Keep at least one chunk's worth buffered until Close()
            // so the deferred-final pattern can decide whether to emit
            // final_flag = true. Only emit when more than _chunkSize
            // bytes are present (one byte past the boundary).
            if (_filled > _chunkSize)
            {
                EmitOne(_chunkSize, false);
                // Shift residue (the trailing _filled - _chunkSize
                // bytes) to staging[0]; wipe consumed prefix.
                var residue = _filled - _chunkSize;
                if (residue > 0)
                {
                    Buffer.BlockCopy(_staging, _chunkSize, _staging, 0, residue);
                }
                Array.Clear(_staging, residue, _staging.Length - residue);
                _filled = residue;
            }
        }
        return data.Length;
    }

    /// <summary>
    /// Emits the residual buffer as the terminating chunk and
    /// finalises the stream. Idempotent.
    /// </summary>
    public void Close()
    {
        if (_closed)
        {
            WipeOutBuf();
            return;
        }
        EmitPrefix();
        EmitOne(_filled, true);
        Array.Clear(_staging, 0, _staging.Length);
        _filled = 0;
        WipeOutBuf();
        _closed = true;
    }

    /// <summary>Calls <see cref="Close"/> if it has not been called
    /// yet.</summary>
    public void Dispose()
    {
        Close();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Authenticated chunked-decrypt writer (Single Ouroboros + MAC).
/// Reads the 32-byte <c>stream_id</c> prefix once, then drains every
/// complete chunk available in the internal buffer. Each chunk is
/// verified under the running cumulative pixel offset and recovered
/// <c>final_flag</c>.
/// </summary>
/// <remarks>
/// <para>The wrapped <see cref="Stream"/> is NOT disposed when this
/// writer is disposed.</para>
/// <para>An incomplete 32-byte prefix at <see cref="Close"/> surfaces
/// as <see cref="ItbException"/> with status
/// <see cref="StatusCode.BadInput"/> (wire-level malformation).
/// Missing terminator after a fully observed prefix surfaces from
/// <see cref="Close"/> as <see cref="ItbStreamTruncatedException"/>;
/// trailing bytes after the terminator surface from
/// <see cref="Feed"/> / <see cref="Close"/> as
/// <see cref="ItbStreamAfterFinalException"/>. Tampered transcript
/// or wrong MAC key surfaces as <see cref="ItbException"/> with
/// status <see cref="StatusCode.MacFailure"/>.</para>
/// </remarks>
public sealed class StreamDecryptorAuth : IDisposable
{
    private readonly Seed _noise;
    private readonly Seed _data;
    private readonly Seed _start;
    private readonly Mac _mac;
    private readonly Stream _output;
    private readonly int _width;
    private readonly int _headerSize;
    private readonly byte[] _streamId = new byte[StreamAuthInternal.StreamIdLen];
    private int _sidHave;
    // Contiguous accumulator — _accum[_accumStart.._accumEnd) holds
    // the unparsed wire bytes belonging to chunks not yet consumed.
    // Slides via a head index (_accumStart) instead of List<byte>.
    // RemoveRange; compacts when the head crosses half-way through
    // the buffer to bound memory.
    private byte[] _accum;
    private int _accumStart;
    private int _accumEnd;
    private ulong _cumPixels;
    private bool _seenFinal;
    private bool _closed;
    // Per-stream output buffer cache for the per-chunk dispatcher
    // (Bonus 1b in .NEXTBIND.md §7.1) — mirrors the per-encryptor
    // _outputBuffer field on Encryptor but lives on the streaming
    // class instance. Grown on demand by StreamAuthCipher.ConsumeSingle
    // with the same wipe-on-grow + 1.25× + 128 KiB envelope shape as
    // Encryptor.CipherCall; reused across every chunk's invocation.
    private byte[] _outBuf = Array.Empty<byte>();

    /// <summary>
    /// Constructs a fresh authenticated stream decryptor.
    /// </summary>
    public StreamDecryptorAuth(
        Seed noise, Seed data, Seed start, Mac mac,
        Stream output)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(mac);
        ArgumentNullException.ThrowIfNull(output);
        _noise = noise;
        _data = data;
        _start = start;
        _mac = mac;
        _output = output;
        _width = noise.Width;
        _headerSize = Library.HeaderSize;
        // 1 MiB initial capacity — same floor as the Easy Mode driver
        // (Encryptor.DecryptStreamAuth) so cross-binding behaviour
        // matches.
        _accum = new byte[1 << 20];
    }

    private void Drain()
    {
        while (true)
        {
            if (_seenFinal)
            {
                if (_accumEnd - _accumStart > 0)
                {
                    throw new ItbStreamAfterFinalException(
                        StatusCode.StreamAfterFinal,
                        "auth stream: trailing bytes after terminator");
                }
                return;
            }
            if (_accumEnd - _accumStart < _headerSize)
            {
                return;
            }
            var chunkLen = Library.ParseChunkLen(
                new ReadOnlySpan<byte>(_accum, _accumStart, _headerSize));
            if (_accumEnd - _accumStart < chunkLen)
            {
                return;
            }
            var w = StreamAuthInternal.ReadBe16(_accum, _accumStart + _headerSize - 4);
            var h = StreamAuthInternal.ReadBe16(_accum, _accumStart + _headerSize - 2);
            var pixels = (ulong)w * (ulong)h;
            var chunk = new byte[chunkLen];
            Buffer.BlockCopy(_accum, _accumStart, chunk, 0, chunkLen);
            _accumStart += chunkLen;
            // Compact when the head drifts past half the buffer
            // — keeps the live region near offset 0 so subsequent
            // Feed calls can append without growing.
            if (_accumStart > _accum.Length / 2)
            {
                var live = _accumEnd - _accumStart;
                if (live > 0)
                {
                    Buffer.BlockCopy(_accum, _accumStart, _accum, 0, live);
                }
                Array.Clear(_accum, live, _accum.Length - live);
                _accumStart = 0;
                _accumEnd = live;
            }
            var (ptBuf, ptLen, ff) = StreamAuthCipher.ConsumeSingle(
                _width, _noise, _data, _start, _mac,
                chunk, chunk.Length, _streamId, _cumPixels,
                ref _outBuf);
            _output.Write(ptBuf, 0, ptLen);
            Array.Clear(ptBuf, 0, ptLen);
            _cumPixels += pixels;
            if (ff)
            {
                _seenFinal = true;
            }
        }
    }

    /// <summary>
    /// Wipes the per-stream output buffer cache. Mirrors the
    /// wipe-on-Dispose discipline on
    /// <see cref="Encryptor.WipeOutputBuffer"/>; called from
    /// <see cref="Close"/> / <see cref="Dispose"/> so the most recent
    /// chunk's plaintext does not linger in heap garbage past stream
    /// teardown.
    /// </summary>
    private void WipeOutBuf()
    {
        if (_outBuf.Length > 0)
        {
            Array.Clear(_outBuf, 0, _outBuf.Length);
        }
    }

    private void AppendToAccum(ReadOnlySpan<byte> src)
    {
        var add = src.Length;
        if (add == 0)
        {
            return;
        }
        // Compact if there isn't enough tail space to absorb `add`
        // bytes; grow if the live region itself is larger than the
        // current capacity.
        if (_accumEnd + add > _accum.Length)
        {
            var live = _accumEnd - _accumStart;
            if (live + add > _accum.Length)
            {
                var newCap = _accum.Length;
                while (newCap < live + add) { newCap *= 2; }
                var grown = new byte[newCap];
                if (live > 0)
                {
                    Buffer.BlockCopy(_accum, _accumStart, grown, 0, live);
                }
                Array.Clear(_accum, 0, _accum.Length);
                _accum = grown;
            }
            else if (_accumStart > 0)
            {
                if (live > 0)
                {
                    Buffer.BlockCopy(_accum, _accumStart, _accum, 0, live);
                }
                // Wipe the now-stale tail region.
                Array.Clear(_accum, live, _accum.Length - live);
            }
            _accumStart = 0;
            _accumEnd = live;
        }
        src.CopyTo(new Span<byte>(_accum, _accumEnd, add));
        _accumEnd += add;
    }

    /// <summary>
    /// Appends <paramref name="data"/> to the internal buffer and
    /// drains every complete chunk available.
    /// </summary>
    public int Feed(ReadOnlySpan<byte> data)
    {
        if (_closed)
        {
            throw new ItbException(StatusCode.EasyClosed,
                "feed on closed StreamDecryptorAuth");
        }
        var off = 0;
        if (_sidHave < StreamAuthInternal.StreamIdLen)
        {
            var need = StreamAuthInternal.StreamIdLen - _sidHave;
            var take = Math.Min(need, data.Length);
            data.Slice(0, take).CopyTo(
                new Span<byte>(_streamId, _sidHave, take));
            _sidHave += take;
            off = take;
        }
        if (off < data.Length)
        {
            AppendToAccum(data.Slice(off));
        }
        if (_sidHave == StreamAuthInternal.StreamIdLen)
        {
            Drain();
        }
        return data.Length;
    }

    /// <summary>
    /// Finalises the decryptor. An incomplete 32-byte stream-id
    /// prefix surfaces <see cref="ItbException"/> with
    /// <see cref="StatusCode.BadInput"/> (wire-level malformation,
    /// header never finished arriving). A fully observed prefix
    /// without a terminating chunk surfaces
    /// <see cref="ItbStreamTruncatedException"/>.
    /// </summary>
    public void Close()
    {
        if (_closed)
        {
            WipeOutBuf();
            return;
        }
        if (_sidHave < StreamAuthInternal.StreamIdLen)
        {
            WipeOutBuf();
            _closed = true;
            // Incomplete prefix is a wire-level malformation
            // (header never finished arriving), distinct from
            // "chunks observed but no terminator chunk among them"
            // which is the truncate-tail signal.
            throw new ItbException(
                StatusCode.BadInput,
                "auth stream: prefix never observed");
        }
        try
        {
            Drain();
        }
        finally
        {
            WipeOutBuf();
        }
        _closed = true;
        Array.Clear(_accum, 0, _accum.Length);
        if (!_seenFinal)
        {
            throw new ItbStreamTruncatedException(
                StatusCode.StreamTruncated,
                "auth stream: terminator never observed");
        }
    }

    /// <summary>Marks the decryptor closed without raising on partial
    /// input.</summary>
    public void Dispose()
    {
        WipeOutBuf();
        _closed = true;
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Triple Ouroboros (7-seed) counterpart of
/// <see cref="StreamEncryptorAuth"/>.
/// </summary>
public sealed class StreamEncryptorAuthTriple : IDisposable
{
    private readonly Seed _noise;
    private readonly Seed _data1;
    private readonly Seed _data2;
    private readonly Seed _data3;
    private readonly Seed _start1;
    private readonly Seed _start2;
    private readonly Seed _start3;
    private readonly Mac _mac;
    private readonly Stream _output;
    private readonly int _chunkSize;
    private readonly int _width;
    private readonly int _headerSize;
    private readonly byte[] _streamId;
    // Contiguous staging buffer — sized to chunkSize + 1 so a single
    // byte beyond the chunk boundary can sit there as the deferred-final
    // probe. When _filled exceeds _chunkSize the leading _chunkSize
    // bytes are emitted as non-terminal and the trailing residue
    // (_filled - _chunkSize bytes) is shifted to staging[0]. On Close
    // the residue is emitted as the terminating chunk.
    private readonly byte[] _staging;
    private int _filled;
    private ulong _cumPixels;
    private bool _closed;
    private bool _prefixEmitted;
    // Per-stream output buffer cache for the per-chunk dispatcher
    // (Bonus 1b in .NEXTBIND.md §7.1) — mirrors the per-encryptor
    // _outputBuffer field on Encryptor but lives on the streaming
    // class instance. Grown on demand by StreamAuthCipher.EmitTriple
    // with the same wipe-on-grow + 1.25× + 128 KiB envelope shape as
    // Encryptor.CipherCall; reused across every chunk's invocation.
    private byte[] _outBuf = Array.Empty<byte>();

    /// <summary>Constructs a fresh Triple Ouroboros authenticated
    /// stream encryptor. <paramref name="chunkSize"/> must be
    /// positive.</summary>
    public StreamEncryptorAuthTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Mac mac,
        Stream output,
        int chunkSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data1);
        ArgumentNullException.ThrowIfNull(data2);
        ArgumentNullException.ThrowIfNull(data3);
        ArgumentNullException.ThrowIfNull(start1);
        ArgumentNullException.ThrowIfNull(start2);
        ArgumentNullException.ThrowIfNull(start3);
        ArgumentNullException.ThrowIfNull(mac);
        ArgumentNullException.ThrowIfNull(output);
        if (chunkSize <= 0)
        {
            throw new ItbException(StatusCode.BadInput,
                "chunkSize must be positive");
        }
        _noise = noise;
        _data1 = data1;
        _data2 = data2;
        _data3 = data3;
        _start1 = start1;
        _start2 = start2;
        _start3 = start3;
        _mac = mac;
        _output = output;
        _chunkSize = chunkSize;
        _width = noise.Width;
        _headerSize = Library.HeaderSize;
        _streamId = StreamAuthInternal.GenerateStreamId();
        // chunkSize + 1 holds the deferred-final probe byte.
        _staging = new byte[chunkSize + 1];
    }

    private void EmitPrefix()
    {
        if (!_prefixEmitted)
        {
            _output.Write(_streamId, 0, _streamId.Length);
            _prefixEmitted = true;
        }
    }

    private void EmitOne(int plaintextLen, bool finalFlag)
    {
        var (ctBuf, ctLen) = StreamAuthCipher.EmitTriple(
            _width, _noise, _data1, _data2, _data3,
            _start1, _start2, _start3, _mac,
            _staging, plaintextLen, _streamId, _cumPixels, finalFlag,
            ref _outBuf);
        if (ctLen >= _headerSize)
        {
            var w = StreamAuthInternal.ReadBe16(ctBuf, _headerSize - 4);
            var h = StreamAuthInternal.ReadBe16(ctBuf, _headerSize - 2);
            _cumPixels += (ulong)w * (ulong)h;
        }
        _output.Write(ctBuf, 0, ctLen);
    }

    /// <summary>
    /// Wipes the per-stream output buffer cache. Mirrors the
    /// wipe-on-Dispose discipline on
    /// <see cref="Encryptor.WipeOutputBuffer"/>; called from
    /// <see cref="Close"/> / <see cref="Dispose"/> so the most recent
    /// chunk's ciphertext does not linger in heap garbage past stream
    /// teardown.
    /// </summary>
    private void WipeOutBuf()
    {
        if (_outBuf.Length > 0)
        {
            Array.Clear(_outBuf, 0, _outBuf.Length);
        }
    }

    /// <summary>Appends <paramref name="data"/> to the internal
    /// buffer and emits non-terminal chunks.</summary>
    public int Write(ReadOnlySpan<byte> data)
    {
        if (_closed)
        {
            throw new ItbException(StatusCode.EasyClosed,
                "write on closed StreamEncryptorAuthTriple");
        }
        EmitPrefix();
        var consumed = 0;
        while (consumed < data.Length)
        {
            var room = _staging.Length - _filled;
            var take = Math.Min(room, data.Length - consumed);
            data.Slice(consumed, take).CopyTo(
                new Span<byte>(_staging, _filled, take));
            _filled += take;
            consumed += take;
            // Keep at least one chunk's worth buffered until Close()
            // so the deferred-final pattern can decide whether to emit
            // final_flag = true. Only emit when more than _chunkSize
            // bytes are present (one byte past the boundary).
            if (_filled > _chunkSize)
            {
                EmitOne(_chunkSize, false);
                var residue = _filled - _chunkSize;
                if (residue > 0)
                {
                    Buffer.BlockCopy(_staging, _chunkSize, _staging, 0, residue);
                }
                Array.Clear(_staging, residue, _staging.Length - residue);
                _filled = residue;
            }
        }
        return data.Length;
    }

    /// <summary>Emits the residual buffer as the terminating chunk
    /// and finalises the stream. Idempotent.</summary>
    public void Close()
    {
        if (_closed)
        {
            WipeOutBuf();
            return;
        }
        EmitPrefix();
        EmitOne(_filled, true);
        Array.Clear(_staging, 0, _staging.Length);
        _filled = 0;
        WipeOutBuf();
        _closed = true;
    }

    /// <summary>Calls <see cref="Close"/> if not already called.</summary>
    public void Dispose()
    {
        Close();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Triple Ouroboros (7-seed) counterpart of
/// <see cref="StreamDecryptorAuth"/>.
/// </summary>
public sealed class StreamDecryptorAuthTriple : IDisposable
{
    private readonly Seed _noise;
    private readonly Seed _data1;
    private readonly Seed _data2;
    private readonly Seed _data3;
    private readonly Seed _start1;
    private readonly Seed _start2;
    private readonly Seed _start3;
    private readonly Mac _mac;
    private readonly Stream _output;
    private readonly int _width;
    private readonly int _headerSize;
    private readonly byte[] _streamId = new byte[StreamAuthInternal.StreamIdLen];
    private int _sidHave;
    // Contiguous accumulator — _accum[_accumStart.._accumEnd) holds
    // the unparsed wire bytes belonging to chunks not yet consumed.
    // Slides via a head index (_accumStart) instead of List<byte>.
    // RemoveRange; compacts when the head crosses half-way through
    // the buffer to bound memory.
    private byte[] _accum;
    private int _accumStart;
    private int _accumEnd;
    private ulong _cumPixels;
    private bool _seenFinal;
    private bool _closed;
    // Per-stream output buffer cache for the per-chunk dispatcher
    // (Bonus 1b in .NEXTBIND.md §7.1) — mirrors the per-encryptor
    // _outputBuffer field on Encryptor but lives on the streaming
    // class instance. Grown on demand by StreamAuthCipher.ConsumeTriple
    // with the same wipe-on-grow + 1.25× + 128 KiB envelope shape as
    // Encryptor.CipherCall; reused across every chunk's invocation.
    private byte[] _outBuf = Array.Empty<byte>();

    /// <summary>Constructs a fresh Triple Ouroboros authenticated
    /// stream decryptor.</summary>
    public StreamDecryptorAuthTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Mac mac,
        Stream output)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data1);
        ArgumentNullException.ThrowIfNull(data2);
        ArgumentNullException.ThrowIfNull(data3);
        ArgumentNullException.ThrowIfNull(start1);
        ArgumentNullException.ThrowIfNull(start2);
        ArgumentNullException.ThrowIfNull(start3);
        ArgumentNullException.ThrowIfNull(mac);
        ArgumentNullException.ThrowIfNull(output);
        _noise = noise;
        _data1 = data1;
        _data2 = data2;
        _data3 = data3;
        _start1 = start1;
        _start2 = start2;
        _start3 = start3;
        _mac = mac;
        _output = output;
        _width = noise.Width;
        _headerSize = Library.HeaderSize;
        // 1 MiB initial capacity — same floor as the Easy Mode driver
        // (Encryptor.DecryptStreamAuth).
        _accum = new byte[1 << 20];
    }

    private void Drain()
    {
        while (true)
        {
            if (_seenFinal)
            {
                if (_accumEnd - _accumStart > 0)
                {
                    throw new ItbStreamAfterFinalException(
                        StatusCode.StreamAfterFinal,
                        "auth stream: trailing bytes after terminator");
                }
                return;
            }
            if (_accumEnd - _accumStart < _headerSize)
            {
                return;
            }
            var chunkLen = Library.ParseChunkLen(
                new ReadOnlySpan<byte>(_accum, _accumStart, _headerSize));
            if (_accumEnd - _accumStart < chunkLen)
            {
                return;
            }
            var w = StreamAuthInternal.ReadBe16(_accum, _accumStart + _headerSize - 4);
            var h = StreamAuthInternal.ReadBe16(_accum, _accumStart + _headerSize - 2);
            var pixels = (ulong)w * (ulong)h;
            var chunk = new byte[chunkLen];
            Buffer.BlockCopy(_accum, _accumStart, chunk, 0, chunkLen);
            _accumStart += chunkLen;
            // Compact when the head drifts past half the buffer
            // — keeps the live region near offset 0 so subsequent
            // Feed calls can append without growing.
            if (_accumStart > _accum.Length / 2)
            {
                var live = _accumEnd - _accumStart;
                if (live > 0)
                {
                    Buffer.BlockCopy(_accum, _accumStart, _accum, 0, live);
                }
                Array.Clear(_accum, live, _accum.Length - live);
                _accumStart = 0;
                _accumEnd = live;
            }
            var (ptBuf, ptLen, ff) = StreamAuthCipher.ConsumeTriple(
                _width, _noise, _data1, _data2, _data3,
                _start1, _start2, _start3, _mac,
                chunk, chunk.Length, _streamId, _cumPixels,
                ref _outBuf);
            _output.Write(ptBuf, 0, ptLen);
            Array.Clear(ptBuf, 0, ptLen);
            _cumPixels += pixels;
            if (ff)
            {
                _seenFinal = true;
            }
        }
    }

    /// <summary>
    /// Wipes the per-stream output buffer cache. Mirrors the
    /// wipe-on-Dispose discipline on
    /// <see cref="Encryptor.WipeOutputBuffer"/>; called from
    /// <see cref="Close"/> / <see cref="Dispose"/> so the most recent
    /// chunk's plaintext does not linger in heap garbage past stream
    /// teardown.
    /// </summary>
    private void WipeOutBuf()
    {
        if (_outBuf.Length > 0)
        {
            Array.Clear(_outBuf, 0, _outBuf.Length);
        }
    }

    private void AppendToAccum(ReadOnlySpan<byte> src)
    {
        var add = src.Length;
        if (add == 0)
        {
            return;
        }
        // Compact if there isn't enough tail space to absorb `add`
        // bytes; grow if the live region itself is larger than the
        // current capacity.
        if (_accumEnd + add > _accum.Length)
        {
            var live = _accumEnd - _accumStart;
            if (live + add > _accum.Length)
            {
                var newCap = _accum.Length;
                while (newCap < live + add) { newCap *= 2; }
                var grown = new byte[newCap];
                if (live > 0)
                {
                    Buffer.BlockCopy(_accum, _accumStart, grown, 0, live);
                }
                Array.Clear(_accum, 0, _accum.Length);
                _accum = grown;
            }
            else if (_accumStart > 0)
            {
                if (live > 0)
                {
                    Buffer.BlockCopy(_accum, _accumStart, _accum, 0, live);
                }
                // Wipe the now-stale tail region.
                Array.Clear(_accum, live, _accum.Length - live);
            }
            _accumStart = 0;
            _accumEnd = live;
        }
        src.CopyTo(new Span<byte>(_accum, _accumEnd, add));
        _accumEnd += add;
    }

    /// <summary>Appends <paramref name="data"/> and drains every
    /// complete chunk.</summary>
    public int Feed(ReadOnlySpan<byte> data)
    {
        if (_closed)
        {
            throw new ItbException(StatusCode.EasyClosed,
                "feed on closed StreamDecryptorAuthTriple");
        }
        var off = 0;
        if (_sidHave < StreamAuthInternal.StreamIdLen)
        {
            var need = StreamAuthInternal.StreamIdLen - _sidHave;
            var take = Math.Min(need, data.Length);
            data.Slice(0, take).CopyTo(
                new Span<byte>(_streamId, _sidHave, take));
            _sidHave += take;
            off = take;
        }
        if (off < data.Length)
        {
            AppendToAccum(data.Slice(off));
        }
        if (_sidHave == StreamAuthInternal.StreamIdLen)
        {
            Drain();
        }
        return data.Length;
    }

    /// <summary>Finalises the decryptor. An incomplete 32-byte
    /// stream-id prefix surfaces <see cref="ItbException"/> with
    /// <see cref="StatusCode.BadInput"/> (wire-level malformation,
    /// header never finished arriving). A fully observed prefix
    /// without a terminating chunk surfaces
    /// <see cref="ItbStreamTruncatedException"/>.</summary>
    public void Close()
    {
        if (_closed)
        {
            WipeOutBuf();
            return;
        }
        if (_sidHave < StreamAuthInternal.StreamIdLen)
        {
            WipeOutBuf();
            _closed = true;
            // Incomplete prefix is a wire-level malformation
            // (header never finished arriving), distinct from
            // "chunks observed but no terminator chunk among them"
            // which is the truncate-tail signal.
            throw new ItbException(
                StatusCode.BadInput,
                "auth stream: prefix never observed");
        }
        try
        {
            Drain();
        }
        finally
        {
            WipeOutBuf();
        }
        _closed = true;
        Array.Clear(_accum, 0, _accum.Length);
        if (!_seenFinal)
        {
            throw new ItbStreamTruncatedException(
                StatusCode.StreamTruncated,
                "auth stream: terminator never observed");
        }
    }

    /// <summary>Marks the decryptor closed without raising on
    /// partial input.</summary>
    public void Dispose()
    {
        WipeOutBuf();
        _closed = true;
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Per-chunk dispatch helpers for the Streaming AEAD encrypt /
/// decrypt path. Probes output capacity, allocates, and runs the
/// call again. Every static method that extracts a handle from a
/// Seed / Mac argument keeps the wrapper objects reachable past the
/// FFI call via <see cref="GC.KeepAlive(object)"/>.
/// </summary>
internal static unsafe class StreamAuthCipher
{
    public static (byte[] Buf, int OutLen) EmitSingle(
        int width,
        Seed noise, Seed data, Seed start, Mac mac,
        byte[] plaintext, int plaintextLen, byte[] streamId,
        ulong cumPixels, bool finalFlag,
        ref byte[] cache)
    {
        try
        {
            var nh = noise.Handle;
            var dh = data.Handle;
            var sh = start.Handle;
            var mh = mac.Handle;
            var ff = finalFlag ? 1 : 0;
            var payloadLen = plaintextLen;
            // 1.25× + 128 KiB headroom; see Encryptor.CipherCall.
            var cap = Math.Max(131072, payloadLen * 5 / 4 + 131072);
            StreamAuthEasy.EnsureStreamCache(ref cache, cap);
            nuint outLen;
            int rc;
            fixed (byte* inPtr = plaintext)
            fixed (byte* sidPtr = streamId)
            fixed (byte* outPtr = cache)
            {
                rc = InvokeEnc1(width, nh, dh, sh, mh,
                    inPtr, (nuint)payloadLen,
                    sidPtr, cumPixels, ff,
                    outPtr, (nuint)cache.Length, out outLen);
            }
            if (rc == Status.BufferTooSmall)
            {
                StreamAuthEasy.EnsureStreamCache(ref cache, (int)outLen);
                fixed (byte* inPtr = plaintext)
                fixed (byte* sidPtr = streamId)
                fixed (byte* outPtr = cache)
                {
                    rc = InvokeEnc1(width, nh, dh, sh, mh,
                        inPtr, (nuint)payloadLen,
                        sidPtr, cumPixels, ff,
                        outPtr, (nuint)cache.Length, out outLen);
                }
            }
            ItbException.Check(rc);
            return (cache, (int)outLen);
        }
        finally
        {
            GC.KeepAlive(noise);
            GC.KeepAlive(data);
            GC.KeepAlive(start);
            GC.KeepAlive(mac);
        }
    }

    public static (byte[] Buf, int OutLen) EmitTriple(
        int width,
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Mac mac,
        byte[] plaintext, int plaintextLen, byte[] streamId,
        ulong cumPixels, bool finalFlag,
        ref byte[] cache)
    {
        try
        {
            var nh = noise.Handle;
            var d1 = data1.Handle;
            var d2 = data2.Handle;
            var d3 = data3.Handle;
            var s1 = start1.Handle;
            var s2 = start2.Handle;
            var s3 = start3.Handle;
            var mh = mac.Handle;
            var ff = finalFlag ? 1 : 0;
            var payloadLen = plaintextLen;
            // 1.25× + 128 KiB headroom; see Encryptor.CipherCall.
            var cap = Math.Max(131072, payloadLen * 5 / 4 + 131072);
            StreamAuthEasy.EnsureStreamCache(ref cache, cap);
            nuint outLen;
            int rc;
            fixed (byte* inPtr = plaintext)
            fixed (byte* sidPtr = streamId)
            fixed (byte* outPtr = cache)
            {
                rc = InvokeEnc3(width, nh, d1, d2, d3, s1, s2, s3, mh,
                    inPtr, (nuint)payloadLen,
                    sidPtr, cumPixels, ff,
                    outPtr, (nuint)cache.Length, out outLen);
            }
            if (rc == Status.BufferTooSmall)
            {
                StreamAuthEasy.EnsureStreamCache(ref cache, (int)outLen);
                fixed (byte* inPtr = plaintext)
                fixed (byte* sidPtr = streamId)
                fixed (byte* outPtr = cache)
                {
                    rc = InvokeEnc3(width, nh, d1, d2, d3, s1, s2, s3, mh,
                        inPtr, (nuint)payloadLen,
                        sidPtr, cumPixels, ff,
                        outPtr, (nuint)cache.Length, out outLen);
                }
            }
            ItbException.Check(rc);
            return (cache, (int)outLen);
        }
        finally
        {
            GC.KeepAlive(noise);
            GC.KeepAlive(data1);
            GC.KeepAlive(data2);
            GC.KeepAlive(data3);
            GC.KeepAlive(start1);
            GC.KeepAlive(start2);
            GC.KeepAlive(start3);
            GC.KeepAlive(mac);
        }
    }

    public static (byte[] Buf, int OutLen, bool FinalFlag) ConsumeSingle(
        int width,
        Seed noise, Seed data, Seed start, Mac mac,
        byte[] ciphertext, int ciphertextLen, byte[] streamId, ulong cumPixels,
        ref byte[] cache)
    {
        try
        {
            var nh = noise.Handle;
            var dh = data.Handle;
            var sh = start.Handle;
            var mh = mac.Handle;
            var payloadLen = ciphertextLen;
            // 1.25× + 128 KiB headroom; see Encryptor.CipherCall.
            var cap = Math.Max(131072, payloadLen * 5 / 4 + 131072);
            StreamAuthEasy.EnsureStreamCache(ref cache, cap);
            nuint outLen;
            int ff;
            int rc;
            fixed (byte* inPtr = ciphertext)
            fixed (byte* sidPtr = streamId)
            fixed (byte* outPtr = cache)
            {
                rc = InvokeDec1(width, nh, dh, sh, mh,
                    inPtr, (nuint)payloadLen,
                    sidPtr, cumPixels,
                    outPtr, (nuint)cache.Length, out outLen, out ff);
            }
            if (rc == Status.BufferTooSmall)
            {
                StreamAuthEasy.EnsureStreamCache(ref cache, (int)outLen);
                fixed (byte* inPtr = ciphertext)
                fixed (byte* sidPtr = streamId)
                fixed (byte* outPtr = cache)
                {
                    rc = InvokeDec1(width, nh, dh, sh, mh,
                        inPtr, (nuint)payloadLen,
                        sidPtr, cumPixels,
                        outPtr, (nuint)cache.Length, out outLen, out ff);
                }
            }
            ItbException.Check(rc);
            return (cache, (int)outLen, ff != 0);
        }
        finally
        {
            GC.KeepAlive(noise);
            GC.KeepAlive(data);
            GC.KeepAlive(start);
            GC.KeepAlive(mac);
        }
    }

    public static (byte[] Buf, int OutLen, bool FinalFlag) ConsumeTriple(
        int width,
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Mac mac,
        byte[] ciphertext, int ciphertextLen, byte[] streamId, ulong cumPixels,
        ref byte[] cache)
    {
        try
        {
            var nh = noise.Handle;
            var d1 = data1.Handle;
            var d2 = data2.Handle;
            var d3 = data3.Handle;
            var s1 = start1.Handle;
            var s2 = start2.Handle;
            var s3 = start3.Handle;
            var mh = mac.Handle;
            var payloadLen = ciphertextLen;
            // 1.25× + 128 KiB headroom; see Encryptor.CipherCall.
            var cap = Math.Max(131072, payloadLen * 5 / 4 + 131072);
            StreamAuthEasy.EnsureStreamCache(ref cache, cap);
            nuint outLen;
            int ff;
            int rc;
            fixed (byte* inPtr = ciphertext)
            fixed (byte* sidPtr = streamId)
            fixed (byte* outPtr = cache)
            {
                rc = InvokeDec3(width, nh, d1, d2, d3, s1, s2, s3, mh,
                    inPtr, (nuint)payloadLen,
                    sidPtr, cumPixels,
                    outPtr, (nuint)cache.Length, out outLen, out ff);
            }
            if (rc == Status.BufferTooSmall)
            {
                StreamAuthEasy.EnsureStreamCache(ref cache, (int)outLen);
                fixed (byte* inPtr = ciphertext)
                fixed (byte* sidPtr = streamId)
                fixed (byte* outPtr = cache)
                {
                    rc = InvokeDec3(width, nh, d1, d2, d3, s1, s2, s3, mh,
                        inPtr, (nuint)payloadLen,
                        sidPtr, cumPixels,
                        outPtr, (nuint)cache.Length, out outLen, out ff);
                }
            }
            ItbException.Check(rc);
            return (cache, (int)outLen, ff != 0);
        }
        finally
        {
            GC.KeepAlive(noise);
            GC.KeepAlive(data1);
            GC.KeepAlive(data2);
            GC.KeepAlive(data3);
            GC.KeepAlive(start1);
            GC.KeepAlive(start2);
            GC.KeepAlive(start3);
            GC.KeepAlive(mac);
        }
    }

    private static int InvokeEnc1(
        int width,
        nuint nh, nuint dh, nuint sh, nuint mh,
        byte* inPtr, nuint ptLen,
        byte* sidPtr, ulong cumPixels, int ff,
        byte* outPtr, nuint outCap, out nuint outLen)
    {
        return width switch
        {
            128 => ItbNative.ITB_EncryptStreamAuthenticated128(
                nh, dh, sh, mh, inPtr, ptLen, sidPtr, cumPixels, ff,
                outPtr, outCap, out outLen),
            256 => ItbNative.ITB_EncryptStreamAuthenticated256(
                nh, dh, sh, mh, inPtr, ptLen, sidPtr, cumPixels, ff,
                outPtr, outCap, out outLen),
            512 => ItbNative.ITB_EncryptStreamAuthenticated512(
                nh, dh, sh, mh, inPtr, ptLen, sidPtr, cumPixels, ff,
                outPtr, outCap, out outLen),
            _ => throw new ItbException(StatusCode.SeedWidthMix,
                $"unsupported native hash width {width}"),
        };
    }

    private static int InvokeEnc3(
        int width,
        nuint nh, nuint d1, nuint d2, nuint d3,
        nuint s1, nuint s2, nuint s3, nuint mh,
        byte* inPtr, nuint ptLen,
        byte* sidPtr, ulong cumPixels, int ff,
        byte* outPtr, nuint outCap, out nuint outLen)
    {
        return width switch
        {
            128 => ItbNative.ITB_EncryptStreamAuthenticated3x128(
                nh, d1, d2, d3, s1, s2, s3, mh,
                inPtr, ptLen, sidPtr, cumPixels, ff,
                outPtr, outCap, out outLen),
            256 => ItbNative.ITB_EncryptStreamAuthenticated3x256(
                nh, d1, d2, d3, s1, s2, s3, mh,
                inPtr, ptLen, sidPtr, cumPixels, ff,
                outPtr, outCap, out outLen),
            512 => ItbNative.ITB_EncryptStreamAuthenticated3x512(
                nh, d1, d2, d3, s1, s2, s3, mh,
                inPtr, ptLen, sidPtr, cumPixels, ff,
                outPtr, outCap, out outLen),
            _ => throw new ItbException(StatusCode.SeedWidthMix,
                $"unsupported native hash width {width}"),
        };
    }

    private static int InvokeDec1(
        int width,
        nuint nh, nuint dh, nuint sh, nuint mh,
        byte* inPtr, nuint ctLen,
        byte* sidPtr, ulong cumPixels,
        byte* outPtr, nuint outCap, out nuint outLen, out int finalFlagOut)
    {
        return width switch
        {
            128 => ItbNative.ITB_DecryptStreamAuthenticated128(
                nh, dh, sh, mh, inPtr, ctLen, sidPtr, cumPixels,
                outPtr, outCap, out outLen, out finalFlagOut),
            256 => ItbNative.ITB_DecryptStreamAuthenticated256(
                nh, dh, sh, mh, inPtr, ctLen, sidPtr, cumPixels,
                outPtr, outCap, out outLen, out finalFlagOut),
            512 => ItbNative.ITB_DecryptStreamAuthenticated512(
                nh, dh, sh, mh, inPtr, ctLen, sidPtr, cumPixels,
                outPtr, outCap, out outLen, out finalFlagOut),
            _ => throw new ItbException(StatusCode.SeedWidthMix,
                $"unsupported native hash width {width}"),
        };
    }

    private static int InvokeDec3(
        int width,
        nuint nh, nuint d1, nuint d2, nuint d3,
        nuint s1, nuint s2, nuint s3, nuint mh,
        byte* inPtr, nuint ctLen,
        byte* sidPtr, ulong cumPixels,
        byte* outPtr, nuint outCap, out nuint outLen, out int finalFlagOut)
    {
        return width switch
        {
            128 => ItbNative.ITB_DecryptStreamAuthenticated3x128(
                nh, d1, d2, d3, s1, s2, s3, mh,
                inPtr, ctLen, sidPtr, cumPixels,
                outPtr, outCap, out outLen, out finalFlagOut),
            256 => ItbNative.ITB_DecryptStreamAuthenticated3x256(
                nh, d1, d2, d3, s1, s2, s3, mh,
                inPtr, ctLen, sidPtr, cumPixels,
                outPtr, outCap, out outLen, out finalFlagOut),
            512 => ItbNative.ITB_DecryptStreamAuthenticated3x512(
                nh, d1, d2, d3, s1, s2, s3, mh,
                inPtr, ctLen, sidPtr, cumPixels,
                outPtr, outCap, out outLen, out finalFlagOut),
            _ => throw new ItbException(StatusCode.SeedWidthMix,
                $"unsupported native hash width {width}"),
        };
    }
}

/// <summary>
/// Per-chunk dispatch helpers for the Easy Mode Streaming AEAD path.
/// Wraps the <c>ITB_Easy_EncryptStreamAuth</c> /
/// <c>ITB_Easy_DecryptStreamAuth</c> ABI exports with the standard
/// probe-and-allocate retry against the caller-supplied output
/// capacity.
///
/// The <c>cache</c> parameter is a <c>ref</c> handle to the caller's
/// reusable output buffer (typically <c>Encryptor._outputBuffer</c> —
/// Bonus 1 in .NEXTBIND.md §7.1). The helper grows it on demand with
/// the same wipe-on-grow + 1.25× + 128 KiB envelope shape as
/// <c>Encryptor.CipherCall</c>; the returned tuple references the
/// cache directly. The next chunk's call may reuse the same cache —
/// <see cref="System.IO.Stream.Write(byte[], int, int)"/> is
/// synchronous and consumes the buffer before returning, so the
/// caller's <c>output.Write(buf, 0, len)</c> is complete by the time
/// the next per-chunk dispatcher runs.
/// </summary>
internal static unsafe class StreamAuthEasy
{
    public static (byte[] Buf, int OutLen) Emit(nuint encryptorHandle,
        byte[] plaintext, int plaintextLen, byte[] streamId,
        ulong cumPixels, bool finalFlag,
        ref byte[] cache)
    {
        var ff = finalFlag ? 1 : 0;
        var payloadLen = plaintextLen;
        // 1.25× + 128 KiB headroom; see Encryptor.CipherCall.
        var cap = Math.Max(131072, payloadLen * 5 / 4 + 131072);
        EnsureStreamCache(ref cache, cap);
        nuint outLen;
        int rc;
        fixed (byte* inPtr = plaintext)
        fixed (byte* sidPtr = streamId)
        fixed (byte* outPtr = cache)
        {
            rc = ItbNative.ITB_Easy_EncryptStreamAuth(
                encryptorHandle, inPtr, (nuint)payloadLen,
                sidPtr, cumPixels, ff,
                outPtr, (nuint)cache.Length, out outLen);
        }
        if (rc == Status.BufferTooSmall)
        {
            EnsureStreamCache(ref cache, (int)outLen);
            fixed (byte* inPtr = plaintext)
            fixed (byte* sidPtr = streamId)
            fixed (byte* outPtr = cache)
            {
                rc = ItbNative.ITB_Easy_EncryptStreamAuth(
                    encryptorHandle, inPtr, (nuint)payloadLen,
                    sidPtr, cumPixels, ff,
                    outPtr, (nuint)cache.Length, out outLen);
            }
        }
        ItbException.Check(rc);
        return (cache, (int)outLen);
    }

    public static (byte[] Buf, int OutLen, bool FinalFlag) Consume(nuint encryptorHandle,
        byte[] ciphertext, int ciphertextLen, byte[] streamId, ulong cumPixels,
        ref byte[] cache)
    {
        var payloadLen = ciphertextLen;
        // 1.25× + 128 KiB headroom; see Encryptor.CipherCall.
        var cap = Math.Max(131072, payloadLen * 5 / 4 + 131072);
        EnsureStreamCache(ref cache, cap);
        nuint outLen;
        int ff;
        int rc;
        fixed (byte* inPtr = ciphertext)
        fixed (byte* sidPtr = streamId)
        fixed (byte* outPtr = cache)
        {
            rc = ItbNative.ITB_Easy_DecryptStreamAuth(
                encryptorHandle, inPtr, (nuint)payloadLen,
                sidPtr, cumPixels,
                outPtr, (nuint)cache.Length, out outLen, out ff);
        }
        if (rc == Status.BufferTooSmall)
        {
            EnsureStreamCache(ref cache, (int)outLen);
            fixed (byte* inPtr = ciphertext)
            fixed (byte* sidPtr = streamId)
            fixed (byte* outPtr = cache)
            {
                rc = ItbNative.ITB_Easy_DecryptStreamAuth(
                    encryptorHandle, inPtr, (nuint)payloadLen,
                    sidPtr, cumPixels,
                    outPtr, (nuint)cache.Length, out outLen, out ff);
            }
        }
        ItbException.Check(rc);
        return (cache, (int)outLen, ff != 0);
    }

    /// <summary>
    /// Grow-on-demand + wipe-on-grow helper for the per-chunk output
    /// buffer cache. Mirrors <c>Encryptor.EnsureCapacity</c>: zeros
    /// the OLD contents before reassigning so the previous-chunk
    /// ciphertext / plaintext does not linger in heap garbage between
    /// dispatcher calls.
    /// </summary>
    internal static void EnsureStreamCache(ref byte[] cache, int needed)
    {
        if (cache.Length < needed)
        {
            if (cache.Length > 0)
            {
                Array.Clear(cache, 0, cache.Length);
            }
            cache = new byte[needed];
        }
    }
}
