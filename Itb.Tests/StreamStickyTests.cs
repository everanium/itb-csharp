// A decrypt session fed a tampered wire fails with a sticky MAC
// failure. Uses a position probe rather than a single bit flip
// because the over-sized container carries CSPRNG residue in the
// non-payload area — a flip that lands inside the residue is
// architecturally inert (residue is not payload) and the session
// finishes clean. Probing 32 evenly-spaced positions makes the
// all-residue probability negligible; the first position that
// surfaces an error must give Status.MacFailure and remain sticky on
// subsequent reads.

namespace Itb.Tests;

public class StreamStickyTests
{
    [Fact]
    public void TamperedWireStickyFailure()
    {
        using var sender = Pipeline.Init("streaming-aead-triple-mac-v1");
        using var receiver = Pipeline.Load(sender.Save());

        var plain = new byte[65_536];
        for (int i = 0; i < plain.Length; i++)
        {
            plain[i] = (byte)(i % 227);
        }
        var baseWire = sender.EncryptStreamOneShot(plain);
        Assert.True(baseWire.Length > 128,
            $"wire too short to place a distributed probe: {baseWire.Length} bytes");

        const int Probes = 32;
        // Evenly spread through the wire body; skip the first / last
        // 16 bytes so a hit against the outer envelope framing does
        // not muddy the observation.
        int bodyStart = 16;
        int bodyEnd = baseWire.Length - 16;
        int stride = (bodyEnd - bodyStart) / Probes;

        for (int probe = 0; probe < Probes; probe++)
        {
            int idx = bodyStart + probe * stride;

            var wire = (byte[])baseWire.Clone();
            wire[idx] ^= 0x01;

            using var session = receiver.BeginDecryptStream();
            // Ignore Write / End status — the failure may surface on
            // either side or only on the drain that follows.
            try
            {
                session.Write(wire);
                session.End();
            }
            catch (ItbException)
            {
            }

            var buf = new byte[4096];
            ItbException? firstErr = null;
            bool finishedClean = false;
            while (true)
            {
                try
                {
                    session.Read(buf, out bool finished);
                    if (finished)
                    {
                        finishedClean = true;
                        break;
                    }
                }
                catch (ItbException e)
                {
                    firstErr = e;
                    break;
                }
            }
            if (finishedClean)
            {
                // Residue hit at this offset — try the next probe.
                continue;
            }
            Assert.NotNull(firstErr);
            Assert.True(Status.MacFailure == firstErr.Status,
                $"expected MAC failure on tampered wire at probe {probe} " +
                $"(byte {idx}), got {firstErr.Status}");

            // Sticky: a subsequent read reports the same status.
            var again = Assert.Throws<ItbException>(() => session.Read(buf, out _));
            Assert.Equal(firstErr.Status, again.Status);
            return;
        }
        Assert.Fail(
            $"no probe among {Probes} evenly-spaced positions surfaced a MAC " +
            "failure — either the probe pattern is degenerate or " +
            "authentication is not covering the wire body it should");
    }
}
