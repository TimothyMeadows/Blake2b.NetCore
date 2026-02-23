using System;
using System.Text;
using PinnedMemory;

namespace Blake2b.NetCore.Tests;

public class Blake2bVectorsTests
{
    [Fact]
    public void Blake2b_512_EmptyString_MatchesRfc7693Vector()
    {
        var digest = new Blake2b();
        using var output = new PinnedMemory<byte>(new byte[digest.GetLength()]);

        digest.DoFinal(output, 0);

        var actual = Convert.ToHexString(output.ToArray()).ToLowerInvariant();
        const string expected = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce";
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Blake2b_512_Abc_MatchesRfc7693Vector()
    {
        var digest = new Blake2b();
        using var output = new PinnedMemory<byte>(new byte[digest.GetLength()]);
        var message = Encoding.ASCII.GetBytes("abc");

        digest.UpdateBlock(message, 0, message.Length);
        digest.DoFinal(output, 0);

        var actual = Convert.ToHexString(output.ToArray()).ToLowerInvariant();
        const string expected = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(8)]
    [InlineData(72)]
    [InlineData(160)]
    [InlineData(256)]
    [InlineData(384)]
    [InlineData(512)]
    public void Blake2b_AllowsValidBitLengths(int digestBits)
    {
        var digest = new Blake2b(digestBits);
        Assert.Equal(digestBits / 8, digest.GetLength());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(513)]
    [InlineData(130)]
    public void Blake2b_RejectsInvalidBitLengths(int digestBits)
    {
        Assert.Throws<ArgumentException>(() => new Blake2b(digestBits));
    }

    [Fact]
    public void UpdateBlock_PinnedMemory_DoesNotDisposeCallerBuffer()
    {
        var digest = new Blake2b();
        using var message = new PinnedMemory<byte>(new byte[] { 1, 2, 3, 4 }, false);

        digest.UpdateBlock(message, 0, message.Length);

        var roundTrip = message.ToArray();
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, roundTrip);
    }
}
