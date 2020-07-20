using System;
using PinnedMemory;

namespace Blake2b.NetCore
{
    /*
        This code was adapted from BouncyCastle 1.8.3 Blake2bDigest.cs
        The BLAKE2 cryptographic hash function was designed by Jean-
        Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian
        Winnerlein.
   
        Reference Implementation and Description can be found at: https://blake2.net/      
        Internet Draft: https://tools.ietf.org/html/draft-saarinen-blake2-02

        This implementation does not support the Tree Hashing Mode. 
     */

    /*
     * Implementation of the cryptographic hash function Blakbe2b.
     * <p>
     * Blake2b offers a built-in keying mechanism to be used directly
     * for authentication ("Prefix-MAC") rather than a HMAC construction.
     * <p>
     * Blake2b offers a built-in support for a salt for randomized hashing
     * and a personal string for defining a unique hash function for each application.
     * <p>
     * BLAKE2b is optimized for 64-bit platforms and produces digests of any size
     * between 1 and 64 bytes.
     */
    public class Blake2bMac : IDisposable
    {
        // Blake2b Initialization Vector:
        private static readonly ulong[] Blake2BIv =
            // Produced from the square root of primes 2, 3, 5, 7, 11, 13, 17, 19.
            // The same as SHA-512 IV.
            {
                0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL,
                0xa54ff53a5f1d36f1UL, 0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
                0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
            };

        // Message word permutations:
        private static readonly byte[,] Blake2BSigma =
        {
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
            { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
            { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
            { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
            { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
            { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
            { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
            { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
            { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
        };

        private const int Rounds = 12; // to use for Catenas H'
        private const int BlockLengthBytes = 128;// bytes

        // General parameters:
        private readonly int _digestLength; // 1- 64 bytes
        private readonly int _keyLength = 0; // 0 - 64 bytes for keyed hashing for MAC
        private readonly byte[] _salt = null;// new byte[16];

        // the key
        private readonly PinnedMemory<byte> _key;

        // Tree hashing parameters:
        // Because this class does not implement the Tree Hashing Mode,
        // these parameters can be treated as constants (see init() function)
        /*
	     * private int fanout = 1; // 0-255 private int depth = 1; // 1 - 255
	     * private int leafLength= 0; private long nodeOffset = 0L; private int
	     * nodeDepth = 0; private int innerHashLength = 0;
	     */

        // whenever this buffer overflows, it will be processed
        // in the Compress() function.
        // For performance issues, long messages will not use this buffer.
        private readonly byte[] _buffer = null;// new byte[BLOCK_LENGTH_BYTES];
        private readonly PinnedMemory<byte> _bufferPin;
        // Position of last inserted byte:
        private int _bufferPos = 0;// a value from 0 up to 128

        private readonly ulong[] _internalState = new ulong[16]; // In the Blake2b paper it is
        // called: v
        private ulong[] _chainValue = null; // state vector, in the Blake2b paper it
        // is called: h

        private ulong t0 = 0UL; // holds last significant bits, counter (counts bytes)
        private ulong t1 = 0UL; // counter: Length up to 2^128 are supported
        private ulong f0 = 0UL; // finalization flag, for last block: ~0L

        // For Tree Hashing Mode, not used here:
        // private long f1 = 0L; // finalization flag, for last node: ~0L

        /**
         * Blake2b for authentication ("Prefix-MAC mode").
         * After calling the doFinal() method, the key will
         * remain to be used for further computations of
         * this instance.
         * The key can be overwritten using the clearKey() method.
         *
         * @param key A key up to 64 bytes or null
         */
        public Blake2bMac(PinnedMemory<byte> key)
        {
            _buffer = new byte[BlockLengthBytes];
            _bufferPin = new PinnedMemory<byte>(_buffer);
            if (key != null)
            { 
                _key = key;
                if (_key.Length > 64)
                    throw new ArgumentException("Keys > 64 are not supported");

                _keyLength = _key.Length;
                Array.Copy(_key.ToArray(), 0, _buffer, 0, _keyLength);
                _bufferPos = BlockLengthBytes; // zero padding
            }
            _digestLength = 64;
            Init();
        }

        /**
         * Blake2b with key, required digest length (in bytes), salt and personalization.
         * After calling the doFinal() method, the key, the salt and the personal string
         * will remain and might be used for further computations with this instance.
         * The key can be overwritten using the clearKey() method, the salt (pepper)
         * can be overwritten using the clearSalt() method.
         *
         * @param key             A key up to 64 bytes or null
         * @param digestLength    from 1 up to 64 bytes
         * @param salt            16 bytes or null
         * @param personalization 16 bytes or null
         */
        public Blake2bMac(PinnedMemory<byte> key, byte[] salt, int digestLength = 512)
        {
            if (digestLength < 1 || digestLength > 64)
                throw new ArgumentException("Invalid digest length (required: 1 - 64)");

            this._digestLength = digestLength;
            _buffer = new byte[BlockLengthBytes];
            _bufferPin = new PinnedMemory<byte>(_buffer);

            if (salt != null)
            {
                if (salt.Length != 16)
                    throw new ArgumentException("salt length must be exactly 16 bytes");

                this._salt = new byte[16];
                Array.Copy(salt, 0, this._salt, 0, salt.Length);
            }

            if (key != null)
            {
                if (key.Length > 64)
                    throw new ArgumentException("Keys > 64 are not supported");

                _key = key;
                _keyLength = key.Length;
                _bufferPos = BlockLengthBytes; // zero padding
            }

            Init();
        }

        // initialize chainValue
        private void Init()
        {
            if (_chainValue == null)
            {
                _chainValue = new ulong[8];

                _chainValue[0] = Blake2BIv[0] ^ (ulong)(_digestLength | (_keyLength << 8) | 0x1010000);

                // 0x1010000 = ((fanout << 16) | (depth << 24) | (leafLength <<
                // 32));
                // with fanout = 1; depth = 0; leafLength = 0;
                _chainValue[1] = Blake2BIv[1];// ^ nodeOffset; with nodeOffset = 0;
                _chainValue[2] = Blake2BIv[2];// ^ ( nodeDepth | (innerHashLength << 8) );
                // with nodeDepth = 0; innerHashLength = 0;

                _chainValue[3] = Blake2BIv[3];

                _chainValue[4] = Blake2BIv[4];
                _chainValue[5] = Blake2BIv[5];
                if (_salt != null)
                {
                    _chainValue[4] ^= LE_To_UInt64(_salt, 0);
                    _chainValue[5] ^= LE_To_UInt64(_salt, 8);
                }

                _chainValue[6] = Blake2BIv[6];
                _chainValue[7] = Blake2BIv[7];
            }
        }

        private void InitializeInternalState()
        {
            // initialize v:
            Array.Copy(_chainValue, 0, _internalState, 0, _chainValue.Length);
            Array.Copy(Blake2BIv, 0, _internalState, _chainValue.Length, 4);
            _internalState[12] = t0 ^ Blake2BIv[4];
            _internalState[13] = t1 ^ Blake2BIv[5];
            _internalState[14] = f0 ^ Blake2BIv[6];
            _internalState[15] = Blake2BIv[7];// ^ f1 with f1 = 0
        }

        /**
         * update the message digest with a single byte.
         *
         * @param b the input byte to be entered.
         */
        public virtual void Update(byte b)
        {
            var remainingLength = 0; // left bytes of buffer

            // process the buffer if full else add to buffer:
            remainingLength = BlockLengthBytes - _bufferPos;
            if (remainingLength == 0)
            { // full buffer
                t0 += BlockLengthBytes;
                if (t0 == 0)
                { // if message > 2^64
                    t1++;
                }
                Compress(_buffer, 0);
                Array.Clear(_buffer, 0, _buffer.Length);// clear buffer
                _buffer[0] = b;
                _bufferPos = 1;
            }
            else
            {
                _buffer[_bufferPos] = b;
                _bufferPos++;
                return;
            }
        }

        public virtual void UpdateBlock(PinnedMemory<byte> message, int offset, int len)
        {
            UpdateBlock(message.ToArray(), offset, len);
            message.Dispose();
        }

        /**
         * update the message digest with a block of bytes.
         *
         * @param message the byte array containing the data.
         * @param offset  the offset into the byte array where the data starts.
         * @param len     the length of the data.
         */
        public virtual void UpdateBlock(byte[] message, int offset, int len)
        {
            if (message == null || len == 0)
                return;

            var remainingLength = 0; // left bytes of buffer

            if (_bufferPos != 0)
            { // commenced, incomplete buffer

                // complete the buffer:
                remainingLength = BlockLengthBytes - _bufferPos;
                if (remainingLength < len)
                { // full buffer + at least 1 byte
                    Array.Copy(message, offset, _buffer, _bufferPos,
                        remainingLength);
                    t0 += BlockLengthBytes;
                    if (t0 == 0)
                    { // if message > 2^64
                        t1++;
                    }
                    Compress(_buffer, 0);
                    _bufferPos = 0;
                    Array.Clear(_buffer, 0, _buffer.Length);// clear buffer
                }
                else
                {
                    Array.Copy(message, offset, _buffer, _bufferPos, len);
                    _bufferPos += len;
                    return;
                }
            }

            // process blocks except last block (also if last block is full)
            int messagePos;
            var blockWiseLastPos = offset + len - BlockLengthBytes;
            for (messagePos = offset + remainingLength; messagePos < blockWiseLastPos; messagePos += BlockLengthBytes)
            { // block wise 128 bytes
                // without buffer:
                t0 += BlockLengthBytes;
                if (t0 == 0)
                {
                    t1++;
                }
                Compress(message, messagePos);
            }

            // fill the buffer with left bytes, this might be a full block
            Array.Copy(message, messagePos, _buffer, 0, offset + len
                - messagePos);
            _bufferPos += offset + len - messagePos;
        }

        /**
         * close the digest, producing the final digest value. The doFinal
         * call leaves the digest reset.
         * Key, salt and personal string remain.
         *
         * @param out       the array the digest is to be copied into.
         * @param outOffset the offset into the out array the digest is to start at.
         */
        public virtual void DoFinal(PinnedMemory<byte> output, int outOffset)
        {
            f0 = 0xFFFFFFFFFFFFFFFFUL;
            t0 += (ulong)_bufferPos;
            if (_bufferPos > 0 && t0 == 0)
            {
                t1++;
            }
            Compress(_buffer, 0);
            Array.Clear(_buffer, 0, _buffer.Length);// Holds eventually the key if input is null
            Array.Clear(_internalState, 0, _internalState.Length);

            for (var i = 0; i < _chainValue.Length && (i * 8 < _digestLength); i++)
            {
                var bytes = UInt64_To_LE(_chainValue[i]);

                if (i * 8 < _digestLength - 8)
                {
                    Array.Copy(bytes, 0, output.ToArray(), outOffset + i * 8, 8);
                }
                else
                {
                    Array.Copy(bytes, 0, output.ToArray(), outOffset + i * 8, _digestLength - (i * 8));
                }
            }

            Array.Clear(_chainValue, 0, _chainValue.Length);
            Reset();
        }

        /**
         * Reset the digest back to it's initial state.
         * The key, the salt and the personal string will
         * remain for further computations.
         */
        public virtual void Reset()
        {
            _bufferPos = 0;
            f0 = 0L;
            t0 = 0L;
            t1 = 0L;
            _chainValue = null;
            Array.Clear(_buffer, 0, _buffer.Length);

            if (_key != null)
            {
                Array.Copy(_key.ToArray(), 0, _buffer, 0, _key.Length);
                _bufferPos = BlockLengthBytes; // zero padding
            }
            Init();
        }

        private void Compress(byte[] message, int messagePos)
        {
            InitializeInternalState();

            var m = new ulong[16];
            for (var j = 0; j < 16; j++)
            {
                m[j] = LE_To_UInt64(message, messagePos + j * 8);
            }

            for (var round = 0; round < Rounds; round++)
            {
                // G apply to columns of internalState:m[blake2b_sigma[round][2 * blockPos]] /+1
                G(m[Blake2BSigma[round, 0]], m[Blake2BSigma[round, 1]], 0, 4, 8, 12);
                G(m[Blake2BSigma[round, 2]], m[Blake2BSigma[round, 3]], 1, 5, 9, 13);
                G(m[Blake2BSigma[round, 4]], m[Blake2BSigma[round, 5]], 2, 6, 10, 14);
                G(m[Blake2BSigma[round, 6]], m[Blake2BSigma[round, 7]], 3, 7, 11, 15);
                // G apply to diagonals of internalState:
                G(m[Blake2BSigma[round, 8]], m[Blake2BSigma[round, 9]], 0, 5, 10, 15);
                G(m[Blake2BSigma[round, 10]], m[Blake2BSigma[round, 11]], 1, 6, 11, 12);
                G(m[Blake2BSigma[round, 12]], m[Blake2BSigma[round, 13]], 2, 7, 8, 13);
                G(m[Blake2BSigma[round, 14]], m[Blake2BSigma[round, 15]], 3, 4, 9, 14);
            }

            // update chain values:
            for (var offset = 0; offset < _chainValue.Length; offset++)
            {
                _chainValue[offset] = _chainValue[offset] ^ _internalState[offset] ^ _internalState[offset + 8];
            }
        }

        private void G(ulong m1, ulong m2, int posA, int posB, int posC, int posD)
        {
            _internalState[posA] = _internalState[posA] + _internalState[posB] + m1;
            _internalState[posD] = Rotr64(_internalState[posD] ^ _internalState[posA], 32);
            _internalState[posC] = _internalState[posC] + _internalState[posD];
            _internalState[posB] = Rotr64(_internalState[posB] ^ _internalState[posC], 24); // replaces 25 of BLAKE
            _internalState[posA] = _internalState[posA] + _internalState[posB] + m2;
            _internalState[posD] = Rotr64(_internalState[posD] ^ _internalState[posA], 16);
            _internalState[posC] = _internalState[posC] + _internalState[posD];
            _internalState[posB] = Rotr64(_internalState[posB] ^ _internalState[posC], 63); // replaces 11 of BLAKE
        }

        private static ulong Rotr64(ulong x, int rot)
        {
            return x >> rot | x << -rot;
        }

        /**
         * return the size, in bytes, of the digest produced by this message digest.
         *
         * @return the size, in bytes, of the digest produced by this message digest.
         */
        public virtual int GetLength()
        {
            return _digestLength;
        }

        /**
         * Return the size in bytes of the internal buffer the digest applies it's compression
         * function to.
         *
         * @return byte length of the digests internal buffer.
         */
        public virtual int GetBlockSize()
        {
            return BlockLengthBytes;
        }

        /**
         * Overwrite the key
         * if it is no longer used (zeroization)
         */
        public virtual void ClearKey()
        {
            if (_key == null)
                return;

            Array.Clear(_key.ToArray(), 0, _key.Length);
            Array.Clear(_buffer, 0, _buffer.Length);
        }

        /**
         * Overwrite the salt (pepper) if it
         * is secret and no longer used (zeroization)
         */
        public virtual void ClearSalt()
        {
            if (_salt == null)
                return;

            Array.Clear(_salt, 0, _salt.Length);
        }

        // Little endian 32, and 64 encoding methods
        private uint LE_To_UInt32(byte[] bs, int off)
        {
            return (uint)bs[off]
                   | (uint)bs[off + 1] << 8
                   | (uint)bs[off + 2] << 16
                   | (uint)bs[off + 3] << 24;
        }

        private ulong LE_To_UInt64(byte[] bs, int off)
        {
            var lo = LE_To_UInt32(bs, off);
            var hi = LE_To_UInt32(bs, off + 4);
            return ((ulong)hi << 32) | (ulong)lo;
        }

        private byte[] UInt64_To_LE(ulong n)
        {
            var bs = new byte[8];
            UInt64_To_LE(n, bs, 0);
            return bs;
        }

        private void UInt64_To_LE(ulong n, byte[] bs, int off)
        {
            UInt32_To_LE((uint)(n), bs, off);
            UInt32_To_LE((uint)(n >> 32), bs, off + 4);
        }

        private void UInt32_To_LE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[off + 1] = (byte)(n >> 8);
            bs[off + 2] = (byte)(n >> 16);
            bs[off + 3] = (byte)(n >> 24);
        }

        public void Dispose()
        {
            Reset();
            ClearSalt();
            _bufferPin?.Dispose();
        }
    }
}
