using PinnedMemory;
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Blake2b.NetCore.Examples
{
    class Program
    {
        static void Main(string[] args)
        {
            // WARNING: It's unsafe to output pinned memory as a string, even using bitconverter however for the sake of learning this is done below.
            // DO NOT DO THIS IN YOUR APPLICATION, you should store your pinned data in it's native form so it will remain locked, and pinned in place
            // strings can't be pinned due to there nature, however, for example an array of char[] can be provided it's not converted back to string

            Console.WriteLine("[Example 1]");
            // This is an example of hashing byte[] using PinnedMemory. This is the best method as it protects bytes during creation of the hash
            // and not just the output. It will also zero bytes after there written. However, raw byte[] is also accepted as shown in the commented version.
            var digest = new Blake2b();
            using var exampleHash = new PinnedMemory<byte>(new byte[digest.GetLength()]);
            // digest.UpdateBlock(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, 0, 11); // This may be exposed without being pinned.
            digest.UpdateBlock(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, false),
                0, 11);
            digest.DoFinal(exampleHash, 0);
            Console.WriteLine(BitConverter.ToString(exampleHash.ToArray()));

            Console.WriteLine("[Example 2]");
            // This is a common, but unsafe example of dealing with strings.
            using var exampleHash2 = new PinnedMemory<byte>(new byte[digest.GetLength()]);
            var unsafeCaw = "caw caw caw 2"; // this is unsafe because string's can't be pinned and are subject to garbage collection, and being written to disk (pagefile).
            var caw = new PinnedMemory<byte>(Encoding.UTF8.GetBytes(unsafeCaw), false); // this is now safe but ONLY the variable caw, unsafeCaw is STILL exposed.
            unsafeCaw = string.Empty; // unsafeCaw COULD STILL exposed even tho we set it to empty because this depends on garbage collection getting around to clearing it.
            digest.UpdateBlock(caw, 0, 11);
            digest.DoFinal(exampleHash2, 0);
            Console.WriteLine(BitConverter.ToString(exampleHash2.ToArray()));

            // This is a more uncommon but should be safer example of how to deal with strings.
            Console.WriteLine("[Example 3]");
            using var exampleHash3 = new PinnedMemory<byte>(new byte[digest.GetLength()]);
            var secureCaw = new SecureString();
            secureCaw.AppendChar('c');
            secureCaw.AppendChar('a');
            secureCaw.AppendChar('w');
            secureCaw.AppendChar(' ');
            secureCaw.AppendChar('c');
            secureCaw.AppendChar('a');
            secureCaw.AppendChar('w');
            secureCaw.AppendChar(' ');
            secureCaw.AppendChar('c');
            secureCaw.AppendChar('a');
            secureCaw.AppendChar('w');
            secureCaw.AppendChar(' ');
            secureCaw.AppendChar('3');
            secureCaw.MakeReadOnly();

            using var pinnedCaw = new PinnedMemory<char>(new char[secureCaw.Length]);
            var cawPointer = Marshal.SecureStringToBSTR(secureCaw);
            for (var i = 0; i <= secureCaw.Length - 1; i++)
            {
                var c = (char)Marshal.ReadByte(cawPointer, i * 2);
                pinnedCaw.Write(i, c);
            }

            using var pinnedCawBytes = new PinnedMemory<byte>(Encoding.UTF8.GetBytes(pinnedCaw.ToArray()), false);
            digest.UpdateBlock(pinnedCawBytes, 0, secureCaw.Length);
            digest.DoFinal(exampleHash3, 0);
            Console.WriteLine(BitConverter.ToString(exampleHash3.ToArray()));
        }
    }
}
