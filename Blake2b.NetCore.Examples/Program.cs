using PinnedMemory;
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using Blake2b.NetCore.Examples.Examples;

namespace Blake2b.NetCore.Examples
{
    class Program
    {
        static void Main(string[] args)
        {
            ByteArrayExample.Run();
            StringExample.Run();
        }
    }
}
