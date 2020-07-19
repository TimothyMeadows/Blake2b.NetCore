# Blake2b.NetCore
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![nuget](https://img.shields.io/nuget/v/Blake2b.NetCore.svg)](https://www.nuget.org/packages/Blake2b.NetCore/)

Implementation of the cryptographic hash function BLAKE2b. Optimized for PinnedMemory, and 64-bit platforms and produces digests of any size between 1 and 64 bytes.

# Install

From a command prompt
```bash
dotnet add package Blake2b.NetCore
```

```bash
Install-Package Blake2b.NetCore
```

You can also search for package via your nuget ui / website:

https://www.nuget.org/packages/Blake2b.NetCore/

# Examples

You can find more examples in the github examples project.

```csharp
var digest = new Blake2b();
using var exampleHash = new PinnedMemory<byte>(new byte[digest.GetLength()]);
digest.UpdateBlock(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, false), 0, 11);
digest.DoFinal(exampleHash, 0);
```
