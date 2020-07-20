# Blake2b.NetCore
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![nuget](https://img.shields.io/nuget/v/Blake2b.NetCore.svg)](https://www.nuget.org/packages/Blake2b.NetCore/)

Implementation of the cryptographic hash function [BLAKE2b](https://tools.ietf.org/html/draft-saarinen-blake2-02). Optimized for [PinnedMemory](https://github.com/TimothyMeadows/PinnedMemory), and 64-bit platforms.

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

# Constructor

Digest size restricted to 160, 256, 384, 512

```csharp
Blake2b(int digestSize = 512)
```
# Methods

Update the message digest with a single byte.
```csharp
void Update(byte b)
```

Update the message digest with a pinned memory byte array.
```csharp
void UpdateBlock(PinnedMemory<byte> message, int offset, int len)
```

Update the message digest with a byte array.
```csharp
void UpdateBlock(byte[] message, int offset, int len)
```

Produce the final digest value outputting to pinned memory. Key & salt remain until dispose is called.
```csharp
void DoFinal(PinnedMemory<byte> output, int outOffset)
```

Reset the digest back to it's initial state for further processing. Key & salt remain until dispose is called.
```csharp
void Reset()
```

Clear key & salt, reset digest back to it's initial state.
```csharp
void Dispose()
```
