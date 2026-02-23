# Blake2b.NetCore

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![nuget](https://img.shields.io/nuget/v/Blake2b.NetCore.svg)](https://www.nuget.org/packages/Blake2b.NetCore/)

`Blake2b.NetCore` is a .NET implementation of the [BLAKE2b](https://www.blake2.net/) cryptographic hash function with support for both:

- **Unkeyed hashing** (`Blake2b`)
- **Keyed hashing / MAC** (`Blake2bMac`)

The implementation is optimized for 64-bit platforms and integrates with [`PinnedMemory`](https://github.com/TimothyMeadows/PinnedMemory) to support memory-sensitive use cases.

Hash compression and digest serialization use SIMD-aware fast paths on supported runtimes, with an automatic scalar fallback to preserve correctness on non-SIMD hardware.

> This implementation does **not** support BLAKE2 tree hashing mode.

---

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
  - [Hashing with Blake2b](#hashing-with-blake2b)
  - [Message authentication with Blake2bMac](#message-authentication-with-blake2bmac)
- [API reference](#api-reference)
  - [`Blake2b`](#blake2b)
  - [`Blake2bMac`](#blake2bmac)
- [Performance notes](#performance-notes)
- [Best practices](#best-practices)
- [Validation and known test vectors](#validation-and-known-test-vectors)
- [Development](#development)
- [Security notes](#security-notes)
- [License](#license)

---

## Requirements

- **.NET 8 SDK** for building/testing this repository.
- Target runtime/framework for the project: **.NET 8**.

The repository contains a `global.json` pinning the SDK family used for development.

---

## Installation

### NuGet Package Manager (CLI)

```bash
dotnet add package Blake2b.NetCore
```

### Package Manager Console

```powershell
Install-Package Blake2b.NetCore
```

### NuGet Gallery

- https://www.nuget.org/packages/Blake2b.NetCore/

---

## Quick start

### Hashing with Blake2b

```csharp
using System;
using System.Text;
using Blake2b.NetCore;
using PinnedMemory;

var message = Encoding.UTF8.GetBytes("hello world");

using var blake2b = new Blake2b(); // default: 512-bit output (64 bytes)
using var output = new PinnedMemory<byte>(new byte[blake2b.GetLength()]);

blake2b.UpdateBlock(message, 0, message.Length);
blake2b.DoFinal(output, 0);

var hashHex = Convert.ToHexString(output.ToArray()).ToLowerInvariant();
Console.WriteLine(hashHex);
```

### Message authentication with Blake2bMac

```csharp
using System;
using System.Text;
using Blake2b.NetCore;
using PinnedMemory;

var message = Encoding.UTF8.GetBytes("payload");
using var key = new PinnedMemory<byte>(Encoding.UTF8.GetBytes("a-32-byte-demo-key-change-me-1234"), false);

using var mac = new Blake2bMac(key); // default: 64-byte output
using var output = new PinnedMemory<byte>(new byte[mac.GetLength()]);

mac.UpdateBlock(message, 0, message.Length);
mac.DoFinal(output, 0);

var macHex = Convert.ToHexString(output.ToArray()).ToLowerInvariant();
Console.WriteLine(macHex);

// Optional explicit zeroization of sensitive inputs when done:
mac.ClearKey();
```

---

## API reference

## `Blake2b`

### Constructor

```csharp
Blake2b(int digestSize = 512)
```

- `digestSize` is in **bits**.
- Valid range: **8..512**, in multiples of 8.
- Examples: 256 => 32-byte digest, 512 => 64-byte digest.

### Core methods

```csharp
void Update(byte b)
void UpdateBlock(byte[] message, int offset, int len)
void UpdateBlock(PinnedMemory<byte> message, int offset, int len)
void DoFinal(PinnedMemory<byte> output, int outOffset)
void Reset()
int GetLength()
int GetBlockSize()
void Dispose()
```

### Behavior notes

- `DoFinal(...)` finalizes and then resets internal state so the instance can be reused.
- `GetLength()` returns output length in **bytes**.
- `GetBlockSize()` returns 128 bytes for BLAKE2b.

---

## `Blake2bMac`

### Constructors

```csharp
Blake2bMac(PinnedMemory<byte> key)
Blake2bMac(PinnedMemory<byte> key, byte[] salt, int digestLength = 64)
```

- `key` length: 0..64 bytes.
- `digestLength` is in **bytes**, valid range 1..64.
- `salt` must be exactly 16 bytes if provided.

### Core methods

```csharp
void Update(byte b)
void UpdateBlock(byte[] message, int offset, int len)
void UpdateBlock(PinnedMemory<byte> message, int offset, int len)
void DoFinal(PinnedMemory<byte> output, int outOffset)
void Reset()
int GetLength()
int GetBlockSize()
void ClearKey()
void ClearSalt()
void Dispose()
```

### Behavior notes

- `DoFinal(...)` finalizes and resets while retaining key/salt configuration for reuse.
- `ClearKey()` and `ClearSalt()` allow explicit zeroization of sensitive material.

---

## Performance notes

- On runtimes where `Vector128` hardware acceleration is available, the library uses SIMD-assisted code paths for block word loading and chain-value folding in both `Blake2b` and `Blake2bMac`.
- On runtimes without SIMD support, the implementation automatically falls back to scalar processing with identical outputs.
- For validation and troubleshooting, SIMD can be disabled at runtime via the `AppContext` switch `Blake2b.NetCore.DisableSimd` (used by the test suite to assert SIMD/scalar parity).

---

## Best practices

### 1) Prefer keyed mode (`Blake2bMac`) for authenticity

- Use `Blake2b` for integrity fingerprinting.
- Use `Blake2bMac` when you need an authentication tag with a secret key.

### 2) Validate digest size intentionally

- For compatibility with many external systems, 32-byte (256-bit) or 64-byte (512-bit) digests are common.
- Keep digest length consistent across all producers/consumers.

### 3) Reuse instances when hashing many messages serially

- `DoFinal(...)` resets state, so a single instance can process many independent messages.
- Avoid sharing one instance across concurrent threads.

### 4) Handle sensitive material explicitly

- Keep MAC keys in pinned memory where practical.
- Call `ClearKey()`/`ClearSalt()` when secrets are no longer needed.
- Dispose instances promptly (`using` blocks).

### 5) Stream large inputs in chunks

- For files or network payloads, feed chunks via `UpdateBlock(...)` instead of loading everything in memory.
- Example chunk size: 4 KB to 1 MB depending on I/O profile.

### 6) Use fixed encoding when hashing strings

- Always pick an explicit encoding (`UTF8`, `ASCII`, etc.).
- Do not hash language runtime string memory directly.

---

## Validation and known test vectors

The test project validates implementation behavior against published vectors and verifies SIMD/scalar parity, including:

- BLAKE2b-512 of empty string
- BLAKE2b-512 of `"abc"`
- Equivalence checks between SIMD-enabled and SIMD-disabled execution paths for `Blake2b` and `Blake2bMac`

Example expected values:

- Empty string:
  `786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce`
- `abc`:
  `ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923`

---

## Development

### Build

```bash
dotnet build Blake2b.NetCore.sln
```

### Test

```bash
dotnet test Blake2b.NetCore.sln
```

If `dotnet` is installed locally but not on `PATH`, invoke it explicitly:

```bash
$HOME/.dotnet/dotnet test Blake2b.NetCore.sln
```

---

## Security notes

- This library implements BLAKE2b and keyed BLAKE2b MAC, but not tree hashing mode.
- Cryptographic usage should be reviewed for your threat model and protocol requirements.
- For protocol interoperability, ensure all participants agree on:
  - digest size
  - keyed vs unkeyed mode
  - key and salt handling conventions
  - input canonicalization and text encoding

---

## License

MIT. See [LICENSE](LICENSE).
