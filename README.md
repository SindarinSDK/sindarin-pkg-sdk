# Sindarin SDK

A comprehensive standard library for the [Sindarin](https://github.com/SindarinSDK/sindarin-compiler) programming language, providing modules for I/O, networking, cryptography, encoding, and more.

## Installation

Add the SDK as a dependency in your `sn.yaml`:

```yaml
dependencies:
- name: sindarin-pkg-sdk
  git: git@github.com:SindarinSDK/sindarin-pkg-sdk.git
  branch: main
```

Then run `sn pkg install` to fetch the package.

## Quick Start

```sindarin
import "sdk/time/date"
import "sdk/time/time"
import "sdk/os/env"
import "sdk/core/random"
import "sdk/io/textfile"

fn main(): int =>
    // Current date and time
    var today: Date = Date.today()
    var now: Time = Time.now()
    print($"Today: {today.toIso()}\n")
    print($"Now: {now.format("HH:mm:ss")}\n")

    // Environment variables
    var user: str = Environment.getOr("USER", "unknown")
    print($"User: {user}\n")

    // Random values
    var dice: int = Random.randInt(1, 6)
    print($"Dice roll: {dice}\n")

    // File I/O
    TextFile.writeAll("/tmp/hello.txt", "Hello, SDK!")
    var content: str = TextFile.readAll("/tmp/hello.txt")
    print($"File: {content}\n")

    return 0
```

## Documentation

Full documentation is available in the [docs](./docs/) folder.

### Overview

- [SDK Overview](./docs/overview.md) - Introduction and shared concepts

### Core

General-purpose utilities for math, randomness, and identifiers.

| Module | Import | Description |
|--------|--------|-------------|
| [Math](./docs/core/math.md) | `import "sdk/core/math"` | Mathematical functions and constants |
| [Random](./docs/core/random.md) | `import "sdk/core/random"` | Random number generation |
| [UUID](./docs/core/uuid.md) | `import "sdk/core/uuid"` | UUID generation and parsing |

### Crypto

| Module | Import | Description |
|--------|--------|-------------|
| [Crypto](./docs/crypto/crypto.md) | `import "sdk/crypto/crypto"` | Hashing, encryption, HMAC, PBKDF2 |

### Encoding

Data serialization, parsing, and compression.

| Module | Import | Description |
|--------|--------|-------------|
| [JSON](./docs/encoding/json.md) | `import "sdk/encoding/json"` | JSON parsing and serialization |
| [XML](./docs/encoding/xml.md) | `import "sdk/encoding/xml"` | XML parsing, XPath, DOM manipulation |
| [YAML](./docs/encoding/yaml.md) | `import "sdk/encoding/yaml"` | YAML parsing and serialization |
| [ZLib](./docs/encoding/zlib.md) | `import "sdk/encoding/zlib"` | Compression and decompression |

### I/O

File operations, path utilities, directory management, and standard streams.

| Module | Import | Description |
|--------|--------|-------------|
| [Overview](./docs/io/index.md) | | I/O module overview |
| [TextFile](./docs/io/textfile.md) | `import "sdk/io/textfile"` | Text file reading/writing |
| [BinaryFile](./docs/io/binaryfile.md) | `import "sdk/io/binaryfile"` | Binary file operations |
| [Path](./docs/io/path.md) | `import "sdk/io/path"` | Path manipulation utilities |
| [Directory](./docs/io/directory.md) | `import "sdk/io/directory"` | Directory operations |
| [Bytes](./docs/io/bytes.md) | `import "sdk/io/bytes"` | Byte encoding/decoding (hex, base64) |
| [Stdio](./docs/io/stdio.md) | `import "sdk/io/stdio"` | Standard input/output/error streams |

### Net

TCP, UDP, TLS, DTLS, SSH, QUIC, and Git networking.

| Module | Import | Description |
|--------|--------|-------------|
| [Overview](./docs/net/index.md) | | Networking module overview |
| [TCP](./docs/net/tcp.md) | `import "sdk/net/tcp"` | TCP client and server |
| [UDP](./docs/net/udp.md) | `import "sdk/net/udp"` | UDP sockets |
| [TLS](./docs/net/tls.md) | `import "sdk/net/tls"` | TLS-encrypted connections |
| [DTLS](./docs/net/dtls.md) | `import "sdk/net/dtls"` | DTLS-encrypted UDP |
| [SSH](./docs/net/ssh.md) | `import "sdk/net/ssh"` | SSH client and server |
| [QUIC](./docs/net/quic.md) | `import "sdk/net/quic"` | QUIC protocol |
| [Git](./docs/net/git.md) | `import "sdk/net/git"` | Git repository operations |

### OS

Operating system and process interaction.

| Module | Import | Description |
|--------|--------|-------------|
| [OS](./docs/os/os.md) | `import "sdk/os/os"` | OS detection utilities |
| [Environment](./docs/os/env.md) | `import "sdk/os/env"` | Environment variable access |
| [Process](./docs/os/process.md) | `import "sdk/os/process"` | Process execution |

### Time

Calendar dates and timestamps.

| Module | Import | Description |
|--------|--------|-------------|
| [Date](./docs/time/date.md) | `import "sdk/time/date"` | Calendar date operations |
| [Time](./docs/time/time.md) | `import "sdk/time/time"` | Time and duration operations |

## Running Tests

To run the SDK test suite:

```bash
make test
```

This will compile and run all tests with parallel execution. Use `make help` to see all available targets.

## Dependencies

The SDK depends on [sindarin-libs](https://github.com/SindarinSDK/sindarin-libs) for native library bindings (OpenSSL, zlib, etc.). Dependencies are automatically managed via the `sn.yaml` package manifest.

## License

MIT License - see [LICENSE](./LICENSE) for details.
