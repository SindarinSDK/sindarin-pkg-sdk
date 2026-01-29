# Sindarin SDK

The Sindarin SDK provides a collection of modules that extend the language's capabilities. SDK modules are imported using the `import` statement and provide types and functions for common programming tasks.

## Modules

| Category | Module | Import | Description |
|----------|--------|--------|-------------|
| **Core** | [Math](core/math.md) | `import "sdk/core/math"` | Mathematical functions and constants |
| | [Random](core/random.md) | `import "sdk/core/random"` | Random number generation |
| | [UUID](core/uuid.md) | `import "sdk/core/uuid"` | UUID generation and parsing |
| **Crypto** | [Crypto](crypto/crypto.md) | `import "sdk/crypto/crypto"` | Cryptographic hashing, encryption, and key derivation |
| **Encoding** | [JSON](encoding/json.md) | `import "sdk/encoding/json"` | JSON parsing and serialization |
| | [XML](encoding/xml.md) | `import "sdk/encoding/xml"` | XML parsing, XPath, and DOM manipulation |
| | [YAML](encoding/yaml.md) | `import "sdk/encoding/yaml"` | YAML parsing and serialization |
| | [ZLib](encoding/zlib.md) | `import "sdk/encoding/zlib"` | Compression and decompression |
| **I/O** | [Stdio](io/stdio.md) | `import "sdk/io/stdio"` | Standard input/output/error streams |
| | [TextFile](io/readme.md) | `import "sdk/io/textfile"` | Text file reading/writing |
| | [BinaryFile](io/readme.md) | `import "sdk/io/binaryfile"` | Binary file operations |
| | [Path](io/readme.md) | `import "sdk/io/path"` | Path utilities |
| | [Directory](io/readme.md) | `import "sdk/io/directory"` | Directory operations |
| | [Bytes](io/readme.md) | `import "sdk/io/bytes"` | Byte encoding/decoding |
| **Net** | [Net](net/readme.md) | `import "sdk/net/..."` | TCP, UDP, TLS, DTLS, SSH, QUIC, and Git networking |
| **OS** | [OS](os/os.md) | `import "sdk/os/os"` | Operating system detection |
| | [Environment](os/env.md) | `import "sdk/os/env"` | Environment variable access |
| | [Process](os/process.md) | `import "sdk/os/process"` | Process execution and output capture |
| **Time** | [Date](time/date.md) | `import "sdk/time/date"` | Calendar date operations |
| | [Time](time/time.md) | `import "sdk/time/time"` | Time and duration operations |

## Quick Start

```sindarin
import "sdk/time/date"
import "sdk/time/time"
import "sdk/os/env"
import "sdk/os/process"
import "sdk/core/random"
import "sdk/core/uuid"
import "sdk/io/textfile"
import "sdk/net/tcp"

fn main(): int =>
  // Current date and time
  var today: Date = Date.today()
  var now: Time = Time.now()
  print($"Today: {today.toIso()}\n")
  print($"Now: {now.format("HH:mm:ss")}\n")

  // Environment variables
  var user: str = Environment.getOr("USER", "unknown")
  print($"User: {user}\n")

  // Run external command
  var p: Process = Process.run("pwd")
  print($"Current dir: {p.stdout()}")

  // Random values
  var dice: int = Random.int(1, 6)
  print($"Dice roll: {dice}\n")

  // Generate UUID
  var id: UUID = UUID.create()
  print($"ID: {id}\n")

  // File I/O
  TextFile.writeAll("/tmp/hello.txt", "Hello, SDK!")
  var content: str = TextFile.readAll("/tmp/hello.txt")
  print($"File: {content}\n")

  return 0
```

---

## Shared Concepts

### Import Syntax

SDK modules are imported by path relative to the SDK root:

```sindarin
import "sdk/time/date"      // Time module
import "sdk/io/textfile"    // I/O module
import "sdk/encoding/json"  // Encoding module
```

### Naming Conventions

SDK types use the `Sn` prefix to distinguish them from built-in types:

| SDK Type | Description |
|----------|-------------|
| `Date` | Calendar date |
| `Time` | Timestamp |
| `OS` | Operating system detection |
| `Environment` | Environment variables |
| `Process` | Process execution |
| `TextFile` | Text file handle |
| `BinaryFile` | Binary file handle |
| `Path` | Path utilities |
| `Directory` | Directory operations |
| `Bytes` | Byte encoding/decoding |
| `TcpListener` | TCP server socket |
| `TcpStream` | TCP connection |
| `UdpSocket` | UDP socket |
| `TlsStream` | TLS-encrypted TCP connection |
| `DtlsConnection` | DTLS-encrypted UDP connection |
| `SshConnection` | SSH client connection |
| `SshListener` | SSH server listener |
| `QuicConnection` | QUIC connection |
| `QuicListener` | QUIC server listener |
| `QuicStream` | QUIC stream |
| `GitRepo` | Git repository |
| `GitCommit` | Git commit metadata |
| `GitBranch` | Git branch reference |
| `GitRemote` | Git remote configuration |
| `GitDiff` | Git diff entry |
| `GitStatus` | Git working tree status entry |
| `GitTag` | Git tag reference |
| `Crypto` | Cryptographic operations |
| `Json` | JSON value |
| `Xml` | XML node |
| `Yaml` | YAML node |
| `Stdin` | Standard input |
| `Stdout` | Standard output |
| `Stderr` | Standard error |

Some types like `Random` and `UUID` don't use the prefix as they have no built-in equivalent.

### Static vs Instance Methods

SDK types typically provide both static methods (called on the type) and instance methods (called on values):

```sindarin
// Static method - called on the type
var today: Date = Date.today()
var exists: bool = TextFile.exists("file.txt")

// Instance method - called on a value
var formatted: str = today.format("YYYY-MM-DD")
var line: str = file.readLine()
```

### Error Handling

SDK operations that can fail will panic with a descriptive error message. Use existence checks to avoid panics:

```sindarin
// Check before operations that require existing files
if TextFile.exists(path) =>
  var content: str = TextFile.readAll(path)
else =>
  print("File not found\n")
```

Future SDK versions may introduce a `Result` type for recoverable error handling.

### Memory Management

SDK types integrate with Sindarin's arena-based memory management:

- **Automatic cleanup**: Resources are released when their arena is destroyed
- **Private functions**: Use `private fn` for guaranteed cleanup of temporary resources
- **Explicit release**: Call `.close()` for immediate resource release

```sindarin
// Automatic - file closes when function returns
fn readConfig(): str =>
  var f: TextFile = TextFile.open("config.txt")
  return f.readRemaining()

// Explicit - immediate cleanup
var f: TextFile = TextFile.open("large.log")
processFile(f)
f.close()  // Release now, don't wait for arena
```

See the [I/O documentation](io/readme.md) for detailed memory management patterns with file handles.

---

## Module Reference

### Core

General-purpose utilities for math, randomness, and identifiers.

```sindarin
import "sdk/core/math" as math
import "sdk/core/random"
import "sdk/core/uuid"

var angle: double = math.degToRad(45.0)
var dice: int = Random.int(1, 6)
var id: UUID = UUID.create()
```

[Math →](core/math.md) | [Random →](core/random.md) | [UUID →](core/uuid.md)

### Crypto

Cryptographic hashing, HMAC, AES-256-GCM encryption, PBKDF2 key derivation, and secure random bytes.

```sindarin
import "sdk/crypto/crypto"

var hash: byte[] = Crypto.sha256Str("hello")
var key: byte[] = Crypto.randomBytes(32)
var encrypted: byte[] = Crypto.encrypt(key, plaintext)
var decrypted: byte[] = Crypto.decrypt(key, encrypted)
```

[Full documentation →](crypto/crypto.md)

### Encoding

Data serialization, parsing, and compression.

```sindarin
import "sdk/encoding/json"
import "sdk/encoding/xml"
import "sdk/encoding/yaml"
import "sdk/encoding/zlib"

var doc: Json = Json.parse("{\"name\": \"Alice\"}")
var root: Xml = Xml.parseFile("data.xml")
var config: Yaml = Yaml.parseFile("config.yaml")
```

[JSON →](encoding/json.md) | [XML →](encoding/xml.md) | [YAML →](encoding/yaml.md) | [ZLib →](encoding/zlib.md)

### I/O

File operations, path utilities, directory management, and standard streams.

```sindarin
import "sdk/io/textfile"
import "sdk/io/binaryfile"
import "sdk/io/path"
import "sdk/io/directory"
import "sdk/io/bytes"
import "sdk/io/stdio"

var content: str = TextFile.readAll("data.txt")
var dir: str = Path.directory("/home/user/file.txt")
Stdout.write("Enter name: ")
var name: str = Stdin.readLine()
```

[Full documentation →](io/readme.md) | [Stdio →](io/stdio.md)

### Net

TCP, UDP, TLS, DTLS, SSH, QUIC, and Git operations for network communication.

```sindarin
import "sdk/net/tcp"
import "sdk/net/tls"
import "sdk/net/ssh"
import "sdk/net/quic"
import "sdk/net/git"

var server: TcpListener = TcpListener.bind(":8080")
var secure: TlsStream = TlsStream.connect("example.com:443")
var ssh: SshConnection = SshConnection.connectPassword("server:22", "user", "pass")
var repo: GitRepo = GitRepo.open(".")
```

[Full documentation →](net/readme.md)

### OS

Operating system detection and process interaction.

```sindarin
import "sdk/os/os"
import "sdk/os/env"
import "sdk/os/process"

// Platform detection
if OS.isWindows() =>
    print("Running on Windows\n")
else if OS.isUnix() =>
    print($"Running on {OS.name()}\n")

var user: str = Environment.getOr("USER", "unknown")
var p: Process = Process.runArgs("ls", {"-la"})
if p.success() =>
    print(p.stdout())
```

[OS →](os/os.md) | [Environment →](os/env.md) | [Process →](os/process.md)

### Time

Calendar dates and timestamps.

```sindarin
import "sdk/time/date"
import "sdk/time/time"

var today: Date = Date.today()
var now: Time = Time.now()
var elapsed: int = Time.now().diff(now)
print($"Today: {today.toIso()}\n")
```

[Date →](time/date.md) | [Time →](time/time.md)

---

## See Also

- [Language Overview](../readme.md) - Core language documentation
- SDK source code: `sdk/` directory
