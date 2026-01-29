---
title: "TLS"
description: "TLS-encrypted TCP connections"
permalink: /sdk/net/tls/
---

TLS provides encrypted TCP connections using OpenSSL. `TlsStream` wraps a TCP socket with TLS encryption, enabling secure communication with HTTPS servers and other TLS-enabled services. `TlsListener` provides server-side TLS, accepting incoming connections and wrapping them with encryption.

## Import

```sindarin
import "sdk/net/tls"
```

---

## TlsStream

A TLS-encrypted TCP connection for secure bidirectional communication.

```sindarin
var conn: TlsStream = TlsStream.connect("example.com:443")
conn.writeLine("GET / HTTP/1.1")
conn.writeLine("Host: example.com")
conn.writeLine("Connection: close")
conn.writeLine("")

var response: byte[] = conn.readAll()
print(response.toString())
conn.close()
```

### Static Methods

#### TlsStream.connect(address)

Connects to a remote host with TLS encryption. Performs DNS resolution, TCP connection, TLS handshake, and certificate verification.

```sindarin
// Connect with explicit port
var conn: TlsStream = TlsStream.connect("example.com:443")

// IPv6 address
var v6: TlsStream = TlsStream.connect("[::1]:443")
```

The address format is `host:port`. The connection will fail (panic) if:
- DNS resolution fails
- TCP connection is refused
- TLS handshake fails
- Server certificate verification fails

### Instance Methods

#### read(maxBytes)

Reads up to `maxBytes` bytes from the encrypted stream. May return fewer bytes than requested.

```sindarin
var data: byte[] = conn.read(1024)
print($"Received {data.length} bytes\n")
```

#### readAll()

Reads all remaining data until the connection is closed by the remote peer.

```sindarin
var response: byte[] = conn.readAll()
```

#### readLine()

Reads until a newline character (`\n`). Strips trailing `\r\n` or `\n`. Blocks until a complete line is available.

```sindarin
var line: str = conn.readLine()
```

#### write(data)

Writes a byte array to the encrypted stream. Returns the number of bytes written.

```sindarin
var data: byte[] = "Hello".toBytes()
var sent: int = conn.write(data)
```

#### writeLine(text)

Writes a string followed by `\r\n` to the encrypted stream.

```sindarin
conn.writeLine("GET / HTTP/1.1")
conn.writeLine("Host: example.com")
conn.writeLine("")  // empty line ends HTTP headers
```

#### remoteAddress()

Returns the remote address string as passed to `connect()`.

```sindarin
var addr: str = conn.remoteAddress()
print($"Connected to: {addr}\n")
```

#### close()

Performs a TLS shutdown, frees the SSL context, and closes the underlying TCP socket. Safe to call multiple times.

```sindarin
conn.close()
```

---

## TlsListener

A TLS server that listens for incoming encrypted TCP connections. Accepts connections and wraps them with TLS, returning `TlsStream` instances.

```sindarin
var server: TlsListener = TlsListener.bind(":8443", "cert.pem", "key.pem")
var conn: TlsStream = server.accept()
var line: str = conn.readLine()
conn.writeLine($"Echo: {line}")
conn.close()
server.close()
```

### Static Methods

#### TlsListener.bind(address, certFile, keyFile)

Creates a TLS server listening on the specified address. Requires paths to a PEM-encoded certificate file and private key file.

```sindarin
// Listen on all interfaces, port 8443
var server: TlsListener = TlsListener.bind(":8443", "cert.pem", "key.pem")

// Listen on specific interface
var local: TlsListener = TlsListener.bind("127.0.0.1:8443", "cert.pem", "key.pem")

// OS-assigned port
var dynamic: TlsListener = TlsListener.bind(":0", "cert.pem", "key.pem")
print($"Listening on port {dynamic.port()}\n")
```

### Instance Methods

#### accept()

Waits for and accepts a new TLS connection. Blocks until a client connects and the TLS handshake completes. Returns a `TlsStream` for bidirectional encrypted communication.

```sindarin
var client: TlsStream = server.accept()
```

#### port()

Returns the port number the listener is bound to. Useful when binding to port `0` (OS-assigned).

```sindarin
var p: int = server.port()
```

#### close()

Closes the listener socket. Safe to call multiple times.

```sindarin
server.close()
```

---

## Example: TLS Echo Server

```sindarin
import "sdk/net/tls"

fn main(): void =>
    var server: TlsListener = TlsListener.bind(":8443", "server.crt", "server.key")
    print($"TLS server listening on port {server.port()}\n")

    while true =>
        var client: TlsStream = server.accept()
        var line: str = client.readLine()
        client.writeLine($"Echo: {line}")
        client.close()
```

---

## Certificate Verification

TlsStream verifies the server's certificate chain on every connection. Certificates are loaded in this priority order:

### 1. SN_CERTS Environment Variable

If set, certificates are loaded from the specified path. The value can be either a PEM file or a directory containing PEM files.

```bash
# Use a custom CA bundle file
export SN_CERTS=/path/to/ca-bundle.crt

# Use a directory of PEM certificates
export SN_CERTS=/path/to/certs/
```

This is useful for:
- Corporate environments with internal Certificate Authorities
- Development with self-signed certificates
- Containers or minimal environments without system certificates

### 2. Platform-Native Certificate Store (fallback)

If `SN_CERTS` is not set, the platform's native certificate store is used:

- **Windows**: Windows Certificate Store (`ROOT` store via CryptoAPI)
- **macOS**: System Keychain (via Security.framework)
- **Linux**: OpenSSL default paths (e.g., `/etc/ssl/certs/`)

---

## Error Handling

All TLS operations panic on failure with a descriptive error message:

| Operation | Failure Causes |
|-----------|---------------|
| `connect()` | DNS failure, connection refused, handshake failure, certificate verification failure |
| `read()` / `readAll()` / `readLine()` | Connection reset, SSL error |
| `write()` / `writeLine()` | Broken pipe, SSL error |

---

## Example: HTTPS GET Request

```sindarin
import "sdk/net/tls"

fn main(): void =>
    var conn: TlsStream = TlsStream.connect("httpbin.org:443")

    conn.writeLine("GET /get HTTP/1.1")
    conn.writeLine("Host: httpbin.org")
    conn.writeLine("Connection: close")
    conn.writeLine("")

    # Read status line
    var status: str = conn.readLine()
    print($"Status: {status}\n")

    # Read headers
    while true =>
        var header: str = conn.readLine()
        if header == "" =>
            break
        print($"{header}\n")

    # Read body
    var body: byte[] = conn.readAll()
    print(body.toString())

    conn.close()
```

---

## See Also

- [Net Overview](readme.md) - Network I/O concepts
- [TCP](tcp.md) - TCP connection-oriented communication
- [DTLS](dtls.md) - DTLS-encrypted UDP datagrams
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/net/tls.sn`
