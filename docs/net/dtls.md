---
title: "DTLS"
description: "DTLS-encrypted UDP communication"
permalink: /sdk/net/dtls/
---

DTLS (Datagram TLS) provides TLS-level encryption over UDP datagrams. Unlike TLS which operates over TCP streams, DTLS preserves message boundaries — each `send()` corresponds to exactly one `receive()` on the other end. `DtlsListener` provides server-side DTLS with cookie exchange for DoS protection.

## Import

```sindarin
import "sdk/net/dtls"
```

---

## DtlsConnection

A DTLS-encrypted UDP connection for secure datagram communication.

```sindarin
var conn: DtlsConnection = DtlsConnection.connect("server:4433")
conn.send("Hello".toBytes())
var response: byte[] = conn.receive(1024)
print(response.toString())
conn.close()
```

### Static Methods

#### DtlsConnection.connect(address)

Connects to a remote host with DTLS encryption. Creates a connected UDP socket, performs the DTLS handshake, and verifies the server certificate.

```sindarin
var conn: DtlsConnection = DtlsConnection.connect("server.example.com:4433")
```

The address format is `host:port`. Default port is 4433 if omitted. The connection will fail (panic) if:
- DNS resolution fails
- UDP socket creation fails
- DTLS handshake fails
- Server certificate verification fails

### Instance Methods

#### send(data)

Sends an encrypted datagram. Returns the number of bytes sent. Each call sends exactly one DTLS record.

```sindarin
var data: byte[] = "Hello".toBytes()
var sent: int = conn.send(data)
```

**MTU Note:** DTLS has a maximum datagram size (typically ~1200 bytes for safe transmission over the internet). Sending larger datagrams may result in fragmentation or failure.

#### receive(maxBytes)

Receives a single encrypted datagram, up to `maxBytes` in size. Blocks until a datagram arrives or the connection is closed. Returns an empty byte array on timeout or connection close.

```sindarin
var data: byte[] = conn.receive(1024)
if data.length > 0 =>
    print($"Received: {data.toString()}\n")
```

#### remoteAddress()

Returns the remote address string as passed to `connect()`.

```sindarin
var addr: str = conn.remoteAddress()
print($"Connected to: {addr}\n")
```

#### close()

Performs a DTLS shutdown and closes the underlying UDP socket. Safe to call multiple times.

```sindarin
conn.close()
```

---

## DtlsListener

A DTLS server that listens for incoming encrypted datagram connections. Uses OpenSSL DTLS cookie exchange for DoS protection.

```sindarin
var server: DtlsListener = DtlsListener.bind(":4433", "cert.pem", "key.pem")
var conn: DtlsConnection = server.accept()
var data: byte[] = conn.receive(1024)
conn.send(data)  // echo back
conn.close()
server.close()
```

### Static Methods

#### DtlsListener.bind(address, certFile, keyFile)

Creates a DTLS server listening on the specified address. Requires paths to a PEM-encoded certificate file and private key file.

```sindarin
// Listen on all interfaces, port 4433
var server: DtlsListener = DtlsListener.bind(":4433", "cert.pem", "key.pem")

// OS-assigned port
var dynamic: DtlsListener = DtlsListener.bind(":0", "cert.pem", "key.pem")
print($"Listening on port {dynamic.port()}\n")
```

### Instance Methods

#### accept()

Waits for and accepts a new DTLS connection. Blocks until a client connects and the DTLS handshake (including cookie exchange) completes. Returns a `DtlsConnection` for bidirectional encrypted datagram communication.

```sindarin
var client: DtlsConnection = server.accept()
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

## Example: DTLS Echo Server

```sindarin
import "sdk/net/dtls"

fn main(): void =>
    var server: DtlsListener = DtlsListener.bind(":4433", "server.crt", "server.key")
    print($"DTLS server listening on port {server.port()}\n")

    while true =>
        var conn: DtlsConnection = server.accept()
        var data: byte[] = conn.receive(1024)
        if data.length > 0 =>
            conn.send(data)
        conn.close()
```

---

## Certificate Verification

DtlsConnection verifies the server's certificate chain on every connection, using the same priority as TlsStream:

### 1. SN_CERTS Environment Variable

```bash
export SN_CERTS=/path/to/ca-bundle.crt
```

### 2. Platform-Native Certificate Store (fallback)

- **Windows**: Windows Certificate Store (CryptoAPI)
- **macOS**: System Keychain (Security.framework)
- **Linux**: OpenSSL default paths

---

## DTLS vs TLS

| Feature | TlsStream (TLS) | DtlsConnection (DTLS) |
|---------|-----------------|----------------------|
| Transport | TCP | UDP |
| Message boundaries | No (stream) | Yes (datagram) |
| Ordering | Guaranteed | Not guaranteed |
| Reliability | Guaranteed | Not guaranteed |
| Methods | read/readAll/readLine/write/writeLine | send/receive |
| Use case | HTTP, file transfer | Real-time, IoT, VPN |

---

## Error Handling

| Operation | Failure Causes |
|-----------|---------------|
| `connect()` | DNS failure, handshake timeout, certificate failure |
| `send()` | Connection closed, SSL error |
| `receive()` | Connection reset, SSL error (returns empty on timeout) |

---

## Example: Encrypted Echo Client

```sindarin
import "sdk/net/dtls"

fn main(): void =>
    var conn: DtlsConnection = DtlsConnection.connect("echo-server:4433")

    var messages: str[] = ["Hello", "World", "DTLS works!"]

    for msg in messages =>
        conn.send(msg.toBytes())
        var response: byte[] = conn.receive(1024)
        print($"Sent: {msg}, Received: {response.toString()}\n")

    conn.close()
```

---

## Testing with OpenSSL

To test locally, create a self-signed certificate and start a DTLS echo server:

```bash
# Generate test certificate
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=localhost"

# Start DTLS echo server
openssl s_server -dtls -accept 4433 -cert server.crt -key server.key

# Point Sindarin to the test certificate
export SN_CERTS=server.crt
```

---

## See Also

- [Net Overview](readme.md) - Network I/O concepts
- [UDP](udp.md) - UDP socket operations
- [TLS](tls.md) - TLS-encrypted TCP streams
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/net/dtls.sn`
