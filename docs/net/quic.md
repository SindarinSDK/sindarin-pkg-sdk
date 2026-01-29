---
title: "QUIC"
description: "QUIC multiplexed encrypted streams"
permalink: /sdk/net/quic/
---

QUIC provides multiplexed, encrypted transport over UDP with low-latency connection establishment. Built on ngtcp2 with OpenSSL, QUIC offers TLS 1.3 encryption, stream multiplexing without head-of-line blocking, and connection migration.

## Import

```sindarin
import "sdk/net/quic"
```

---

## QuicConnection (Client)

A QUIC connection supporting multiplexed bidirectional and unidirectional streams.

```sindarin
var conn: QuicConnection = QuicConnection.connect("server:4433")
var stream: QuicStream = conn.openStream()
stream.writeLine("Hello, QUIC!")
var response: str = stream.readLine()
print(response)
stream.close()
conn.close()
```

### Static Methods

#### QuicConnection.connect(address)

Connects to a QUIC server. Performs the QUIC handshake with TLS 1.3 encryption.

```sindarin
var conn: QuicConnection = QuicConnection.connect("server.example.com:4433")
```

#### QuicConnection.connectWith(address, config)

Connects with custom configuration.

```sindarin
var config: QuicConfig = QuicConfig.defaults()
    .setMaxBidiStreams(100)
    .setIdleTimeout(30000)

var conn: QuicConnection = QuicConnection.connectWith("server:4433", config)
```

#### QuicConnection.connectEarly(address, token)

Connects with 0-RTT early data using a previously saved resumption token. Allows sending data before the handshake completes for reduced latency.

```sindarin
# Save token from previous connection
var token: byte[] = prevConn.resumptionToken()

# Reconnect with 0-RTT
var conn: QuicConnection = QuicConnection.connectEarly("server:4433", token)
```

### Instance Methods

#### openStream()

Opens a new bidirectional stream for reading and writing.

```sindarin
var stream: QuicStream = conn.openStream()
stream.writeLine("request")
var response: str = stream.readLine()
```

#### openUnidirectionalStream()

Opens a new unidirectional stream (write-only from this side).

```sindarin
var stream: QuicStream = conn.openUnidirectionalStream()
stream.writeLine("one-way data")
stream.close()
```

#### acceptStream()

Accepts an incoming stream opened by the peer. Blocks until a stream is available.

```sindarin
var stream: QuicStream = conn.acceptStream()
var msg: str = stream.readLine()
```

#### resumptionToken()

Gets a resumption token for 0-RTT reconnection. Call after the handshake completes.

```sindarin
var token: byte[] = conn.resumptionToken()
# Save token for later use with connectEarly()
```

#### migrate(newLocalAddress)

Migrates the connection to a new local address (e.g., after a network change).

```sindarin
conn.migrate("192.168.1.100:0")
```

#### remoteAddress()

Returns the remote peer address.

```sindarin
var addr: str = conn.remoteAddress()
```

#### close()

Closes the connection gracefully. Safe to call multiple times.

```sindarin
conn.close()
```

---

## QuicStream

A QUIC stream for bidirectional or unidirectional communication. Multiple streams can be multiplexed over a single connection without head-of-line blocking.

### Read Methods

| Method | Return | Description |
|--------|--------|-------------|
| `read(maxBytes)` | `byte[]` | Read up to maxBytes from the stream |
| `readAll()` | `byte[]` | Read until stream is closed by peer |
| `readLine()` | `str` | Read until newline |

### Write Methods

| Method | Return | Description |
|--------|--------|-------------|
| `write(data)` | `int` | Write bytes, returns count written |
| `writeLine(text)` | `void` | Write string followed by newline |

### Info Methods

| Method | Return | Description |
|--------|--------|-------------|
| `id()` | `long` | Get the stream ID |
| `isUnidirectional()` | `bool` | Check if this is a unidirectional stream |

### Lifecycle

| Method | Description |
|--------|-------------|
| `close()` | Close the stream |

---

## QuicListener (Server)

A QUIC server that listens for incoming connections.

```sindarin
var server: QuicListener = QuicListener.bind(":4433", "cert.pem", "key.pem")
var client: QuicConnection = server.accept()
var stream: QuicStream = client.acceptStream()
var msg: str = stream.readLine()
stream.writeLine($"Echo: {msg}")
stream.close()
client.close()
server.close()
```

### Static Methods

#### QuicListener.bind(address, certFile, keyFile)

Creates a QUIC listener with TLS certificate and key files.

```sindarin
var server: QuicListener = QuicListener.bind(":4433", "server.crt", "server.key")
```

#### QuicListener.bindWith(address, certFile, keyFile, config)

Creates a listener with custom configuration.

```sindarin
var config: QuicConfig = QuicConfig.defaults()
    .setMaxBidiStreams(200)
    .setMaxConnWindow(2097152)

var server: QuicListener = QuicListener.bindWith(":4433", "cert.pem", "key.pem", config)
```

### Instance Methods

| Method | Return | Description |
|--------|--------|-------------|
| `accept()` | `QuicConnection` | Wait for and accept a new connection (blocks) |
| `port()` | `int` | Get the bound port number |
| `close()` | `void` | Close the listener |

---

## QuicConfig

Configuration for QUIC connections and listeners. Uses a builder pattern.

```sindarin
var config: QuicConfig = QuicConfig.defaults()
    .setMaxBidiStreams(100)
    .setMaxUniStreams(50)
    .setMaxStreamWindow(1048576)
    .setMaxConnWindow(2097152)
    .setIdleTimeout(30000)
```

### Builder Methods

| Method | Description |
|--------|-------------|
| `setMaxBidiStreams(n)` | Maximum number of bidirectional streams |
| `setMaxUniStreams(n)` | Maximum number of unidirectional streams |
| `setMaxStreamWindow(bytes)` | Per-stream flow control window |
| `setMaxConnWindow(bytes)` | Per-connection flow control window |
| `setIdleTimeout(ms)` | Idle timeout in milliseconds (0 = no timeout) |

---

## Certificate Configuration

### Server

The server requires a TLS certificate and private key in PEM format, passed directly to `bind()` or `bindWith()`.

### Client

Client connections verify the server certificate. CA certificates are loaded from:

1. **SN_CERTS environment variable** - Path to a CA bundle or certificate directory
2. **Platform certificate store** (fallback) - System-installed CA certificates

---

## QUIC vs TCP/TLS

| Feature | TLS (TCP) | QUIC (UDP) |
|---------|-----------|------------|
| Handshake | TCP + TLS (2-3 RTT) | 1 RTT (0-RTT with resumption) |
| Multiplexing | Single stream | Multiple streams, no HOL blocking |
| Connection migration | Not supported | Supported |
| Encryption | TLS 1.2/1.3 | TLS 1.3 only |
| Ordering | Guaranteed (per connection) | Guaranteed (per stream) |
| Use case | HTTP/1.1, general purpose | HTTP/3, real-time, mobile |

---

## Error Handling

| Operation | Failure Causes |
|-----------|---------------|
| `connect()` | DNS failure, handshake timeout, certificate verification failure |
| `bind()` | Address in use, certificate/key file not found |
| `accept()` | Handshake failure with incoming client |
| `openStream()` | Stream limit reached |
| `read()` / `write()` | Stream reset, connection closed |

---

## Example: Echo Server

```sindarin
import "sdk/net/quic"

fn main(): void =>
    var server: QuicListener = QuicListener.bind(":4433", "cert.pem", "key.pem")
    print($"QUIC server listening on port {server.port()}\n")

    while true =>
        var client: QuicConnection = server.accept()
        var stream: QuicStream = client.acceptStream()

        var msg: str = stream.readLine()
        stream.writeLine($"Echo: {msg}")

        stream.close()
        client.close()
```

## Example: Multiplexed Client

```sindarin
import "sdk/net/quic"

fn main(): void =>
    var conn: QuicConnection = QuicConnection.connect("server:4433")

    # Open multiple streams on same connection
    var s1: QuicStream = conn.openStream()
    var s2: QuicStream = conn.openStream()
    var s3: QuicStream = conn.openStream()

    s1.writeLine("request-1")
    s2.writeLine("request-2")
    s3.writeLine("request-3")

    # Read responses (no head-of-line blocking)
    print(s1.readLine())
    print(s2.readLine())
    print(s3.readLine())

    s1.close()
    s2.close()
    s3.close()
    conn.close()
```

## Example: 0-RTT Reconnection

```sindarin
import "sdk/net/quic"

fn main(): void =>
    # First connection - save resumption token
    var conn: QuicConnection = QuicConnection.connect("server:4433")
    var stream: QuicStream = conn.openStream()
    stream.writeLine("hello")
    stream.close()
    var token: byte[] = conn.resumptionToken()
    conn.close()

    # Reconnect with 0-RTT (reduced latency)
    var fast: QuicConnection = QuicConnection.connectEarly("server:4433", token)
    var s2: QuicStream = fast.openStream()
    s2.writeLine("fast hello")
    s2.close()
    fast.close()
```

---

## See Also

- [Net Overview](readme.md) - Network I/O concepts
- [TLS](tls.md) - TLS-encrypted TCP streams
- [DTLS](dtls.md) - DTLS-encrypted UDP datagrams
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/net/quic.sn`
