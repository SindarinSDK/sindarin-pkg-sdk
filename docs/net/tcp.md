---
title: "TCP"
description: "TCP listener and stream connections"
permalink: /sdk/net/tcp/
---

TCP provides connection-oriented, reliable communication using `TcpListener` for servers and `TcpStream` for connections.

## Import

```sindarin
import "sdk/net/tcp"
```

---

## TcpListener

A TCP socket that listens for incoming connections.

```sindarin
var server: TcpListener = TcpListener.bind(":8080")
print($"Listening on port {server.port()}\n")

while true =>
    var client: TcpStream = server.accept()
    &handleClient(client)  // handle in background thread

server.dispose()
```

### Static Methods

#### TcpListener.bind(address)

Creates a listener bound to the specified address.

```sindarin
// Bind to all interfaces on port 8080
var server: TcpListener = TcpListener.bind(":8080")

// Bind to localhost only
var local: TcpListener = TcpListener.bind("127.0.0.1:8080")

// Let OS assign a port
var dynamic: TcpListener = TcpListener.bind(":0")
print($"Assigned port: {dynamic.port()}\n")
```

### Instance Methods

#### accept()

Waits for and accepts an incoming connection. Returns a `TcpStream` for the connected client.

```sindarin
var client: TcpStream = server.accept()
print($"Client connected from {client.remoteAddress()}\n")
```

#### acceptOrShutdown(signalFd)

Waits for a connection or a readable shutdown descriptor. A shutdown signal
returns a stream for which `isValid()` is false. On Windows the descriptor must
be a socket that can be used with the socket readiness API. The caller owns and
closes the shutdown descriptor.

#### port()

Returns the bound port number. Useful when binding to `:0` for OS-assigned ports.

```sindarin
var server: TcpListener = TcpListener.bind(":0")
print($"Server listening on port {server.port()}\n")
```

#### dispose()

Closes the listener socket.

```sindarin
server.dispose()
```

---

## TcpStream

A TCP connection for bidirectional communication.

```sindarin
// Client connection
var conn: TcpStream = TcpStream.connect("example.com:80")
conn.writeLine("GET / HTTP/1.0")
conn.writeLine("Host: example.com")
conn.writeLine("")
var response: byte[] = conn.readAll()
print(response.toString())
conn.dispose()
```

### Static Methods

#### TcpStream.connect(address)

Connects to a remote address and returns a stream.

```sindarin
var conn: TcpStream = TcpStream.connect("example.com:80")
```

### Instance Methods

#### read(maxBytes)

Reads up to `maxBytes` from the stream. May return fewer bytes if less data is available.

```sindarin
var data: byte[] = conn.read(1024)
if data.length == 0 =>
    print("Connection closed\n")
```

#### readAll()

Reads all data until the connection closes.

```sindarin
var response: byte[] = conn.readAll()
print($"Received {response.length} bytes\n")
```

#### readLine()

Reads until a newline character, returning the line without the trailing newline.

```sindarin
var line: str = conn.readLine()
print($"Received: {line}\n")
```

#### write(data)

Writes bytes to the stream. Returns the number of bytes written.

```sindarin
var bytes: byte[] = "Hello".toBytes()
var written: int = conn.write(bytes)
```

#### writeLine(text)

Writes a string followed by a newline.

```sindarin
conn.writeLine("Hello, World!")
conn.writeLine($"Value: {x}")
```

#### remoteAddress()

Returns the remote peer's address as a string.

```sindarin
print($"Connected to: {conn.remoteAddress()}\n")
```

#### setTimeout(ms)

Sets the stream's read timeout in milliseconds. A negative value keeps reads
blocking, zero polls without waiting, and a positive value limits the wait.

#### isValid()

Reports whether the stream stores a descriptor other than the invalid sentinel.
Use it to check the result of `acceptOrShutdown()`. It does not detect whether a
peer has disconnected; read/write results provide that information.

#### dispose()

Closes the connection.

```sindarin
conn.dispose()
```

---

## Common Patterns

### Echo Server

```sindarin
fn main(): int =>
    var server: TcpListener = TcpListener.bind(":8080")
    print("Echo server on :8080\n")

    while true =>
        var client: TcpStream = server.accept()

        while true =>
            var data: byte[] = client.read(1024)
            if data.length == 0 =>
                break
            client.write(data)

        client.dispose()

    return 0
```

### Threaded Server

```sindarin
fn handleClient(client: TcpStream): void =>
    var line: str = client.readLine()
    client.writeLine($"Echo: {line}")
    client.dispose()

fn main(): int =>
    var server: TcpListener = TcpListener.bind(":8080")

    while true =>
        var client: TcpStream = server.accept()
        &handleClient(client)

    return 0
```

### Line-Based Protocol

```sindarin
fn handleClient(client: TcpStream): void =>
    client.writeLine("Welcome! Commands: PING, TIME, QUIT")

    while true =>
        var line: str = client.readLine().trim().toUpper()

        if line == "PING" =>
            client.writeLine("PONG")
        else if line == "TIME" =>
            client.writeLine(Time.now().toIso())
        else if line == "QUIT" =>
            client.writeLine("Goodbye!")
            break
        else =>
            client.writeLine($"Unknown: {line}")

    client.dispose()
```

### Simple HTTP Request

```sindarin
fn httpGet(url: str): str =>
    // Parse "host/path" or just "host"
    var parts: str[] = url.split("/", 2)
    var host: str = parts[0]
    var path: str = "/"
    if parts.length > 1 =>
        path = $"/{parts[1]}"

    var conn: TcpStream = TcpStream.connect($"{host}:80")
    conn.writeLine($"GET {path} HTTP/1.0")
    conn.writeLine($"Host: {host}")
    conn.writeLine("Connection: close")
    conn.writeLine("")

    var response: byte[] = conn.readAll()
    conn.dispose()
    return response.toString()
```

### Parallel Connections

```sindarin
var c1: TcpStream = &TcpStream.connect("api1.example.com:80")
var c2: TcpStream = &TcpStream.connect("api2.example.com:80")
var c3: TcpStream = &TcpStream.connect("api3.example.com:80")

[c1, c2, c3]!

// All connected, use them...
c1.dispose()
c2.dispose()
c3.dispose()
```

---

## Error Handling

Bind, connect and accept failures terminate the process with a diagnostic.
Reads return empty or accumulated data when they encounter EOF, a timeout or a
socket error. An empty read alone does not distinguish those conditions.

`write()` returns the number of bytes sent, which can be less than the input
length, or `-1` on failure. Broken-pipe and connection-reset errors return quietly.
`writeLine()` returns no status and stops on a send error. Peer disconnection
does not terminate the process through `SIGPIPE`; signal handling stays local to
the send operation or socket. Use `write()` when the caller needs a result.

---

## Native C module

The reusable [TCP C header](../../src/net/tcp.native.h) exposes streams and
listeners with the existing Sindarin layouts. Its implementation includes the
same `tcp.sn.c` backing used by legacy imports. The public Sindarin declarations
and original callers are unchanged.

Native clients use the `sn_sdk_tcp_*_create`, `retain` and `release` functions.
Factories return one owned reference. Retained aliases share the same record;
the last release closes factory-owned resources. Explicit `dispose()` remains
idempotent. Default records keep zero-valued public fields and releasing them
does not close standard input. Returned arrays and remote-address/line strings
own snapshots that survive stream release. Native clients must release those
results through the matching runtime/allocator API.

Run the C/Rust archive and original-caller checks from the SDK checkout:

```sh
python3 scripts/check_tcp_native.py --compiler /path/to/compiler/bin/sn
python3 scripts/check_tcp_native.py --compiler /path/to/compiler/bin/sn --sanitize
```

The second command instruments the C module and actual shared runtime. The
normal check compares canonical storage with C generated independently from the
original Sindarin declarations, including alignment and every field width and
offset. [Local validation](tcp-native-validation.json) and
[complete platform acceptance](tcp-hosted-acceptance.json) cover this native
foundation on Linux, macOS and Windows. Compiler source/sealed package-artifact
integration is the next step; full Rust/C parity remains open.

## See Also

- [Net Overview](readme.md) - Network I/O concepts
- [UDP](udp.md) - UDP socket operations
- [TLS](tls.md) - TLS-encrypted TCP streams
- [DTLS](dtls.md) - DTLS-encrypted UDP datagrams
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/net/tcp.sn`