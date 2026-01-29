---
title: "UDP"
description: "UDP socket for datagram communication"
permalink: /sdk/net/udp/
---

UDP provides connectionless datagram communication using `UdpSocket`.

## Import

```sindarin
import "sdk/net/udp"
```

---

## UdpSocket

A UDP socket for sending and receiving datagrams.

```sindarin
// Server - echo datagrams back
var socket: UdpSocket = UdpSocket.bind(":9000")

while true =>
    var result: UdpReceiveResult = socket.receiveFrom(1024)
    print($"From {result.sender()}: {result.data().toString()}\n")
    socket.sendTo(result.data(), result.sender())

socket.close()
```

### Static Methods

#### UdpSocket.bind(address)

Creates a UDP socket bound to the specified address.

```sindarin
// Bind to all interfaces on port 9000
var socket: UdpSocket = UdpSocket.bind(":9000")

// Bind to localhost only
var local: UdpSocket = UdpSocket.bind("127.0.0.1:9000")

// Let OS assign a port (useful for clients)
var client: UdpSocket = UdpSocket.bind(":0")
print($"Assigned port: {client.port()}\n")
```

### Instance Methods

#### sendTo(data, address)

Sends a datagram to the specified address. Returns the number of bytes sent.

```sindarin
var bytes: byte[] = "Hello".toBytes()
var sent: int = socket.sendTo(bytes, "127.0.0.1:9000")
print($"Sent {sent} bytes\n")
```

#### receiveFrom(maxBytes)

Receives a datagram of up to `maxBytes`. Returns an `UdpReceiveResult` containing both the data and sender address.

```sindarin
var result: UdpReceiveResult = socket.receiveFrom(1024)
var data: byte[] = result.data()
var sender: str = result.sender()
print($"Received {data.length} bytes from {sender}\n")
```

#### port()

Returns the bound port number. Useful when binding to `:0` for OS-assigned ports.

```sindarin
var socket: UdpSocket = UdpSocket.bind(":0")
print($"Listening on port {socket.port()}\n")
```

#### close()

Closes the socket.

```sindarin
socket.close()
```

---

## UdpReceiveResult

A result struct returned by `receiveFrom()` containing the received data and sender address.

### Methods

#### data()

Returns the received bytes.

```sindarin
var result: UdpReceiveResult = socket.receiveFrom(1024)
var bytes: byte[] = result.data()
var text: str = bytes.toString()
```

#### sender()

Returns the sender's address as a string in `host:port` format.

```sindarin
var result: UdpReceiveResult = socket.receiveFrom(1024)
print($"Message from: {result.sender()}\n")
```

---

## Common Patterns

### UDP Echo Server

```sindarin
fn main(): int =>
    var socket: UdpSocket = UdpSocket.bind(":9000")
    print("UDP echo on :9000\n")

    while true =>
        var result: UdpReceiveResult = socket.receiveFrom(1024)
        socket.sendTo(result.data(), result.sender())

    return 0
```

### UDP Client

```sindarin
fn main(): int =>
    var socket: UdpSocket = UdpSocket.bind(":0")

    // Send message
    socket.sendTo("Hello, Server!".toBytes(), "127.0.0.1:9000")

    // Wait for response
    var result: UdpReceiveResult = socket.receiveFrom(1024)
    print($"Response: {result.data().toString()}\n")

    socket.close()
    return 0
```

### Background Listener

```sindarin
fn listenForMessages(socket: UdpSocket): void =>
    while true =>
        var result: UdpReceiveResult = socket.receiveFrom(1024)
        print($"Message from {result.sender()}: {result.data().toString()}\n")

var socket: UdpSocket = UdpSocket.bind(":9000")
&listenForMessages(socket)  // background listener

// Main thread continues...
```

### Simple Chat

```sindarin
fn receiver(socket: UdpSocket): void =>
    while true =>
        var result: UdpReceiveResult = socket.receiveFrom(1024)
        print($"[{result.sender()}]: {result.data().toString()}\n")

fn main(): int =>
    var socket: UdpSocket = UdpSocket.bind(":9000")
    var peer: str = "127.0.0.1:9001"

    // Start receiver in background
    &receiver(socket)

    // Send messages from stdin
    while true =>
        var line: str = readLine()
        socket.sendTo(line.toBytes(), peer)

    return 0
```

### Broadcast Discovery

```sindarin
fn main(): int =>
    var socket: UdpSocket = UdpSocket.bind(":0")

    // Send discovery message
    socket.sendTo("DISCOVER".toBytes(), "255.255.255.255:9000")

    // Collect responses
    var servers: str[] = str[]{}
    while true =>
        var result: UdpReceiveResult = socket.receiveFrom(1024)
        if result.data().toString() == "HERE" =>
            servers.push(result.sender())
            print($"Found server: {result.sender()}\n")

    return 0
```

---

## Error Handling

UDP operations panic on errors. Common error conditions:

- `UdpSocket.bind()` - Address already in use, permission denied
- `.sendTo()` - Network unreachable, invalid address
- `.receiveFrom()` - Socket closed

```sindarin
// Binding may fail - will panic if it does
var socket: UdpSocket = UdpSocket.bind(":9000")
// If we reach here, binding succeeded
```

Note: UDP is connectionless, so `sendTo()` succeeds even if no one is listening. Delivery is not guaranteed.

---

## See Also

- [Net Overview](readme.md) - Network I/O concepts
- [TCP](tcp.md) - TCP connection-oriented communication
- [TLS](tls.md) - TLS-encrypted TCP streams
- [DTLS](dtls.md) - DTLS-encrypted UDP datagrams
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/net/udp.sn`