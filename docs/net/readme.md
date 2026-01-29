# Network I/O in Sindarin

Sindarin provides TCP, UDP, TLS, DTLS, SSH, QUIC, and Git types through the SDK for network communication. All network types integrate with Sindarin's arena-based memory management and threading model.

## SDK Modules

| Module | Description |
|--------|-------------|
| [TCP](tcp.md) | TCP listener and stream for connection-oriented communication |
| [UDP](udp.md) | UDP socket for connectionless datagram communication |
| [TLS](tls.md) | TLS-encrypted TCP streams and listener (HTTPS, secure connections) |
| [DTLS](dtls.md) | DTLS-encrypted UDP datagrams and listener (secure datagram communication) |
| [SSH](ssh.md) | SSH client and server for secure remote command execution |
| [QUIC](quic.md) | QUIC multiplexed encrypted streams over UDP |
| [Git](git.md) | Git repository operations (clone, commit, branch, push/pull) |

## Quick Start

```sindarin
import "sdk/net/tcp"
import "sdk/net/udp"
import "sdk/net/tls"
import "sdk/net/dtls"
import "sdk/net/ssh"
import "sdk/net/quic"
import "sdk/net/git"

// TCP Server
var server: TcpListener = TcpListener.bind(":8080")
var client: TcpStream = server.accept()
var line: str = client.readLine()
client.writeLine($"Echo: {line}")
client.close()
server.close()

// TCP Client
var conn: TcpStream = TcpStream.connect("example.com:80")
conn.writeLine("GET / HTTP/1.0")
conn.writeLine("")
var response: byte[] = conn.readAll()
print(response.toString())
conn.close()

// TLS Client (HTTPS)
var secure: TlsStream = TlsStream.connect("example.com:443")
secure.writeLine("GET / HTTP/1.1")
secure.writeLine("Host: example.com")
secure.writeLine("Connection: close")
secure.writeLine("")
var body: byte[] = secure.readAll()
secure.close()

// UDP Echo
var socket: UdpSocket = UdpSocket.bind(":9000")
var result: UdpReceiveResult = socket.receiveFrom(1024)
socket.sendTo(result.data(), result.sender())
socket.close()

// DTLS Client (encrypted datagrams)
var dtls: DtlsConnection = DtlsConnection.connect("server:4433")
dtls.send("Hello".toBytes())
var reply: byte[] = dtls.receive(1024)
dtls.close()

// SSH Remote Command
var ssh: SshConnection = SshConnection.connectPassword("server:22", "user", "pass")
var output: str = ssh.run("hostname")
print(output)
ssh.close()

// QUIC Multiplexed Streams
var quic: QuicConnection = QuicConnection.connect("server:4433")
var stream: QuicStream = quic.openStream()
stream.writeLine("Hello, QUIC!")
var response: str = stream.readLine()
stream.close()
quic.close()

// Git Repository
var repo: GitRepo = GitRepo.open(".")
var commits: GitCommit[] = repo.log(5)
for c in commits =>
    print($"{c.id()[0..7]} {c.message()}\n")
repo.close()
```

---

## Address Format

All addresses use `host:port` format:

| Format | Description |
|--------|-------------|
| `"127.0.0.1:8080"` | IPv4 with port |
| `"[::1]:8080"` | IPv6 with port |
| `":8080"` | All interfaces, specific port |
| `":0"` | All interfaces, OS-assigned port |
| `"example.com:80"` | Hostname (resolved via DNS) |

---

## Threading

Network operations integrate with Sindarin's threading model using `&` and `!`.

### Parallel Connections

```sindarin
var c1: TcpStream = &TcpStream.connect("api1.example.com:80")
var c2: TcpStream = &TcpStream.connect("api2.example.com:80")
var c3: TcpStream = &TcpStream.connect("api3.example.com:80")

[c1, c2, c3]!

// All connected, use them...
```

### Threaded Server

```sindarin
fn handleClient(client: TcpStream): void =>
    var line: str = client.readLine()
    client.writeLine($"You said: {line}")
    client.close()

fn main(): int =>
    var server: TcpListener = TcpListener.bind(":8080")

    while true =>
        var client: TcpStream = server.accept()
        &handleClient(client)  // fire and forget

    return 0
```

### Parallel Requests

```sindarin
fn httpGet(host: str, path: str): str =>
    var conn: TcpStream = TcpStream.connect($"{host}:80")
    conn.writeLine($"GET {path} HTTP/1.0")
    conn.writeLine($"Host: {host}")
    conn.writeLine("")
    var response: byte[] = conn.readAll()
    conn.close()
    return response.toString()

// Fetch in parallel
var r1: str = &httpGet("example.com", "/page1")
var r2: str = &httpGet("example.com", "/page2")
var r3: str = &httpGet("example.com", "/page3")

[r1, r2, r3]!

print($"Total bytes: {r1.length + r2.length + r3.length}\n")
```

---

## Memory Management

Network handles integrate with arena-based memory management.

### Automatic Cleanup

```sindarin
fn fetchData(host: str): byte[] =>
    var conn: TcpStream = TcpStream.connect(host)
    var data: byte[] = conn.readAll()
    // conn automatically closed when function returns
    return data
```

### Handle Promotion

```sindarin
fn acceptClient(server: TcpListener): TcpStream =>
    var client: TcpStream = server.accept()
    return client  // promoted to caller's arena

fn main(): int =>
    var server: TcpListener = TcpListener.bind(":8080")
    var client: TcpStream = acceptClient(server)
    // client is valid here
    client.close()
    return 0
```

---

## Error Handling

Network operations panic on errors:

- `TcpStream.connect()` - Connection refused, DNS failure, timeout
- `TcpListener.bind()` - Address in use, permission denied
- `.read()` / `.write()` - Connection reset, broken pipe
- `UdpSocket.bind()` - Address in use, permission denied
- `TlsStream.connect()` - TLS handshake failure, certificate verification failure
- `TlsListener.bind()` - Address in use, certificate/key file error
- `DtlsConnection.connect()` - DTLS handshake failure, certificate verification failure
- `DtlsListener.bind()` - Address in use, certificate/key file error
- `SshConnection.connect*()` - Authentication failure, connection refused
- `QuicConnection.connect()` - Handshake failure, certificate verification failure
- `GitRepo.open()` - Path not found, not a git repository
- `GitRepo.clone()` - Network failure, authentication failure
- `GitRepo.push()` / `.pull()` / `.fetch()` - Network failure, authentication failure

```sindarin
// Connection may fail
var conn: TcpStream = TcpStream.connect("example.com:80")
// If we reach here, connection succeeded
```

---

## See Also

- [SDK Overview](../readme.md) - All SDK modules
- [Threading](../../threading.md) - Threading model (`&` spawn, `!` sync)
- [Memory](../../memory.md) - Arena memory management