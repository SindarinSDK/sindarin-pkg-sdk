---
title: "SSH"
description: "SSH client and server connections"
permalink: /sdk/net/ssh/
---

SSH provides secure remote command execution and interactive shell access using libssh with OpenSSL. Sindarin's SSH module supports both client connections (with multiple authentication methods) and server listeners for building SSH services.

## Import

```sindarin
import "sdk/net/ssh"
```

---

## SshConnection (Client)

An SSH client connection for secure remote command execution.

```sindarin
var conn: SshConnection = SshConnection.connectPassword("host:22", "user", "pass")
var result: SshExecResult = conn.exec("ls -la")
print(result.stdout())
print($"Exit code: {result.exitCode()}\n")
conn.close()
```

### Static Methods (Authentication)

#### SshConnection.connectPassword(address, username, password)

Connects with username/password authentication.

```sindarin
var conn: SshConnection = SshConnection.connectPassword("server.example.com:22", "admin", "secret")
```

#### SshConnection.connectKey(address, username, privateKeyPath, passphrase)

Connects with public key authentication. Pass `""` for passphrase if the key is unencrypted.

```sindarin
var conn: SshConnection = SshConnection.connectKey("server:22", "deploy", "/home/user/.ssh/id_rsa", "")
```

#### SshConnection.connectAgent(address, username)

Connects using the SSH agent (ssh-agent on Linux/macOS, Pageant on Windows).

```sindarin
var conn: SshConnection = SshConnection.connectAgent("server:22", "user")
```

#### SshConnection.connectInteractive(address, username, password)

Connects using keyboard-interactive authentication.

```sindarin
var conn: SshConnection = SshConnection.connectInteractive("server:22", "user", "password")
```

### Instance Methods

#### run(command)

Executes a command and returns stdout as a string. Simple form for when you only need the output.

```sindarin
var output: str = conn.run("hostname")
print(output)
```

#### exec(command)

Executes a command and returns a full `SshExecResult` with stdout, stderr, and exit code.

```sindarin
var result: SshExecResult = conn.exec("make build")
if result.exitCode() != 0 =>
    print($"Build failed: {result.stderr()}\n")
else =>
    print(result.stdout())
```

#### remoteAddress()

Returns the remote peer address.

```sindarin
var addr: str = conn.remoteAddress()
print($"Connected to: {addr}\n")
```

#### close()

Closes the SSH connection. Safe to call multiple times.

```sindarin
conn.close()
```

---

## SshExecResult

Contains the result of a remote command execution.

### Methods

| Method | Return | Description |
|--------|--------|-------------|
| `stdout()` | `str` | Standard output from the command |
| `stderr()` | `str` | Standard error from the command |
| `exitCode()` | `int` | Exit code (0 = success) |

---

## SSH Server

The SSH server consists of three types: `SshListener`, `SshSession`, and `SshChannel`.

### SshServerConfig

Configures authentication and options for an SSH server. Uses a builder pattern.

```sindarin
var config: SshServerConfig = SshServerConfig.defaults()
    .setHostKey("/path/to/host_key")
    .addUser("admin", "password123")
    .setAuthorizedKeysDir("/etc/ssh/authorized_keys.d")
```

#### Static Methods

| Method | Description |
|--------|-------------|
| `defaults()` | Create a config with sensible defaults |

#### Builder Methods

| Method | Description |
|--------|-------------|
| `setHostKey(path)` | Set the host key file path |
| `addUser(username, password)` | Add a user with password authentication |
| `setAuthorizedKeysDir(path)` | Set directory for authorized_keys files |

---

### SshListener

Listens for incoming SSH connections.

```sindarin
var listener: SshListener = SshListener.bind(":2222", "/path/to/host_key")
var session: SshSession = listener.accept()
```

#### Static Methods

##### SshListener.bind(address, hostKeyPath)

Binds a listener with a host key file (simple form).

```sindarin
var listener: SshListener = SshListener.bind(":2222", "host_key")
```

##### SshListener.bindWith(address, config)

Binds a listener with full configuration.

```sindarin
var config: SshServerConfig = SshServerConfig.defaults()
    .setHostKey("host_key")
    .addUser("testuser", "testpass")

var listener: SshListener = SshListener.bindWith(":2222", config)
```

#### Instance Methods

| Method | Return | Description |
|--------|--------|-------------|
| `accept()` | `SshSession` | Wait for and accept the next authenticated session (blocks) |
| `port()` | `int` | Get the bound port number |
| `close()` | `void` | Close the listener |

---

### SshSession

Represents an authenticated client session on the server.

```sindarin
var session: SshSession = listener.accept()
print($"User connected: {session.username()} from {session.remoteAddress()}\n")
var channel: SshChannel = session.acceptChannel()
```

#### Instance Methods

| Method | Return | Description |
|--------|--------|-------------|
| `acceptChannel()` | `SshChannel` | Wait for the next channel request (blocks) |
| `username()` | `str` | Get the authenticated username |
| `remoteAddress()` | `str` | Get the remote peer address |
| `close()` | `void` | Close the session |

---

### SshChannel

Represents a channel for I/O with a connected client. Channels can be either exec (single command) or shell (interactive).

```sindarin
var channel: SshChannel = session.acceptChannel()

if channel.isShell() =>
    # Interactive shell
    channel.writeLine("Welcome!")
    var input: str = channel.readLine()
else =>
    # Exec command
    var cmd: str = channel.command()
    channel.writeLine($"Executing: {cmd}")
    channel.sendExitStatus(0)

channel.close()
```

#### Instance Methods

| Method | Return | Description |
|--------|--------|-------------|
| `command()` | `str` | Get the command requested by the client (empty for shell) |
| `isShell()` | `bool` | Check if this is a shell channel (vs exec) |
| `read(maxBytes)` | `byte[]` | Read up to maxBytes from the channel |
| `readLine()` | `str` | Read a line from the channel |
| `write(data)` | `int` | Write bytes to the channel, returns bytes written |
| `writeLine(text)` | `void` | Write text followed by newline |
| `sendExitStatus(code)` | `void` | Send exit status to the client |
| `close()` | `void` | Close the channel |

---

## Known Hosts Verification

SSH connections verify the server's host key. Known hosts are loaded in this priority order:

### 1. SN_SSH_KNOWN_HOSTS Environment Variable

```bash
export SN_SSH_KNOWN_HOSTS=/path/to/known_hosts
```

### 2. Platform Default (fallback)

- **Linux/macOS**: `~/.ssh/known_hosts`
- **Windows**: `%USERPROFILE%\.ssh\known_hosts`

---

## Error Handling

| Operation | Failure Causes |
|-----------|---------------|
| `connectPassword()` | DNS failure, connection refused, authentication failure |
| `connectKey()` | Key file not found, passphrase incorrect, authentication failure |
| `connectAgent()` | Agent not running, no matching key |
| `run()` / `exec()` | Channel open failure, command execution failure |
| `bind()` | Address in use, host key file not found |
| `accept()` | Authentication failure (retries internally) |

---

## Example: Remote Command Execution

```sindarin
import "sdk/net/ssh"

fn main(): void =>
    var conn: SshConnection = SshConnection.connectPassword("server:22", "admin", "secret")

    # Simple output
    var hostname: str = conn.run("hostname")
    print($"Host: {hostname}")

    # Full result with error handling
    var result: SshExecResult = conn.exec("df -h")
    if result.exitCode() == 0 =>
        print(result.stdout())
    else =>
        print($"Error: {result.stderr()}\n")

    conn.close()
```

## Example: SSH Echo Server

```sindarin
import "sdk/net/ssh"

fn main(): void =>
    var config: SshServerConfig = SshServerConfig.defaults()
        .setHostKey("host_key")
        .addUser("testuser", "testpass")

    var listener: SshListener = SshListener.bindWith(":2222", config)
    print($"SSH server listening on port {listener.port()}\n")

    while true =>
        var session: SshSession = listener.accept()
        print($"Client connected: {session.username()}\n")

        var channel: SshChannel = session.acceptChannel()
        var cmd: str = channel.command()
        channel.writeLine($"You ran: {cmd}")
        channel.sendExitStatus(0)
        channel.close()
        session.close()
```

---

## See Also

- [Net Overview](readme.md) - Network I/O concepts
- [TLS](tls.md) - TLS-encrypted TCP streams
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/net/ssh.sn`
