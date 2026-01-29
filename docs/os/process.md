---
title: "Process"
description: "Process execution and output capture"
permalink: /sdk/os/process/
---

The built-in `Process` type has been deprecated. Please use the SDK-based `Process` type instead.

## Migration to SDK

Import the process module from the SDK:

```sindarin
import "sdk/os/process"
```

The SDK provides the `Process` struct with equivalent functionality:

```sindarin
import "sdk/os/process"

// Run a command
var p: Process = Process.run("pwd")
print(p.stdout())
print($"Exit code: {p.exitCode()}\n")

// Run a command with arguments
var p2: Process = Process.runArgs("ls", {"-la", "/tmp"})
if p2.success() =>
    print(p2.stdout())
else =>
    print(p2.stderr())
```

## SDK Process API

### Static Methods

| Method | Return | Description |
|--------|--------|-------------|
| `Process.run(cmd)` | `Process` | Run command with no arguments |
| `Process.runArgs(cmd, args)` | `Process` | Run command with arguments |

### Instance Methods

| Method | Return | Description |
|--------|--------|-------------|
| `exitCode()` | `int` | Get exit code (0 = success) |
| `stdout()` | `str` | Get captured standard output |
| `stderr()` | `str` | Get captured standard error |
| `success()` | `bool` | Check if exit code is 0 |
| `failed()` | `bool` | Check if exit code is non-zero |
| `notFound()` | `bool` | Check if command was not found (exit code 127) |

## Examples

### Basic Execution

```sindarin
import "sdk/os/process"

var p: Process = Process.run("pwd")
print(p.stdout())      // prints current directory
print(p.exitCode())    // 0 on success
```

### Commands with Arguments

```sindarin
import "sdk/os/process"

var p: Process = Process.runArgs("ls", {"-la", "/tmp"})
print(p.stdout())
```

### Checking Success

```sindarin
import "sdk/os/process"

var p: Process = Process.runArgs("make", {"build"})

if p.success() =>
    print("Build succeeded\n")
    print(p.stdout())
else =>
    print("Build failed\n")
    print(p.stderr())
```

### Capturing Output

Stdout and stderr are captured independently:

```sindarin
import "sdk/os/process"

var p: Process = Process.runArgs("sh", {"-c", "echo out; echo err >&2"})

print(p.stdout())    // "out\n"
print(p.stderr())    // "err\n"
```

### Shell Commands

For pipes, redirection, or shell features, use `sh -c`:

```sindarin
import "sdk/os/process"

// Using pipes
var p1: Process = Process.runArgs("sh", {"-c", "ls -la | grep .txt"})
print(p1.stdout())

// Multiple commands
var p2: Process = Process.runArgs("sh", {"-c", "cd /tmp && pwd"})
print(p2.stdout())    // "/tmp\n"
```

### Exit Codes

Non-zero exit codes indicate failure:

```sindarin
import "sdk/os/process"

var p: Process = Process.run("false")

if p.failed() =>
    print($"Command failed with code {p.exitCode()}\n")
```

### Command Not Found

If the command doesn't exist, the exit code is 127:

```sindarin
import "sdk/os/process"

var p: Process = Process.run("nonexistent-command")

if p.notFound() =>
    print("Command not found\n")
    print(p.stderr())
```

## Exit Code Reference

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1-125 | Command-specific failure |
| 126 | Command found but not executable |
| 127 | Command not found |
| 128+ | Killed by signal (128 + signal number) |

## Limitations

The following features are not supported:

- **Streaming I/O** - Cannot read/write while process runs
- **stdin input** - Cannot pipe data to process stdin
- **Working directory** - Use `sh -c "cd dir && cmd"` instead
- **Environment variables** - Use `sh -c "VAR=val cmd"` instead
- **Timeouts** - Use shell `timeout` command if needed
- **Kill/signal** - Cannot terminate running processes
- **Process ID** - Cannot get PID of spawned process
- **Async execution** - Use threads for parallel execution

---

## See Also

- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/os/process.sn`
