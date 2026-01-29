---
title: "OS"
description: "Operating system detection"
permalink: /sdk/os/os/
---

The SDK `OS` type provides platform detection functions to determine the current operating system at runtime.

## Import

```sindarin
import "sdk/os/os"
```

## Quick Start

```sindarin
import "sdk/os/os"

// Check current platform
if OS.isWindows() =>
    print("Running on Windows\n")
else if OS.isMacOS() =>
    print("Running on macOS\n")
else if OS.isLinux() =>
    print("Running on Linux\n")

// Get OS name as string
var osName: str = OS.name()
print($"Operating System: {osName}\n")
```

## API Reference

### Static Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `isWindows` | `(): bool` | Returns `true` if running on Windows |
| `isMacOS` | `(): bool` | Returns `true` if running on macOS |
| `isLinux` | `(): bool` | Returns `true` if running on Linux |
| `isUnix` | `(): bool` | Returns `true` if running on any Unix-like system |
| `name` | `(): str` | Returns the OS name as a string |

### Platform Detection

#### `isWindows()`

Returns `true` if the program is running on any version of Windows (including Windows with Cygwin).

```sindarin
if OS.isWindows() =>
    var home: str = Environment.get("USERPROFILE")
```

#### `isMacOS()`

Returns `true` if the program is running on macOS (Darwin).

```sindarin
if OS.isMacOS() =>
    print("Running on Apple Silicon or Intel Mac\n")
```

#### `isLinux()`

Returns `true` if the program is running on Linux.

```sindarin
if OS.isLinux() =>
    print("Running on Linux\n")
```

#### `isUnix()`

Returns `true` if the program is running on any Unix-like system, including Linux, macOS, and BSD variants. Returns `false` on Windows.

```sindarin
if OS.isUnix() =>
    // Use POSIX-style paths and commands
    var home: str = Environment.get("HOME")
else =>
    // Use Windows-style paths and commands
    var home: str = Environment.get("USERPROFILE")
```

#### `name()`

Returns the operating system name as a string. Possible values:

- `"Windows"` - Windows operating system
- `"macOS"` - Apple macOS
- `"Linux"` - Linux distributions
- `"FreeBSD"` - FreeBSD
- `"OpenBSD"` - OpenBSD
- `"NetBSD"` - NetBSD
- `"Unknown"` - Unrecognized operating system

```sindarin
var osName: str = OS.name()
print($"Detected OS: {osName}\n")
```

## Examples

### Cross-Platform File Paths

```sindarin
import "sdk/os/os"
import "sdk/os/env"

fn getConfigPath(): str =>
    if OS.isWindows() =>
        var appData: str = Environment.getOr("APPDATA", "C:\\Users\\Default\\AppData\\Roaming")
        return $"{appData}\\MyApp\\config.json"
    else =>
        var home: str = Environment.getOr("HOME", "/tmp")
        return $"{home}/.myapp/config.json"
```

### Cross-Platform Command Execution

```sindarin
import "sdk/os/os"
import "sdk/os/process"

fn clearScreen(): void =>
    if OS.isWindows() =>
        Process.run("cls")
    else =>
        Process.run("clear")

fn listFiles(dir: str): Process =>
    if OS.isWindows() =>
        return Process.runArgs("cmd", {"/c", "dir", dir})
    else =>
        return Process.runArgs("ls", {"-la", dir})
```

### Platform-Specific Behavior

```sindarin
import "sdk/os/os"

fn getPathSeparator(): str =>
    if OS.isWindows() =>
        return "\\"
    return "/"

fn getEnvVarSeparator(): str =>
    if OS.isWindows() =>
        return ";"
    return ":"

fn main(): void =>
    var sep: str = getPathSeparator()
    print($"Path separator: '{sep}'\n")
    print($"Running on: {OS.name()}\n")
```

### Platform Feature Detection

```sindarin
import "sdk/os/os"

fn supportsSymlinks(): bool =>
    // Symlinks work well on Unix, less reliably on Windows
    return OS.isUnix()

fn hasNativePackageManager(): bool =>
    if OS.isMacOS() =>
        // macOS has Homebrew commonly installed
        return true
    else if OS.isLinux() =>
        // Linux distributions have package managers (apt, yum, pacman, etc.)
        return true
    return false

fn main(): void =>
    if supportsSymlinks() =>
        print("Symlinks supported natively\n")
    if hasNativePackageManager() =>
        print("Native package manager available\n")
```

## Implementation Notes

- **Compile-time detection**: Platform checks are resolved at compile time using C preprocessor macros, so there is no runtime overhead
- **Static-only type**: `OS` has no constructor—use static methods only
- **Exactly one true**: Among `isWindows()`, `isMacOS()`, and `isLinux()`, exactly one will return `true` (or all false on exotic platforms)
- **isUnix consistency**: `isUnix()` returns `true` if and only if `isMacOS()` or `isLinux()` returns `true`

## See Also

- [Environment](env.md) - Environment variable access
- [Process](process.md) - Process execution
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/os/os.sn`
