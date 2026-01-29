---
title: "Environment"
description: "Environment variable access"
permalink: /sdk/os/env/
---

The SDK `Environment` type provides access to environment variables.

## SDK Alternative

Import the environment module from the SDK:

```sindarin
import "sdk/os/env"
```

The SDK provides the `Environment` struct with equivalent functionality:

```sindarin
import "sdk/os/env"

// Get required environment variable (panics if not set)
var dbUrl: str = Environment.get("DATABASE_URL")

// Get with default value
var port: str = Environment.getOr("PORT", "8080")

// Check if variable exists
if Environment.has("DEBUG") =>
  print("Debug mode enabled\n")

// List all variables
var all: str[][] = Environment.all()
for entry in all =>
  print($"{entry[0]}={entry[1]}\n")
```

## API Differences

The SDK `Environment` type differs slightly from the built-in `Environment`:

| Built-in | SDK | Description |
|----------|-----|-------------|
| `Environment.get(name)` | `Environment.get(name)` | Get required variable |
| `Environment.get(name, default)` | `Environment.getOr(name, default)` | Get with default |
| `Environment.has(name)` | `Environment.has(name)` | Check existence |
| `Environment.all()` | `Environment.all()` | List all variables |

**Note:** The SDK version uses `getOr()` instead of overloaded `get()` because user-defined structs don't support method overloading in Sindarin.

## SDK Environment API

### Static Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `get` | `(name: str): str` | Get variable value, panics if not set |
| `getOr` | `(name: str, defaultValue: str): str` | Get variable with default value |
| `has` | `(name: str): bool` | True if variable is set (even if empty) |
| `all` | `(): str[][]` | All variables as `[[name, value], ...]` |

### Reading Variables

```sindarin
import "sdk/os/env"

// Required variable - panics if not set
var apiKey: str = Environment.get("API_KEY")

// Optional variable with fallback
var host: str = Environment.getOr("HOST", "localhost")

// Check before accessing
if Environment.has("CONFIG_PATH") =>
  loadConfig(Environment.get("CONFIG_PATH"))
else =>
  loadDefaultConfig()
```

### Listing Variables

```sindarin
import "sdk/os/env"

// Print all environment variables
var all: str[][] = Environment.all()
for entry in all =>
  print($"{entry[0]}={entry[1]}\n")
```

## Error Handling

### Missing Required Variables

When using `get()`, the program panics if the variable is not set:

```sindarin
// Panics if API_KEY is not set
var apiKey: str = Environment.get("API_KEY")
// Error: Environment variable 'API_KEY' is not set
```

### Empty vs Unset

A variable can be set to an empty string, which is different from not being set:

```sindarin
// Variable set to empty string (export EMPTY="")
Environment.has("EMPTY")              // true
Environment.get("EMPTY")              // ""
Environment.getOr("EMPTY", "x")       // "" (not "x")

// Variable not set at all
Environment.has("UNSET")              // false
Environment.get("UNSET")              // panics
Environment.getOr("UNSET", "x")       // "x"
```

## Examples

### Application Configuration

```sindarin
import "sdk/os/env"

fn loadConfig(): void =>
  var dbHost: str = Environment.getOr("DB_HOST", "localhost")
  var dbPort: str = Environment.getOr("DB_PORT", "5432")
  var dbName: str = Environment.getOr("DB_NAME", "myapp")
  var dbUser: str = Environment.get("DB_USER")  // Required
  var dbPass: str = Environment.get("DB_PASS")  // Required
  print($"Connecting to {dbHost}:{dbPort}/{dbName}\n")
```

### Feature Flags

```sindarin
import "sdk/os/env"

fn isFeatureEnabled(feature: str): bool =>
  var envName: str = $"FEATURE_{feature}"
  if Environment.has(envName) =>
    var value: str = Environment.get(envName)
    return value == "true" || value == "1" || value == "yes"
  return false

// Usage
if isFeatureEnabled("DARK_MODE") =>
  enableDarkMode()
```

### Platform Detection

```sindarin
import "sdk/os/env"

fn getPlatform(): str =>
  // Unix-like systems
  if Environment.has("HOME") =>
    return "unix"
  // Windows
  if Environment.has("USERPROFILE") =>
    return "windows"
  return "unknown"

fn getHomeDirectory(): str =>
  if Environment.has("HOME") =>
    return Environment.get("HOME")
  return Environment.get("USERPROFILE")
```

## Notes

- **Static-only type**: `Environment` has no constructor—use static methods only
- **Case sensitivity**: Variable names are case-sensitive on Unix and case-insensitive on Windows
- **Read-only access**: Variables are read from the process environment; modification is not supported
- **Changes affect children**: Environment changes made before program execution are inherited by child processes

---

## See Also

- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/os/env.sn`
