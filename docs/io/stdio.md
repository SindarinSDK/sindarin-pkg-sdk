---
title: "Stdio"
description: "Standard input, output, and error streams"
permalink: /sdk/io/stdio/
---

Provides structured access to standard input, output, and error streams through the `Stdin`, `Stdout`, and `Stderr` types.

**Note:** The convenience functions `readLine()`, `print()`, `println()`, `printErr()`, and `printErrLn()` are built-in and do not require this import. This module provides additional methods like `readChar()`, `readWord()`, `hasChars()`, and explicit flushing.

## Import

```sindarin
import "sdk/io/stdio"
```

---

## Stdin

Static methods for reading from standard input.

```sindarin
var line: str = Stdin.readLine()
var ch: int = Stdin.readChar()
var word: str = Stdin.readWord()
```

### Methods

| Method | Return | Description |
|--------|--------|-------------|
| `readLine()` | `str` | Read a line (strips trailing newline) |
| `readChar()` | `int` | Read a single character (returns -1 on EOF) |
| `readWord()` | `str` | Read a whitespace-delimited word |
| `hasChars()` | `bool` | Check if characters are available |
| `hasLines()` | `bool` | Check if lines are available |
| `isEof()` | `bool` | Check if stdin is at EOF |

---

## Stdout

Static methods for writing to standard output.

```sindarin
Stdout.write("Hello ")
Stdout.writeLine("World")
Stdout.flush()
```

### Methods

| Method | Description |
|--------|-------------|
| `write(text)` | Write text (no newline) |
| `writeLine(text)` | Write text with newline |
| `flush()` | Flush the output buffer |

---

## Stderr

Static methods for writing to standard error.

```sindarin
Stderr.write("Error: ")
Stderr.writeLine("Something went wrong")
Stderr.flush()
```

### Methods

| Method | Description |
|--------|-------------|
| `write(text)` | Write text to stderr (no newline) |
| `writeLine(text)` | Write text to stderr with newline |
| `flush()` | Flush the stderr buffer |

---

## Example: Interactive Input

```sindarin
import "sdk/io/stdio"

fn main(): void =>
    Stdout.write("Enter your name: ")
    Stdout.flush()
    var name: str = Stdin.readLine()
    Stdout.writeLine($"Hello, {name}!")
```

## Example: Reading Until EOF

```sindarin
import "sdk/io/stdio"

fn main(): void =>
    var lineCount: int = 0
    while !Stdin.isEof() =>
        var line: str = Stdin.readLine()
        lineCount += 1

    Stdout.writeLine($"Read {lineCount} lines")
```

## Example: Error Reporting

```sindarin
import "sdk/io/stdio"

fn main(): void =>
    var result: int = doWork()
    if result != 0 =>
        Stderr.writeLine($"Error: operation failed with code {result}")
        Stderr.flush()
```

---

## See Also

- [SDK Overview](readme.md) - All SDK modules
- SDK source: `sdk/stdio.sn`
