---
title: "TextFile"
description: "Text file reading and writing"
permalink: /sdk/io/textfile/
---

`TextFile` is used for reading and writing text content. It works with `str` values.

## Import

```sindarin
import "sdk/io/textfile"
```

## Static Methods

These methods operate directly on file paths without opening a file handle:

### TextFile.readAll(path)

Reads the entire file content as a string.

```sindarin
var content: str = TextFile.readAll("data.txt")
print(content)
```

### TextFile.writeAll(path, content)

Writes a string to a file, creating or overwriting it.

```sindarin
TextFile.writeAll("output.txt", "Hello, World!\nLine 2")
```

### TextFile.exists(path)

Checks if a file exists.

```sindarin
if TextFile.exists("config.txt") =>
  var config: str = TextFile.readAll("config.txt")
else =>
  print("Config file not found\n")
```

### TextFile.copy(source, dest)

Copies a file to a new location.

```sindarin
TextFile.copy("original.txt", "backup.txt")
```

### TextFile.move(source, dest)

Moves or renames a file.

```sindarin
TextFile.move("old_name.txt", "new_name.txt")
```

### TextFile.delete(path)

Deletes a file.

```sindarin
TextFile.delete("temp.txt")
```

## Instance Methods

For streaming operations, open a file handle:

### TextFile.open(path)

Opens a file and returns a handle.

```sindarin
var f: TextFile = TextFile.open("data.txt")
// ... use the file ...
f.close()
```

### readLine()

Reads the next line (without the trailing newline).

```sindarin
var f: TextFile = TextFile.open("data.txt")
while !f.isEof() =>
  var line: str = f.readLine()
  print($"{line}\n")
f.close()
```

### readRemaining()

Reads all remaining content from the current position.

```sindarin
var f: TextFile = TextFile.open("data.txt")
var firstLine: str = f.readLine()
var rest: str = f.readRemaining()  // Everything after the first line
f.close()
```

### readLines()

Reads all remaining lines into an array.

```sindarin
var f: TextFile = TextFile.open("data.txt")
var lines: str[] = f.readLines()
for line in lines =>
  print($"Line: {line}\n")
f.close()
```

### readWord()

Reads the next whitespace-delimited token.

```sindarin
var f: TextFile = TextFile.open("numbers.txt")
while f.hasChars() =>
  var word: str = f.readWord()
  print($"Word: {word}\n")
f.close()
```

### readChar()

Reads a single character (returns -1 at EOF).

```sindarin
var f: TextFile = TextFile.open("data.txt")
var ch: int = f.readChar()
while ch != -1 =>
  print($"Char: {ch}\n")
  ch = f.readChar()
f.close()
```

### writeLine(text)

Writes a string followed by a newline.

```sindarin
var f: TextFile = TextFile.open("output.txt")
f.writeLine("First line")
f.writeLine("Second line")
f.close()
```

### write(text)

Writes a string without a trailing newline.

```sindarin
f.write("Hello")
f.write(" ")
f.write("World")  // Outputs: "Hello World"
```

### writeChar(ch)

Writes a single character.

```sindarin
f.writeChar('A')
```

### print(text) / println(text)

Formatted write methods (uses string interpolation syntax).

```sindarin
f.print($"Value: {x}")
f.println($"Line: {i}")  // Adds newline
```

## State Methods

### isEof()

Returns true if at end of file.

```sindarin
while !f.isEof() =>
  var line: str = f.readLine()
  process(line)
```

### hasChars() / hasWords() / hasLines()

Returns true if more content is available.

```sindarin
while f.hasChars() =>
  var ch: int = f.readChar()

while f.hasWords() =>
  var word: str = f.readWord()

while f.hasLines() =>
  var line: str = f.readLine()
```

### position()

Gets the current byte position in the file.

```sindarin
var pos: int = f.position()
```

### seek(pos)

Seeks to a byte position in the file.

```sindarin
f.seek(0)  // Return to start
f.seek(pos)  // Go to saved position
```

### rewind()

Returns to the beginning of the file.

```sindarin
f.rewind()
```

### flush()

Forces buffered data to be written to disk.

```sindarin
f.writeLine("Important data")
f.flush()  // Ensure it's written
```

### close()

Closes the file handle. Always close files when done.

```sindarin
var f: TextFile = TextFile.open("data.txt")
// ... operations ...
f.close()
```

## Properties

```sindarin
var p: str = f.path()   // Full file path
var n: str = f.name()   // Filename only (without directory)
var s: int = f.size()   // File size in bytes
```

## Common Patterns

### Process File Line by Line

```sindarin
var f: TextFile = TextFile.open("data.txt")
while !f.isEof() =>
  var line: str = f.readLine()
  if !line.isBlank() =>
    processLine(line)
f.close()
```

### Read and Process All Lines

```sindarin
var content: str = TextFile.readAll("data.txt")
var lines: str[] = content.splitLines()
for line in lines =>
  if !line.isBlank() =>
    print($"Processing: {line}\n")
```

### Copy File with Modification

```sindarin
var content: str = TextFile.readAll("input.txt")
var modified: str = content.replace("old", "new")
TextFile.writeAll("output.txt", modified)
```

### Write CSV File

```sindarin
var f: TextFile = TextFile.open("output.csv")
f.writeLine("Name,Age,City")
f.writeLine("Alice,30,Boston")
f.writeLine("Bob,25,Seattle")
f.close()
```

### Read Words from File

```sindarin
var content: str = TextFile.readAll("document.txt")
var words: str[] = content.splitWhitespace()
print($"Word count: {words.length}\n")
```

### Parse CSV File

```sindarin
fn parseCsv(path: str): str[][] =>
  var content: str = TextFile.readAll(path)
  var lines: str[] = content.splitLines()
  var result: str[][] = str[][]{}

  for line in lines =>
    if line.isBlank() =>
      continue
    var fields: str[] = line.split(",")
    var trimmed: str[] = str[]{}
    for field in fields =>
      trimmed.push(field.trim())
    result.push(trimmed)

  return result
```

### Log File Analyzer

```sindarin
fn analyzeLog(path: str): void =>
  var f: TextFile = TextFile.open(path)
  var errorCount: int = 0
  var warnCount: int = 0

  while f.hasLines() =>
    var line: str = f.readLine()
    if line.contains("[ERROR]") =>
      errorCount = errorCount + 1
    else if line.contains("[WARN]") =>
      warnCount = warnCount + 1

  f.close()
  println($"Errors: {errorCount}, Warnings: {warnCount}")
```

## Error Handling

File operations panic on errors (file not found, permission denied, etc.). Always check existence before operations that require existing files:

```sindarin
var path: str = "config.txt"
if TextFile.exists(path) =>
  var config: str = TextFile.readAll(path)
  processConfig(config)
else =>
  print("Warning: Config file not found, using defaults\n")
  useDefaults()
```

Examples of panic conditions:
- `TextFile.open()` - File doesn't exist or permission denied
- `TextFile.delete()` - File doesn't exist or permission denied
- `f.readLine()` - I/O error during read
- `f.seek(pos)` - Invalid position

## See Also

- [I/O Overview](readme.md) - File I/O concepts and shared patterns
- [BinaryFile](binaryfile.md) - Binary file operations
- [Path](path.md) - Path manipulation utilities
- [Directory](directory.md) - Directory operations
- [SDK Overview](../readme.md) - All SDK modules
