---
title: "Path"
description: "File path utilities and manipulation"
permalink: /sdk/io/path/
---

Static methods for path manipulation and file system queries.

## Import

```sindarin
import "sdk/io/path"
```

## Static Methods

### Path.directory(path)

Extracts the directory portion of a path.

```sindarin
var dir: str = Path.directory("/home/user/file.txt")  // "/home/user"
var dir2: str = Path.directory("file.txt")            // ""
```

### Path.filename(path)

Extracts the filename from a path.

```sindarin
var name: str = Path.filename("/home/user/file.txt")  // "file.txt"
var name2: str = Path.filename("document.pdf")        // "document.pdf"
```

### Path.extension(path)

Extracts the file extension (without the leading dot).

```sindarin
var ext: str = Path.extension("/home/user/file.txt")  // "txt"
var ext2: str = Path.extension("archive.tar.gz")      // "gz"
var ext3: str = Path.extension("README")              // ""
```

### Path.join(path1, path2)

Joins two path components with the appropriate separator.

```sindarin
var full: str = Path.join("/home", "user")  // "/home/user"
var rel: str = Path.join("src", "main")     // "src/main"
```

### Path.join3(path1, path2, path3)

Joins three path components.

```sindarin
var full: str = Path.join3("/home", "user", "file.txt")  // "/home/user/file.txt"
```

### Path.joinAll(parts)

Joins an array of path components. Use this when you need to join more than 3 components.

```sindarin
var parts: str[] = {"vcpkg", "installed", "x64-windows", "bin"}
var path: str = Path.joinAll(parts)  // "vcpkg/installed/x64-windows/bin"
```

### Path.absolute(path)

Resolves a relative path to an absolute path.

```sindarin
var abs: str = Path.absolute("./file.txt")  // "/current/dir/file.txt"
var abs2: str = Path.absolute("../other")   // "/parent/other"
```

### Path.exists(path)

Checks if a path exists (file or directory).

```sindarin
if Path.exists("/some/path") =>
  print("Path exists\n")
```

### Path.isFile(path)

Checks if the path points to a file.

```sindarin
if Path.isFile("/home/user/data.txt") =>
  print("It's a file\n")
```

### Path.isDirectory(path)

Checks if the path points to a directory.

```sindarin
if Path.isDirectory("/home/user") =>
  print("It's a directory\n")
```

## Common Patterns

### Extract File Parts

```sindarin
var path: str = "/home/user/documents/report.pdf"

var dir: str = Path.directory(path)   // "/home/user/documents"
var name: str = Path.filename(path)   // "report.pdf"
var ext: str = Path.extension(path)   // "pdf"
```

### Build Output Path

```sindarin
var inputPath: str = "/data/input/file.txt"
var outputDir: str = "/data/output"

var filename: str = Path.filename(inputPath)
var outputPath: str = Path.join(outputDir, filename)
// outputPath = "/data/output/file.txt"
```

### Change File Extension

```sindarin
fn changeExtension(path: str, newExt: str): str =>
  var dir: str = Path.directory(path)
  var name: str = Path.filename(path)
  var ext: str = Path.extension(path)

  // Remove old extension from name
  var baseName: str = name.substring(0, name.length - ext.length - 1)

  if dir.isEmpty() =>
    return $"{baseName}.{newExt}"
  else =>
    return Path.join(dir, $"{baseName}.{newExt}")
```

### Safe File Operations

```sindarin
fn safeReadFile(path: str): str =>
  if !Path.exists(path) =>
    return ""

  if !Path.isFile(path) =>
    return ""

  return TextFile.readAll(path)
```

### Validate Path Type

```sindarin
fn processPath(path: str): void =>
  if !Path.exists(path) =>
    print($"Path not found: {path}\n")
    return

  if Path.isDirectory(path) =>
    print($"Processing directory: {path}\n")
    processDirectory(path)
  else =>
    print($"Processing file: {path}\n")
    processFile(path)
```

## See Also

- [I/O Overview](readme.md) - File I/O concepts and shared patterns
- [Directory](directory.md) - Directory operations
- [TextFile](textfile.md) - Text file operations
- [BinaryFile](binaryfile.md) - Binary file operations
- [SDK Overview](../readme.md) - All SDK modules
