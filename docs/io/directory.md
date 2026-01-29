---
title: "Directory"
description: "Directory listing and manipulation"
permalink: /sdk/io/directory/
---

Static methods for directory operations.

## Import

```sindarin
import "sdk/io/directory"
```

## Static Methods

### Directory.list(path)

Lists files and directories in the specified directory.

```sindarin
var files: str[] = Directory.list("/home/user")
for file in files =>
  print($"{file}\n")
```

### Directory.listRecursive(path)

Lists all files and directories recursively.

```sindarin
var allFiles: str[] = Directory.listRecursive("/home/user/project")
for file in allFiles =>
  print($"{file}\n")
```

### Directory.create(path)

Creates a directory. Creates parent directories if needed.

```sindarin
Directory.create("/new/nested/path")
```

### Directory.delete(path)

Deletes an empty directory. Panics if the directory is not empty.

```sindarin
Directory.delete("/empty/directory")
```

### Directory.deleteRecursive(path)

Deletes a directory and all its contents.

```sindarin
Directory.deleteRecursive("/old/project")
```

## Common Patterns

### Process All Files in Directory

```sindarin
var files: str[] = Directory.list("/data/input")
for file in files =>
  if Path.isFile(file) =>
    processFile(file)
```

### Find Files by Extension

```sindarin
fn findByExtension(dir: str, ext: str): str[] =>
  var result: str[] = str[]{}
  var files: str[] = Directory.listRecursive(dir)

  for file in files =>
    if Path.extension(file) == ext =>
      result.push(file)

  return result

// Usage
var snFiles: str[] = findByExtension("/project/src", "sn")
```

### Create Directory If Not Exists

```sindarin
fn ensureDirectory(path: str): void =>
  if !Path.exists(path) =>
    Directory.create(path)

// Usage
ensureDirectory("/output/reports")
TextFile.writeAll("/output/reports/data.txt", content)
```

### Clean Build Directory

```sindarin
fn cleanBuildDir(path: str): void =>
  if Path.exists(path) =>
    Directory.deleteRecursive(path)
  Directory.create(path)

// Usage
cleanBuildDir("/project/build")
```

### Copy Directory Contents

```sindarin
fn copyDirectory(src: str, dest: str): void =>
  Directory.create(dest)
  var files: str[] = Directory.list(src)

  for file in files =>
    var filename: str = Path.filename(file)
    var destPath: str = Path.join(dest, filename)

    if Path.isDirectory(file) =>
      copyDirectory(file, destPath)
    else =>
      BinaryFile.copy(file, destPath)
```

### Count Files in Directory

```sindarin
fn countFiles(dir: str): int =>
  var count: int = 0
  var files: str[] = Directory.listRecursive(dir)

  for file in files =>
    if Path.isFile(file) =>
      count = count + 1

  return count
```

## Error Handling

Directory operations panic on errors:

- `Directory.list()` - Directory doesn't exist or permission denied
- `Directory.create()` - Permission denied
- `Directory.delete()` - Directory not empty or doesn't exist
- `Directory.deleteRecursive()` - Permission denied

Always check existence before operations that require existing directories:

```sindarin
if Path.exists(dirPath) && Path.isDirectory(dirPath) =>
  var files: str[] = Directory.list(dirPath)
  // Process files...
else =>
  print($"Directory not found: {dirPath}\n")
```

## See Also

- [I/O Overview](readme.md) - File I/O concepts and shared patterns
- [Path](path.md) - Path manipulation utilities
- [TextFile](textfile.md) - Text file operations
- [BinaryFile](binaryfile.md) - Binary file operations
- [SDK Overview](../readme.md) - All SDK modules
