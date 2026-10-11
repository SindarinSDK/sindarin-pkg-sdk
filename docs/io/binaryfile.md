---
title: "BinaryFile"
description: "Binary file read and write operations"
permalink: /sdk/io/binaryfile/
---

`BinaryFile` is used for reading and writing raw bytes.

## Independent C module

`src/io/binaryfile.native.c` builds the existing file operations in
`binaryfile.sn.c` against the canonical C runtime. Its public
`SnSdkBinaryFileRecord` storage has the same layout as existing generated
`BinaryFile` records. Legacy callers retain their generated constructor; the
standalone module supplies its own constructor and atomic retain/release functions.
Final release closes an open file and frees its owned path and record. Calling
`dispose` closes the handle immediately and can be repeated through aliases.

Define `SN_SDK_BINARYFILE_STANDALONE` when including `binaryfile.native.h` to
access the original C file-operation declarations. Returned byte arrays are owned
by the caller and released with `sn_array_free`; returned paths/names are owned
C strings released with `free`. Input byte arrays are borrowed. `readInto`
mutates their existing storage, so aliases observe the bytes immediately.
The public `binaryfile.sn` API and its existing fixtures remain unchanged.

`make test` validates this module on the installed compiler runtime. To run it
directly, use `python3 scripts/check_bytes_native.py --compiler /path/to/bin/sn
--module binaryfile`. Add `--sanitize --runtime-source
/path/to/compiler/src/runtime` to instrument the actual C runtime and module.
This module is part of the SDK migration; complete SDK artifact packaging remains
in progress.

## Import

```sindarin
import "sdk/io/binaryfile"
```

## Static Methods

### BinaryFile.readAll(path)

Reads the entire file as a byte array.

```sindarin
var data: byte[] = BinaryFile.readAll("image.bin")
print($"File size: {data.length} bytes\n")
```

### BinaryFile.writeAll(path, data)

Writes a byte array to a file.

```sindarin
var header: byte[] = {0, 1, 2, 3}
BinaryFile.writeAll("output.bin", header)
```

### BinaryFile.exists(path)

Checks if a file exists.

```sindarin
if BinaryFile.exists("data.bin") =>
  var data: byte[] = BinaryFile.readAll("data.bin")
```

### BinaryFile.copy(source, dest)

Copies a binary file.

```sindarin
BinaryFile.copy("original.bin", "backup.bin")
```

### BinaryFile.move(source, dest)

Moves or renames a binary file.

```sindarin
BinaryFile.move("temp.bin", "final.bin")
```

### BinaryFile.delete(path)

Deletes a binary file.

```sindarin
BinaryFile.delete("temp.bin")
```

## Instance Methods

### BinaryFile.open(path)

Opens a binary file and returns a handle.

```sindarin
var f: BinaryFile = BinaryFile.open("data.bin")
// ... use the file ...
f.close()
```

### readByte()

Reads a single byte (returns -1 at EOF).

```sindarin
var f: BinaryFile = BinaryFile.open("data.bin")
var b: int = f.readByte()
while b != -1 =>
  print($"Byte: {b}\n")
  b = f.readByte()
f.close()
```

### readBytes(count)

Reads up to `count` bytes into an array.

```sindarin
var f: BinaryFile = BinaryFile.open("data.bin")
var header: byte[] = f.readBytes(4)
var body: byte[] = f.readBytes(100)
f.close()
```

### readRemaining()

Reads all remaining bytes from the current position.

```sindarin
var f: BinaryFile = BinaryFile.open("data.bin")
var allData: byte[] = f.readRemaining()
f.close()
```

### readInto(buffer)

Reads into an existing byte buffer, returns number of bytes read.

```sindarin
var buffer: byte[] = byte[1024]{}
var n: int = f.readInto(buffer)
```

### writeByte(value)

Writes a single byte.

```sindarin
var f: BinaryFile = BinaryFile.open("output.bin")
f.writeByte(255)
f.writeByte(0)
f.close()
```

### writeBytes(data)

Writes a byte array.

```sindarin
var f: BinaryFile = BinaryFile.open("output.bin")
var data: byte[] = {1, 2, 3, 4, 5}
f.writeBytes(data)
f.close()
```

## State Methods

### isEof()

Returns true if at end of file.

### hasBytes()

Returns true if more bytes are available.

### position() / seek(pos) / rewind()

Position management, same as TextFile.

```sindarin
var pos: int = f.position()  // Get current position
f.seek(100)                   // Go to byte 100
f.rewind()                    // Return to start
```

### flush()

Forces buffered data to be written to disk.

```sindarin
f.writeByte(42)
f.flush()  // Ensure it's written
```

### close()

Closes the file handle.

## Properties

```sindarin
var p: str = f.path   // Full file path
var n: str = f.name   // Filename only
var s: int = f.size   // File size in bytes
```

## Common Patterns

### Binary File Header Check

```sindarin
var f: BinaryFile = BinaryFile.open("file.bin")
var header: byte[] = f.readBytes(4)
if header.toHex() == "89504e47" =>
  print("PNG file detected\n")
f.close()
```

### Read Entire Binary File

```sindarin
var data: byte[] = BinaryFile.readAll("image.bin")
print($"Read {data.length} bytes\n")
```

### Write Binary Data

```sindarin
var f: BinaryFile = BinaryFile.open("output.bin")
f.writeByte(0x89)  // Magic number
f.writeByte(0x50)
f.writeBytes({0x4E, 0x47, 0x0D, 0x0A})
f.close()
```

## Error Handling

Binary file operations panic on errors. Check existence before reading:

```sindarin
if BinaryFile.exists("data.bin") =>
  var data: byte[] = BinaryFile.readAll("data.bin")
  processData(data)
else =>
  print("Binary file not found\n")
```

## See Also

- [I/O Overview](readme.md) - File I/O concepts and shared patterns
- [TextFile](textfile.md) - Text file operations
- [Bytes](bytes.md) - Byte encoding/decoding utilities
- [Path](path.md) - Path manipulation utilities
- [SDK Overview](../readme.md) - All SDK modules
