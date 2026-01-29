---
title: "ZLib"
description: "Compression and decompression"
permalink: /sdk/encoding/zlib/
---

Provides zlib compression and decompression bindings with high-level convenience wrappers and low-level C library access.

## Import

```sindarin
import "sdk/encoding/zlib"
```

---

## Quick Start

```sindarin
import "sdk/encoding/zlib"

fn main(): void =>
    var data: byte[] = "Hello, World! ".toBytes()

    # Compress
    var compressed: byte[] = compressData(data)
    print($"Original: {data.length} bytes\n")
    print($"Compressed: {compressed.length} bytes\n")
    print($"Saved: {spaceSaved(data.length, compressed.length)}%\n")

    # Decompress
    var original: byte[] = decompressData(compressed, data.length)
    print($"Decompressed: {original.toString()}\n")
```

---

## High-Level API (Recommended)

These functions allocate output buffers automatically.

### compressData(source)

Compresses data with default compression level. Returns compressed bytes, or empty array on error.

```sindarin
var compressed: byte[] = compressData(data)
```

### compressDataLevel(source, level)

Compresses with a specified level (0-9).

```sindarin
var fast: byte[] = compressDataLevel(data, 1)   // Fastest
var best: byte[] = compressDataLevel(data, 9)   // Best compression
```

### decompressData(source, expectedSize)

Decompresses data. You must provide the expected uncompressed size.

```sindarin
var original: byte[] = decompressData(compressed, originalSize)
```

---

## Buffer-Based API

These functions use pre-allocated buffers and return the number of bytes written.

### compressTo(source, dest)

Compresses into a pre-allocated buffer. Returns bytes written, or -1 on error.

```sindarin
var bound: int = maxCompressedSize(data.length)
var buf: byte[bound]
var written: int = compressTo(data, buf)
```

### compressToLevel(source, dest, level)

Compresses with a specified level into a pre-allocated buffer.

```sindarin
var written: int = compressToLevel(data, buf, bestCompression())
```

### decompressTo(source, dest)

Decompresses into a pre-allocated buffer. Returns bytes written, or -1 on error.

```sindarin
var output: byte[expectedSize]
var written: int = decompressTo(compressed, output)
```

---

## Compression Levels

| Function | Value | Description |
|----------|-------|-------------|
| `noCompression()` | 0 | No compression (store only) |
| `bestSpeed()` | 1 | Fastest compression |
| `defaultCompression()` | -1 | Default level (zlib chooses) |
| `bestCompression()` | 9 | Best compression ratio |

---

## Utility Functions

### maxCompressedSize(sourceLen)

Calculates the upper bound for compressed output size. Use this to allocate buffers.

```sindarin
var bound: int = maxCompressedSize(data.length)
```

### isCompressed(data)

Heuristic check if data looks like zlib-compressed data (checks for zlib header bytes).

```sindarin
if isCompressed(data) =>
    var original: byte[] = decompressData(data, expectedSize)
```

### compressionRatio(originalSize, compressedSize)

Returns the compression ratio as a percentage (e.g., 75.5 means compressed to 75.5% of original).

```sindarin
var ratio: double = compressionRatio(1000, 750)  // 75.0
```

### spaceSaved(originalSize, compressedSize)

Returns the percentage of space saved (e.g., 24.5 means 24.5% smaller).

```sindarin
var saved: double = spaceSaved(1000, 750)  // 25.0
```

---

## Error Codes

For use with the low-level API:

| Function | Value | Description |
|----------|-------|-------------|
| `zlibOk()` | 0 | Success |
| `zlibStreamEnd()` | 1 | End of stream |
| `zlibNeedDict()` | 2 | Need dictionary |
| `zlibErrno()` | -1 | File error |
| `zlibStreamError()` | -2 | Stream error |
| `zlibDataError()` | -3 | Data corrupted |
| `zlibMemError()` | -4 | Memory error |
| `zlibBufError()` | -5 | Buffer too small |
| `zlibVersionError()` | -6 | Version mismatch |

### errorMessage(code)

Converts an error code to a human-readable string.

```sindarin
var msg: str = errorMessage(zlibDataError())  // "Data error (corrupted or incomplete)"
```

---

## Low-Level Bindings

Direct bindings to the C zlib library. For most use cases, prefer the high-level API above.

| Function | Description |
|----------|-------------|
| `compress(dest, destLen, source, sourceLen)` | Compress with default level |
| `compress2(dest, destLen, source, sourceLen, level)` | Compress with specified level |
| `uncompress(dest, destLen, source, sourceLen)` | Decompress data |
| `compressBound(sourceLen)` | Calculate max compressed size |

---

## Example: File Compression

```sindarin
import "sdk/encoding/zlib"
import "sdk/io/binaryfile"

fn main(): void =>
    var data: byte[] = BinaryFile.readAll("largefile.bin")

    var compressed: byte[] = compressDataLevel(data, bestCompression())
    BinaryFile.writeAll("largefile.bin.z", compressed)

    var ratio: double = compressionRatio(data.length, compressed.length)
    print($"Compressed to {ratio}% of original size\n")
```

---

## Requirements

- zlib library must be installed (libz)
- Linux: `sudo apt install zlib1g-dev`
- macOS: Usually pre-installed
- Windows: Install via vcpkg

---

## See Also

- [I/O](../io/readme.md) - File operations
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/encoding/zlib.sn`
