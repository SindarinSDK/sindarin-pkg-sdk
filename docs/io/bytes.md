---
title: "Bytes"
description: "Byte encoding and decoding utilities"
permalink: /sdk/io/bytes/
---

The `byte` primitive type and `Bytes` utility class for binary data encoding and decoding.

## Import

```sindarin
import "sdk/io/bytes"
```

## The `byte` Type

The `byte` type is an unsigned 8-bit value (0-255) used for binary operations.

```sindarin
// byte is an unsigned 8-bit value (0-255)
var b: byte = 255
var zero: byte = 0

// Byte arrays use curly braces like other arrays
var data: byte[] = {72, 101, 108, 108, 111}  // ASCII for "Hello"
var empty: byte[] = {}
```

**Note:** Hex literals (like `0xFF`) are not yet implemented. Use decimal values (0-255).

### Byte to Int Conversion

Bytes implicitly convert to integers for arithmetic:

```sindarin
var b1: byte = 100
var b2: byte = 50
var sum: int = b1 + b2      // 150
var product: int = b1 * b2  // 5000 (exceeds byte range, int handles it)
```

## Bytes Static Methods

### Bytes.fromHex(hexString)

Decodes a hexadecimal string to bytes.

```sindarin
var bytes: byte[] = Bytes.fromHex("48656c6c6f")
var text: str = bytes.toString()  // "Hello"
```

### Bytes.fromBase64(base64String)

Decodes a Base64 string to bytes.

```sindarin
var bytes: byte[] = Bytes.fromBase64("SGVsbG8=")
var text: str = bytes.toString()  // "Hello"
```

## Byte Array Methods

Byte arrays have special methods for encoding and conversion.

### toString()

Converts bytes to a string (UTF-8 decoding).

```sindarin
var bytes: byte[] = {72, 101, 108, 108, 111}
var text: str = bytes.toString()  // "Hello"
```

### toStringLatin1()

Converts bytes to a string using Latin-1/ISO-8859-1 encoding.

```sindarin
var bytes: byte[] = {72, 101, 108, 108, 111}
var text: str = bytes.toStringLatin1()
```

### toHex()

Encodes bytes as a hexadecimal string.

```sindarin
var bytes: byte[] = {72, 101, 108, 108, 111}
var hex: str = bytes.toHex()  // "48656c6c6f"
```

### toBase64()

Encodes bytes as a Base64 string.

```sindarin
var bytes: byte[] = {77, 97, 110}
var b64: str = bytes.toBase64()  // "TWFu"
```

## String to Bytes

Convert a string to its byte representation:

```sindarin
var text: str = "Hello"
var bytes: byte[] = text.toBytes()  // {72, 101, 108, 108, 111}
```

## Common Patterns

### Hex Encoding Roundtrip

```sindarin
var original: byte[] = {1, 2, 3, 255}
var hex: str = original.toHex()           // "010203ff"
var decoded: byte[] = Bytes.fromHex(hex)  // {1, 2, 3, 255}
```

### Base64 Encoding Roundtrip

```sindarin
var data: byte[] = {77, 97, 110}
var b64: str = data.toBase64()             // "TWFu"
var decoded: byte[] = Bytes.fromBase64(b64) // {77, 97, 110}
```

### Binary Data to Text

```sindarin
var binaryData: byte[] = BinaryFile.readAll("message.bin")
var text: str = binaryData.toString()
print(text)
```

### Text to Binary Data

```sindarin
var message: str = "Hello, World!"
var bytes: byte[] = message.toBytes()
BinaryFile.writeAll("message.bin", bytes)
```

### Check File Magic Bytes

```sindarin
var header: byte[] = BinaryFile.readAll("file.dat")
if header.length >= 4 =>
  var magic: str = header[0:4].toHex()
  if magic == "89504e47" =>
    print("PNG file\n")
  else if magic == "504b0304" =>
    print("ZIP file\n")
```

## See Also

- [I/O Overview](readme.md) - File I/O concepts and shared patterns
- [BinaryFile](binaryfile.md) - Binary file operations
- [TextFile](textfile.md) - Text file operations
- [SDK Overview](../readme.md) - All SDK modules
