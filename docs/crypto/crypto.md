---
title: "Crypto"
description: "Cryptographic hashing, encryption, and key derivation"
permalink: /sdk/crypto/crypto/
---

Provides cryptographic operations using OpenSSL's libcrypto: hashing, HMAC, AES-256-GCM encryption, PBKDF2 key derivation, secure random, and timing-safe comparison.

## Import

```sindarin
import "sdk/crypto/crypto"
```

---

## Quick Start

```sindarin
import "sdk/crypto/crypto"

fn main(): void =>
    # Hash a string
    var hash: byte[] = Crypto.sha256Str("hello world")
    print($"SHA-256 length: {hash.length}\n")  // 32

    # Encrypt and decrypt
    var key: byte[] = Crypto.randomBytes(32)
    var plaintext: byte[] = {72, 101, 108, 108, 111}
    var encrypted: byte[] = Crypto.encrypt(key, plaintext)
    var decrypted: byte[] = Crypto.decrypt(key, encrypted)

    # Key derivation
    var salt: byte[] = Crypto.randomBytes(16)
    var derived: byte[] = Crypto.pbkdf2("password", salt, 100000, 32)

    # Timing-safe comparison
    if Crypto.constantTimeEqual(hash, hash) =>
        print("Equal\n")
```

---

## Hashing

All hash functions accept either `byte[]` or `str` input and return `byte[]`.

### Byte Array Input

| Method | Output Size | Description |
|--------|-------------|-------------|
| `Crypto.sha256(data: byte[]): byte[]` | 32 bytes | SHA-256 hash |
| `Crypto.sha384(data: byte[]): byte[]` | 48 bytes | SHA-384 hash |
| `Crypto.sha512(data: byte[]): byte[]` | 64 bytes | SHA-512 hash |
| `Crypto.sha1(data: byte[]): byte[]` | 20 bytes | SHA-1 hash (legacy) |
| `Crypto.md5(data: byte[]): byte[]` | 16 bytes | MD5 hash (legacy) |

### String Input

| Method | Output Size | Description |
|--------|-------------|-------------|
| `Crypto.sha256Str(text: str): byte[]` | 32 bytes | SHA-256 of UTF-8 string |
| `Crypto.sha384Str(text: str): byte[]` | 48 bytes | SHA-384 of UTF-8 string |
| `Crypto.sha512Str(text: str): byte[]` | 64 bytes | SHA-512 of UTF-8 string |
| `Crypto.sha1Str(text: str): byte[]` | 20 bytes | SHA-1 of UTF-8 string |
| `Crypto.md5Str(text: str): byte[]` | 16 bytes | MD5 of UTF-8 string |

```sindarin
var hash: byte[] = Crypto.sha256Str("hello")
var dataHash: byte[] = Crypto.sha256(myBytes)
```

---

## HMAC

Keyed-hash message authentication codes.

| Method | Output Size | Description |
|--------|-------------|-------------|
| `Crypto.hmacSha256(key: byte[], data: byte[]): byte[]` | 32 bytes | HMAC-SHA-256 |
| `Crypto.hmacSha512(key: byte[], data: byte[]): byte[]` | 64 bytes | HMAC-SHA-512 |

```sindarin
var key: byte[] = Crypto.randomBytes(32)
var mac: byte[] = Crypto.hmacSha256(key, message)
```

---

## AES-256-GCM Encryption

Authenticated encryption using AES-256 in GCM mode. Requires a 32-byte key.

### Auto-IV (Recommended)

| Method | Description |
|--------|-------------|
| `Crypto.encrypt(key: byte[], plaintext: byte[]): byte[]` | Encrypt with random IV |
| `Crypto.decrypt(key: byte[], ciphertext: byte[]): byte[]` | Decrypt auto-IV output |

Output format for `encrypt`: `[IV (12 bytes)][ciphertext][tag (16 bytes)]`

The `decrypt` function expects this format and extracts the IV automatically.

```sindarin
var key: byte[] = Crypto.randomBytes(32)
var plaintext: byte[] = {1, 2, 3, 4, 5}

var encrypted: byte[] = Crypto.encrypt(key, plaintext)
var decrypted: byte[] = Crypto.decrypt(key, encrypted)
// decrypted == plaintext
```

### Explicit IV

| Method | Description |
|--------|-------------|
| `Crypto.encryptWithIv(key: byte[], iv: byte[], plaintext: byte[]): byte[]` | Encrypt with specified IV |
| `Crypto.decryptWithIv(key: byte[], iv: byte[], ciphertext: byte[]): byte[]` | Decrypt with specified IV |

Output format for `encryptWithIv`: `[ciphertext][tag (16 bytes)]`

The IV must be exactly 12 bytes. Never reuse an IV with the same key.

```sindarin
var key: byte[] = Crypto.randomBytes(32)
var iv: byte[] = Crypto.randomBytes(12)
var plaintext: byte[] = {1, 2, 3, 4, 5}

var encrypted: byte[] = Crypto.encryptWithIv(key, iv, plaintext)
var decrypted: byte[] = Crypto.decryptWithIv(key, iv, encrypted)
```

### Error Handling

All encryption/decryption functions return an empty byte array (`length == 0`) on failure:
- Wrong key size (must be 32 bytes)
- Wrong IV size (must be 12 bytes for explicit IV)
- Authentication failure (tampered ciphertext or wrong key)
- Input too short

```sindarin
var result: byte[] = Crypto.decrypt(wrongKey, encrypted)
if result.length == 0 =>
    print("Decryption failed\n")
```

---

## Key Derivation (PBKDF2)

Derive cryptographic keys from passwords using PBKDF2.

| Method | Description |
|--------|-------------|
| `Crypto.pbkdf2(password: str, salt: byte[], iterations: int, keyLen: int): byte[]` | PBKDF2 with SHA-256 |
| `Crypto.pbkdf2Sha512(password: str, salt: byte[], iterations: int, keyLen: int): byte[]` | PBKDF2 with SHA-512 |

Parameters:
- **password**: The password to derive from
- **salt**: Random salt (recommended: 16+ bytes from `randomBytes`)
- **iterations**: Work factor (recommended: 100,000+ for SHA-256, 50,000+ for SHA-512)
- **keyLen**: Desired output key length in bytes

```sindarin
var salt: byte[] = Crypto.randomBytes(16)
var key: byte[] = Crypto.pbkdf2("my password", salt, 100000, 32)

// Use SHA-512 variant for longer keys
var longKey: byte[] = Crypto.pbkdf2Sha512("my password", salt, 50000, 64)
```

---

## Secure Random

| Method | Description |
|--------|-------------|
| `Crypto.randomBytes(count: int): byte[]` | Generate cryptographically secure random bytes |

Uses OpenSSL's `RAND_bytes` (backed by the OS CSPRNG).

```sindarin
var key: byte[] = Crypto.randomBytes(32)    // 256-bit key
var iv: byte[] = Crypto.randomBytes(12)     // 96-bit IV
var salt: byte[] = Crypto.randomBytes(16)   // 128-bit salt
```

---

## Utility

### constantTimeEqual

| Method | Description |
|--------|-------------|
| `Crypto.constantTimeEqual(a: byte[], b: byte[]): bool` | Timing-safe byte array comparison |

Compares two byte arrays in constant time to prevent timing side-channel attacks. Returns `false` if lengths differ.

```sindarin
var expected: byte[] = Crypto.hmacSha256(key, message)
var received: byte[] = getReceivedMac()

if Crypto.constantTimeEqual(expected, received) =>
    print("Valid MAC\n")
else =>
    print("Invalid MAC\n")
```

---

## Complete Example: Password Storage

```sindarin
import "sdk/crypto/crypto"
import "sdk/io/bytes"

fn hashPassword(password: str): byte[] =>
    var salt: byte[] = Crypto.randomBytes(16)
    var hash: byte[] = Crypto.pbkdf2(password, salt, 100000, 32)
    // Store salt + hash together (16 + 32 = 48 bytes)
    return salt.concat(hash)

fn verifyPassword(password: str, stored: byte[]): bool =>
    var salt: byte[] = stored[0..16]
    var expectedHash: byte[] = stored[16..48]
    var computedHash: byte[] = Crypto.pbkdf2(password, salt, 100000, 32)
    return Crypto.constantTimeEqual(expectedHash, computedHash)
```

---

## Complete Example: Authenticated Encryption

```sindarin
import "sdk/crypto/crypto"

fn encryptMessage(password: str, message: byte[]): byte[] =>
    // Derive key from password
    var salt: byte[] = Crypto.randomBytes(16)
    var key: byte[] = Crypto.pbkdf2(password, salt, 100000, 32)

    // Encrypt
    var encrypted: byte[] = Crypto.encrypt(key, message)

    // Return salt + encrypted (salt needed for decryption)
    return salt.concat(encrypted)

fn decryptMessage(password: str, data: byte[]): byte[] =>
    // Extract salt and ciphertext
    var salt: byte[] = data[0..16]
    var encrypted: byte[] = data[16..data.length]

    // Derive same key
    var key: byte[] = Crypto.pbkdf2(password, salt, 100000, 32)

    // Decrypt
    return Crypto.decrypt(key, encrypted)
```

---

## Requirements

- OpenSSL libcrypto must be installed
- Linux: `sudo apt install libssl-dev`
- macOS: `brew install openssl`
- Windows: Install OpenSSL via vcpkg

---

## See Also

- [Random](../core/random.md) - General-purpose random number generation
- [I/O Bytes](../io/bytes.md) - Hex and Base64 encoding
- [Net TLS](../net/tls.md) - TLS-encrypted network connections
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/crypto/crypto.sn`
