---
title: "UUID"
description: "UUID generation and parsing"
permalink: /sdk/core/uuid/
---

Sindarin provides a `UUID` type for generating and manipulating Universally Unique Identifiers. UUIDs are 128-bit values used to identify resources without central coordination.

## Quick Start

```sindarin
// Generate a time-ordered UUID (v7) - recommended for most uses
var id: UUID = UUID.create()
print($"New record: {id}\n")

// Parse from string
var parsed: UUID = UUID.fromString("01912345-6789-7abc-8def-0123456789ab")

// Check version and extract timestamp
if id.version() == 7 =>
  var created: Time = id.time()
  print($"Created at: {created}\n")
```

## UUID Versions

Sindarin supports three UUID versions:

| Version | Method | Description |
|---------|--------|-------------|
| v7 | `UUID.create()`, `UUID.v7()` | Time-ordered with timestamp prefix (recommended) |
| v4 | `UUID.v4()` | Pure random |
| v5 | `UUID.v5(namespace, name)` | Deterministic from namespace + name |

### Why v7 is the Default

UUIDv7 embeds a timestamp prefix, making new UUIDs naturally sort in chronological order. This provides significant performance benefits for database indexes and B-tree structures compared to random v4 UUIDs.

Use v4 when:
- Timestamp leakage is a concern
- You specifically need unpredictability

## Static Methods

### Factory Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `create` | `(): UUID` | Generate UUIDv7 (recommended default) |
| `v7` | `(): UUID` | Generate UUIDv7 (time-ordered) |
| `v4` | `(): UUID` | Generate UUIDv4 (random) |
| `v5` | `(namespace: UUID, name: str): UUID` | Deterministic UUID from namespace + name |
| `fromString` | `(str): UUID` | Parse standard 36-char format |
| `fromHex` | `(str): UUID` | Parse 32-char hex format |
| `fromBase64` | `(str): UUID` | Parse 22-char URL-safe base64 format |
| `fromBytes` | `(bytes: byte[]): UUID` | Create from 16-byte array |

### Namespace Constants

For v5 deterministic UUIDs, RFC 9562 defines standard namespaces:

| Method | Signature | Description |
|--------|-----------|-------------|
| `namespaceDns` | `(): UUID` | DNS namespace |
| `namespaceUrl` | `(): UUID` | URL namespace |
| `namespaceOid` | `(): UUID` | OID namespace |
| `namespaceX500` | `(): UUID` | X.500 DN namespace |

### Special Values

| Method | Signature | Description |
|--------|-----------|-------------|
| `nil` | `(): UUID` | All zeros: `00000000-0000-0000-0000-000000000000` |
| `max` | `(): UUID` | All ones: `ffffffff-ffff-ffff-ffff-ffffffffffff` |

## Instance Methods

### Properties

| Method | Signature | Description |
|--------|-----------|-------------|
| `.version` | `(): int` | UUID version (1-8) |
| `.variant` | `(): int` | UUID variant |
| `.isNil` | `(): bool` | True if nil UUID |

### Time Extraction (v7 only)

| Method | Signature | Description |
|--------|-----------|-------------|
| `.timestamp` | `(): long` | Unix timestamp in milliseconds |
| `.time` | `(): Time` | Time when UUID was created |

**Note:** These methods panic if called on a non-v7 UUID. Check `.version()` first if the UUID version is uncertain.

### Conversion

| Method | Signature | Description |
|--------|-----------|-------------|
| `.toString` | `(): str` | Standard 36-char format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `.toHex` | `(): str` | 32-char hex string (no dashes) |
| `.toBase64` | `(): str` | 22-char URL-safe base64 |
| `.toBytes` | `(): byte[]` | 16-byte array |

### Comparison

UUIDs are comparable and orderable:

```sindarin
var a: UUID = UUID.create()
var b: UUID = UUID.create()

if a < b =>
  print("a was created before b\n")

// Works with equality
if a == b =>
  print("Same UUID\n")
```

## Examples

### Database Primary Keys

```sindarin
fn createUser(name: str): User =>
  var user: User = User {
    id: UUID.create(),  // v7: time-ordered for index performance
    name: name,
    createdAt: Time.now()
  }
  db.insert(user)
  return user
```

### Deterministic IDs

```sindarin
// Same input always produces same UUID
var ns: UUID = UUID.namespaceUrl()
var userId: UUID = UUID.v5(ns, "https://myapp.com/users/alice")

// Useful for:
// - Idempotent operations
// - Content-addressable storage
// - Reproducible builds
```

### Correlation IDs

```sindarin
fn handleRequest(req: Request): Response =>
  var correlationId: UUID = UUID.create()
  log($"[{correlationId}] Processing request\n")

  // Pass through service calls
  var result: str = callService(req.data, correlationId)

  log($"[{correlationId}] Complete\n")
  return Response { body: result }
```

### Compact URL Format

```sindarin
var id: UUID = UUID.create()

// Standard format for logs, debugging
print($"Created: {id}\n")  // Uses toString()

// Compact format for URLs
var url: str = $"/users/{id.toBase64()}/profile"
// /users/AZEjRWeJq82N7wEjRWeJqw/profile

// Parse back
var parsed: UUID = UUID.fromBase64("AZEjRWeJq82N7wEjRWeJqw")
```

### Time Extraction from v7

```sindarin
var id: UUID = UUID.create()

// Safe pattern when version is uncertain
if id.version() == 7 =>
  var created: Time = id.time()
  print($"Created: {created.format(\"YYYY-MM-DD HH:mm:ss\")}\n")
```

## Notes

- **Monotonicity**: UUIDs generated in the same millisecond are unique but not guaranteed to be ordered within that millisecond.
- **Time extraction**: Calling `.timestamp()` or `.time()` on non-v7 UUIDs will panic.
- **String interpolation**: UUIDs automatically use `.toString()` in string interpolation.
- **Base64 encoding**: Uses URL-safe alphabet (RFC 4648 section 5): `A-Z`, `a-z`, `0-9`, `-`, `_` with no padding.

## References

- [RFC 9562 - Universally Unique IDentifiers (UUIDs)](https://datatracker.ietf.org/doc/rfc9562/)
- [UUIDv7 Benefits](https://uuid7.com/)
- [UUID Versions Explained](https://www.uuidtools.com/uuid-versions-explained)

## See Also

- [Random](random.md) - Random number generation
- [Time](../time/time.md) - Time type operations
- [SDK Overview](../readme.md) - All SDK modules
