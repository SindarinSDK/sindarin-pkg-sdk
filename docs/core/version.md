---
title: "Version"
description: "Semantic versioning and version constraint checking"
permalink: /sdk/core/version/
---

Sindarin provides `Version` and `VersionConstraint` types implementing [SemVer 2.0.0](https://semver.org/) with version constraint checking inspired by npm/Cargo conventions.

## Quick Start

```sindarin
import "sdk/core/version"

// Parse a version string
var v: Version = Version.parse("1.2.3-beta.1+build.5")
print($"Version: {v}\n")
print($"Is stable: {v.isStable()}\n")

// Check if version satisfies a constraint
var satisfies: bool = version_satisfies(v, "^1.0.0")
print($"Satisfies ^1.0.0: {satisfies}\n")

// Compare versions
var v2: Version = Version.parse("2.0.0")
if v.lt(v2) =>
  print("v1 is older than v2\n")
```

## Version Format

Versions follow the SemVer 2.0.0 specification:

```
MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
```

| Component | Description | Example |
|-----------|-------------|---------|
| MAJOR | Breaking changes | `2.0.0` |
| MINOR | New features, backwards compatible | `1.3.0` |
| PATCH | Bug fixes, backwards compatible | `1.2.4` |
| PRERELEASE | Pre-release identifier (optional) | `1.0.0-alpha.1` |
| BUILD | Build metadata (optional, ignored in comparisons) | `1.0.0+build.123` |

## Version Type

### Static Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `parse` | `(s: str): Version` | Parse a version string (optional `v` prefix allowed) |

### Instance Methods

#### Formatting

| Method | Signature | Description |
|--------|-----------|-------------|
| `.toString` | `(): str` | Format as `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]` |

#### Comparison

| Method | Signature | Description |
|--------|-----------|-------------|
| `.compare` | `(other: Version): int` | Returns -1, 0, or 1 following SemVer precedence |
| `.eq` | `(other: Version): bool` | True if versions are equal |
| `.gt` | `(other: Version): bool` | True if this version is greater |
| `.lt` | `(other: Version): bool` | True if this version is less |
| `.gte` | `(other: Version): bool` | True if this version is greater or equal |
| `.lte` | `(other: Version): bool` | True if this version is less or equal |

#### Properties

| Method | Signature | Description |
|--------|-----------|-------------|
| `.isPrerelease` | `(): bool` | True if version has a prerelease identifier |
| `.isStable` | `(): bool` | True if major > 0 and no prerelease |

#### Version Bumping

| Method | Signature | Description |
|--------|-----------|-------------|
| `.bumpMajor` | `(): Version` | Increment major, reset minor/patch/prerelease/build |
| `.bumpMinor` | `(): Version` | Increment minor, reset patch/prerelease/build |
| `.bumpPatch` | `(): Version` | Increment patch, reset prerelease/build |

### Fields

The `Version` struct has these public fields:

| Field | Type | Description |
|-------|------|-------------|
| `major` | `int` | Major version number |
| `minor` | `int` | Minor version number |
| `patch` | `int` | Patch version number |
| `prerelease` | `str` | Prerelease identifier (empty if none) |
| `build` | `str` | Build metadata (empty if none) |

## VersionConstraint Type

Version constraints specify acceptable version ranges using operators.

### Supported Operators

| Operator | Example | Meaning |
|----------|---------|---------|
| `=` or none | `=1.2.3` or `1.2.3` | Exact match |
| `>` | `>1.0.0` | Greater than |
| `>=` | `>=1.0.0` | Greater than or equal |
| `<` | `<2.0.0` | Less than |
| `<=` | `<=1.5.0` | Less than or equal |
| `^` | `^1.2.3` | Compatible (same major, or same minor if major is 0) |
| `~` | `~1.2.3` | Approximately (same major and minor) |

### Caret (`^`) Behavior

The caret operator allows changes that do not modify the leftmost non-zero element:

| Constraint | Equivalent Range | Description |
|------------|------------------|-------------|
| `^1.2.3` | `>=1.2.3, <2.0.0` | Any 1.x.x version |
| `^0.2.3` | `>=0.2.3, <0.3.0` | Any 0.2.x version |
| `^0.0.3` | `>=0.0.3, <0.0.4` | Only 0.0.3 |

### Tilde (`~`) Behavior

The tilde operator allows patch-level changes:

| Constraint | Equivalent Range | Description |
|------------|------------------|-------------|
| `~1.2.3` | `>=1.2.3, <1.3.0` | Any 1.2.x version >= 1.2.3 |
| `~0.2.3` | `>=0.2.3, <0.3.0` | Any 0.2.x version >= 0.2.3 |

### Static Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `parse` | `(s: str): VersionConstraint` | Parse a constraint string |

### Instance Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `.satisfiedBy` | `(v: Version): bool` | True if version satisfies this constraint |

## Convenience Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `version_satisfies` | `(v: Version, constraint: str): bool` | Check if version satisfies a single constraint |
| `version_satisfies_all` | `(v: Version, constraints: str): bool` | Check comma-separated constraints (AND logic) |

## Examples

### Parsing and Comparing Versions

```sindarin
import "sdk/core/version"

fn main(): void =>
  var v1: Version = Version.parse("1.2.3")
  var v2: Version = Version.parse("1.2.4")
  var v3: Version = Version.parse("v2.0.0-beta.1")  // 'v' prefix allowed

  print($"v1: {v1}\n")  // 1.2.3
  print($"v3: {v3}\n")  // 2.0.0-beta.1

  if v1.lt(v2) =>
    print("1.2.3 < 1.2.4\n")

  // Prerelease versions sort before release
  var release: Version = Version.parse("2.0.0")
  if v3.lt(release) =>
    print("2.0.0-beta.1 < 2.0.0\n")
```

### Version Bumping

```sindarin
import "sdk/core/version"

fn main(): void =>
  var v: Version = Version.parse("1.2.3-beta.1")

  var patch: Version = v.bumpPatch()
  print($"Patch bump: {patch}\n")  // 1.2.4

  var minor: Version = v.bumpMinor()
  print($"Minor bump: {minor}\n")  // 1.3.0

  var major: Version = v.bumpMajor()
  print($"Major bump: {major}\n")  // 2.0.0
```

### Checking Constraints

```sindarin
import "sdk/core/version"

fn main(): void =>
  var v: Version = Version.parse("1.5.2")

  // Single constraint
  print($"^1.0.0: {version_satisfies(v, \"^1.0.0\")}\n")   // true
  print($"^1.6.0: {version_satisfies(v, \"^1.6.0\")}\n")   // false
  print($"~1.5.0: {version_satisfies(v, \"~1.5.0\")}\n")   // true
  print($">=1.0.0: {version_satisfies(v, \">=1.0.0\")}\n") // true
  print($"<2.0.0: {version_satisfies(v, \"<2.0.0\")}\n")   // true

  // Multiple constraints (AND logic)
  var range: bool = version_satisfies_all(v, ">=1.0.0, <2.0.0")
  print($">=1.0.0, <2.0.0: {range}\n")  // true
```

### Dependency Version Checking

```sindarin
import "sdk/core/version"

fn checkDependency(name: str, installed: str, required: str): bool =>
  var v: Version = Version.parse(installed)
  var ok: bool = version_satisfies(v, required)

  if ok =>
    print($"  {name} {installed} satisfies {required}\n")
  else =>
    print($"  {name} {installed} does NOT satisfy {required}\n")

  return ok

fn main(): void =>
  print("Checking dependencies...\n")

  var allOk: bool = true
  allOk = checkDependency("openssl", "3.0.8", "^3.0.0") && allOk
  allOk = checkDependency("zlib", "1.2.11", ">=1.2.0") && allOk
  allOk = checkDependency("sqlite", "3.39.0", "~3.39.0") && allOk

  if allOk =>
    print("\nAll dependencies satisfied!\n")
  else =>
    print("\nSome dependencies are incompatible.\n")
```

### Stability Checks

```sindarin
import "sdk/core/version"

fn main(): void =>
  var versions: str[] = {"0.9.0", "1.0.0", "1.0.0-rc.1", "2.0.0-alpha.1"}

  for vstr in versions =>
    var v: Version = Version.parse(vstr)
    print($"{v}: stable={v.isStable()}, prerelease={v.isPrerelease()}\n")

  // Output:
  // 0.9.0: stable=false, prerelease=false
  // 1.0.0: stable=true, prerelease=false
  // 1.0.0-rc.1: stable=false, prerelease=true
  // 2.0.0-alpha.1: stable=false, prerelease=true
```

## Notes

- **Version prefix**: The `v` or `V` prefix is optional and stripped during parsing (`v1.2.3` becomes `1.2.3`).
- **Build metadata**: Build metadata (after `+`) is preserved in `.toString()` but ignored in all comparisons per SemVer spec.
- **Prerelease precedence**: A version with prerelease is always less than the same version without (e.g., `1.0.0-alpha < 1.0.0`).
- **Prerelease comparison**: Prerelease identifiers are compared according to SemVer rules: numeric identifiers compare as integers, alphanumeric compare lexically, and numeric identifiers have lower precedence than alphanumeric.

## References

- [Semantic Versioning 2.0.0](https://semver.org/)
- [npm semver](https://docs.npmjs.com/cli/v6/using-npm/semver)
- [Cargo SemVer Compatibility](https://doc.rust-lang.org/cargo/reference/semver.html)

## See Also

- [UUID](uuid.md) - UUID generation
- [SDK Overview](../readme.md) - All SDK modules
