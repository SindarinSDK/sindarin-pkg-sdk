---
title: "Random"
description: "Random number generation"
permalink: /sdk/core/random/
---

Sindarin provides secure random number generation through the `Random` type. By default, all random operations use operating system entropy for cryptographically suitable randomness, with an optional seeded mode for reproducible sequences.

## Quick Start

```sindarin
import "sdk/core/random"

// Generate random values - no setup required
var dice: int = Random.randInt(1, 6)
var coin: bool = Random.randBool()
var percentage: double = Random.randDouble(0.0, 100.0)

// Pick from a collection
var colors: str[] = {"red", "green", "blue"}
var pick: str = Random.randChoiceStr(colors)
```

## Design Philosophy

### Secure by Default

Unlike many languages that require explicit seeding or initialization, Sindarin's `Random` type uses OS entropy by default. Every call to a static method draws from the operating system's random number generator (`getrandom()` on Linux, equivalent facilities on other platforms).

This design choice means:
- No initialization ceremony required
- No risk of predictable sequences from forgotten or weak seeds
- Cryptographically suitable for security-sensitive applications
- Simpler mental model - just call the method and get a random value

### Reproducible When Needed

For testing, simulations, and procedural generation where reproducibility matters, create a seeded `Random` instance:

```sindarin
var rng: Random = Random.createWithSeed(42l)
var value: int = rng.nextInt(1, 100)  // Same value every time with seed 42
```

### Naming Conventions

Because `int`, `long`, `double`, `bool`, and `byte` are reserved keywords in Sindarin, method names use prefixes:
- **Static methods**: `rand*` prefix (e.g., `randInt`, `randBool`, `randBytes`)
- **Instance methods**: `next*` prefix (e.g., `nextInt`, `nextBool`, `nextBytes`)
- **Collection operations**: type-specific suffixes (e.g., `randChoiceStr`, `shuffleInt`, `sampleDouble`)

## Static Methods

Static methods use OS entropy and require no initialization.

### Factory Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `create` | `(): Random` | Create an OS-entropy backed instance |
| `createWithSeed` | `(seed: long): Random` | Create a seeded PRNG instance for reproducible sequences |

### Value Generation

| Method | Signature | Description |
|--------|-----------|-------------|
| `randInt` | `(min: int, max: int): int` | Random integer in range [min, max] inclusive |
| `randLong` | `(min: long, max: long): long` | Random long in range [min, max] inclusive |
| `randDouble` | `(min: double, max: double): double` | Random double in range [min, max) |
| `randBool` | `(): bool` | Random boolean (50/50) |
| `randByte` | `(): byte` | Random byte (0-255) |
| `randBytes` | `(count: int): byte[]` | Array of random bytes |
| `randGaussian` | `(mean: double, stddev: double): double` | Sample from normal distribution |

### Batch Generation

Generate multiple values in a single call for performance-sensitive loops:

| Method | Signature | Description |
|--------|-----------|-------------|
| `randIntMany` | `(min: int, max: int, count: int): int[]` | Array of random integers |
| `randLongMany` | `(min: long, max: long, count: int): long[]` | Array of random longs |
| `randDoubleMany` | `(min: double, max: double, count: int): double[]` | Array of random doubles |
| `randBoolMany` | `(count: int): bool[]` | Array of random booleans |
| `randGaussianMany` | `(mean: double, stddev: double, count: int): double[]` | Array of gaussian samples |

### Collection Operations

Collection operations use type-specific method names. Available types: `Int`, `Long`, `Double`, `Str`, `Bool`, `Byte`.

| Method Pattern | Example | Description |
|----------------|---------|-------------|
| `randChoice{Type}` | `randChoiceStr(arr: str[]): str` | Random element from array |
| `randWeightedChoice{Type}` | `randWeightedChoiceInt(arr: int[], weights: double[]): int` | Random element with probability weights |
| `randShuffle{Type}` | `randShuffleInt(arr: int[]): void` | Shuffle array in place |
| `randSample{Type}` | `randSampleStr(arr: str[], count: int): str[]` | Random sample without replacement |

## Instance Methods

When you have a `Random` instance (from `create()` or `createWithSeed()`), the same operations are available as instance methods. This allows functions to accept a `Random` parameter and work identically whether it uses OS entropy or a seed.

### Value Generation

| Method | Signature | Description |
|--------|-----------|-------------|
| `.nextInt` | `(min: int, max: int): int` | Next random integer |
| `.nextLong` | `(min: long, max: long): long` | Next random long |
| `.nextDouble` | `(min: double, max: double): double` | Next random double |
| `.nextBool` | `(): bool` | Next random boolean |
| `.nextByte` | `(): byte` | Next random byte |
| `.nextBytes` | `(count: int): byte[]` | Next random bytes |
| `.gaussian` | `(mean: double, stddev: double): double` | Sample from normal distribution |

### Batch Generation

| Method | Signature | Description |
|--------|-----------|-------------|
| `.intMany` | `(min: int, max: int, count: int): int[]` | Array of random integers |
| `.longMany` | `(min: long, max: long, count: int): long[]` | Array of random longs |
| `.doubleMany` | `(min: double, max: double, count: int): double[]` | Array of random doubles |
| `.boolMany` | `(count: int): bool[]` | Array of random booleans |
| `.gaussianMany` | `(mean: double, stddev: double, count: int): double[]` | Array of gaussian samples |

### Collection Operations

Instance collection operations also use type-specific names.

| Method Pattern | Example | Description |
|----------------|---------|-------------|
| `.choice{Type}` | `.choiceStr(arr: str[]): str` | Random element |
| `.weightedChoice{Type}` | `.weightedChoiceInt(arr: int[], weights: double[]): int` | Random element with weights |
| `.shuffle{Type}` | `.shuffleInt(arr: int[]): void` | Shuffle with this generator |
| `.sample{Type}` | `.sampleStr(arr: str[], count: int): str[]` | Random sample without replacement |

## Examples

### Basic Random Values

```sindarin
import "sdk/core/random"

fn main(): void =>
  // Dice roll
  var roll: int = Random.randInt(1, 6)
  print($"You rolled: {roll}\n")

  // Coin flip
  if Random.randBool() =>
    print("Heads!\n")
  else =>
    print("Tails!\n")

  // Percentage (0.0 to 100.0)
  var chance: double = Random.randDouble(0.0, 100.0)
  print($"Random percentage: {chance}%\n")
```

### Working with Collections

```sindarin
import "sdk/core/random"

fn main(): void =>
  // Pick a random color
  var colors: str[] = {"red", "green", "blue", "yellow"}
  var picked: str = Random.randChoiceStr(colors)
  print($"Selected color: {picked}\n")

  // Shuffle a deck
  var cards: int[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
  Random.randShuffleInt(cards)
  print($"Shuffled: {cards.join(\", \")}\n")

  // Sample without replacement
  var lottery: int[] = Random.randSampleInt(cards, 3)
  print($"Winning numbers: {lottery.join(\", \")}\n")
```

### Weighted Selection

```sindarin
import "sdk/core/random"

fn main(): void =>
  // Loot drop with rarity weights
  var items: str[] = {"common", "rare", "legendary"}
  var weights: double[] = {0.7, 0.25, 0.05}

  var drop: str = Random.randWeightedChoiceStr(items, weights)
  print($"You found: {drop}\n")
```

### Statistical Sampling

```sindarin
import "sdk/core/random"

fn main(): void =>
  // Generate heights from normal distribution
  // mean=170cm, standard deviation=10cm
  var height: double = Random.randGaussian(170.0, 10.0)
  print($"Generated height: {height} cm\n")

  // Batch generation for simulations
  var samples: double[] = Random.randGaussianMany(0.0, 1.0, 1000)
  print($"Generated {samples.length} standard normal samples\n")
```

### Reproducible Sequences

```sindarin
import "sdk/core/random"

fn main(): void =>
  // Create seeded generator for reproducibility
  var rng: Random = Random.createWithSeed(12345l)

  // These values will be identical every run
  var a: int = rng.nextInt(1, 100)
  var b: int = rng.nextInt(1, 100)
  var c: int = rng.nextInt(1, 100)

  print($"Sequence: {a}, {b}, {c}\n")
```

### Procedural Generation

```sindarin
import "sdk/core/random"

fn generateTerrain(seed: long, width: int, height: int): int[][] =>
  var rng: Random = Random.createWithSeed(seed)
  var terrain: int[][] = {}

  for var y: int = 0; y < height; y++ =>
    var row: int[] = rng.intMany(0, 9, width)
    terrain.push(row)

  return terrain

fn main(): void =>
  // Same seed = same terrain
  var map: int[][] = generateTerrain(42l, 10, 5)
  for row in map =>
    print($"{row.join(\"\")}\n")
```

### Cryptographic Bytes

```sindarin
import "sdk/core/random"

fn main(): void =>
  // Generate a 32-byte key (256 bits)
  var key: byte[] = Random.randBytes(32)
  print($"Generated {key.length}-byte key\n")
```

## Notes

- **Range bounds**: `randInt`, `randLong`, and related methods use inclusive ranges [min, max]. `randDouble` uses half-open range [min, max).
- **Empty arrays**: `choice*` and `sample*` methods will panic if called on an empty array.
- **Weight validation**: `weightedChoice*` methods require the weights array to have the same length as the items array, with all weights being non-negative.
- **Sample size**: `sample*` methods will panic if `count` exceeds the array length (since they sample without replacement).

## See Also

- [UUID](uuid.md) - UUID generation (uses random internally)
- [SDK Overview](../readme.md) - All SDK modules
- [Arrays](../../arrays.md) - Array operations
