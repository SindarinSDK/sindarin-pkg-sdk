---
title: "Math"
description: "Mathematical functions and constants"
permalink: /sdk/core/math/
---

Provides C math library bindings, mathematical constants, and helper functions for both `double` and `float` precision arithmetic.

## Import

```sindarin
import "sdk/core/math" as math
```

---

## Constants

### Double Precision

| Function | Value | Description |
|----------|-------|-------------|
| `pi()` | 3.14159... | Pi |
| `e()` | 2.71828... | Euler's number |
| `tau()` | 6.28318... | 2 * Pi |
| `phi()` | 1.61803... | Golden ratio |
| `sqrt2()` | 1.41421... | Square root of 2 |
| `sqrt3()` | 1.73205... | Square root of 3 |
| `ln2()` | 0.69314... | Natural log of 2 |
| `ln10()` | 2.30258... | Natural log of 10 |

### Single Precision (float)

All constants are also available with an `F` suffix: `piF()`, `eF()`, `tauF()`, etc.

---

## Trigonometric Functions

```sindarin
var angle: double = math.degToRad(45.0)
var s: double = math.sin(angle)
var c: double = math.cos(angle)
```

| Function | Description |
|----------|-------------|
| `sin(x)` | Sine |
| `cos(x)` | Cosine |
| `tan(x)` | Tangent |
| `asin(x)` | Arc sine |
| `acos(x)` | Arc cosine |
| `atan(x)` | Arc tangent |
| `atan2(y, x)` | Two-argument arc tangent |

### Hyperbolic Functions

| Function | Description |
|----------|-------------|
| `sinh(x)` | Hyperbolic sine |
| `cosh(x)` | Hyperbolic cosine |
| `tanh(x)` | Hyperbolic tangent |
| `asinh(x)` | Inverse hyperbolic sine |
| `acosh(x)` | Inverse hyperbolic cosine |
| `atanh(x)` | Inverse hyperbolic tangent |

---

## Exponential and Logarithmic Functions

| Function | Description |
|----------|-------------|
| `exp(x)` | e^x |
| `exp2(x)` | 2^x |
| `log(x)` | Natural logarithm |
| `log2(x)` | Base-2 logarithm |
| `log10(x)` | Base-10 logarithm |
| `log1p(x)` | log(1 + x), accurate for small x |
| `expm1(x)` | e^x - 1, accurate for small x |

---

## Power Functions

| Function | Description |
|----------|-------------|
| `pow(base, exp)` | base^exp |
| `sqrt(x)` | Square root |
| `cbrt(x)` | Cube root |
| `hypot(x, y)` | sqrt(x^2 + y^2) without overflow |

---

## Rounding Functions

| Function | Description |
|----------|-------------|
| `ceil(x)` | Round up to nearest integer |
| `floor(x)` | Round down to nearest integer |
| `trunc(x)` | Round toward zero |
| `round(x)` | Round to nearest integer |

---

## Remainder and Absolute Value

| Function | Description |
|----------|-------------|
| `fmod(x, y)` | Floating-point remainder |
| `remainder(x, y)` | IEEE remainder |
| `fabs(x)` | Absolute value |

---

## Floating-Point Manipulation

| Function | Description |
|----------|-------------|
| `copysign(x, y)` | x with sign of y |
| `fdim(x, y)` | max(x-y, 0) |
| `fmax(x, y)` | Maximum |
| `fmin(x, y)` | Minimum |

---

## Integer Helpers

```sindarin
var a: int = math.absInt(-5)       // 5
var m: int = math.minInt(3, 7)     // 3
var c: int = math.clampInt(15, 0, 10)  // 10
var s: int = math.signInt(-42)     // -1
```

| Function | Description |
|----------|-------------|
| `absInt(x)` | Absolute value |
| `minInt(a, b)` | Minimum |
| `maxInt(a, b)` | Maximum |
| `clampInt(x, lo, hi)` | Clamp to range [lo, hi] |
| `signInt(x)` | Sign (-1, 0, or 1) |

---

## Double Helpers

| Function | Description |
|----------|-------------|
| `absDouble(x)` | Absolute value |
| `minDouble(a, b)` | Minimum |
| `maxDouble(a, b)` | Maximum |
| `clampDouble(x, lo, hi)` | Clamp to range |
| `signDouble(x)` | Sign (-1.0, 0.0, or 1.0) |

---

## Angle Conversion

```sindarin
var rad: double = math.degToRad(180.0)  // pi
var deg: double = math.radToDeg(math.pi())  // 180.0
```

| Function | Description |
|----------|-------------|
| `degToRad(deg)` | Degrees to radians |
| `radToDeg(rad)` | Radians to degrees |

---

## Safe Wrappers

Safe variants return 0.0 instead of NaN/undefined behavior for invalid inputs.

| Function | Description |
|----------|-------------|
| `safeSqrt(x)` | Returns 0.0 for negative inputs |
| `safeLog(x)` | Returns 0.0 for non-positive inputs |
| `safeLog10(x)` | Returns 0.0 for non-positive inputs |
| `safeLog2(x)` | Returns 0.0 for non-positive inputs |
| `safeAsin(x)` | Clamps input to [-1, 1] |
| `safeAcos(x)` | Clamps input to [-1, 1] |
| `safeDiv(x, y)` | Returns 0.0 for division by zero |
| `safeAcosh(x)` | Returns 0.0 for inputs < 1 |
| `safeAtanh(x)` | Returns 0.0 for inputs outside (-1, 1) |

---

## Utility Functions

### Interpolation

```sindarin
var mid: double = math.lerp(0.0, 100.0, 0.5)  // 50.0
var t: double = math.invLerp(0.0, 100.0, 25.0)  // 0.25
var mapped: double = math.remap(5.0, 0.0, 10.0, 0.0, 100.0)  // 50.0
```

| Function | Description |
|----------|-------------|
| `lerp(a, b, t)` | Linear interpolation: a + (b-a)*t |
| `invLerp(a, b, x)` | Inverse lerp: find t such that lerp(a,b,t)==x |
| `remap(x, inMin, inMax, outMin, outMax)` | Remap from one range to another |
| `smoothstep(edge0, edge1, x)` | Cubic Hermite interpolation |

### Distance

| Function | Description |
|----------|-------------|
| `distance2D(x1, y1, x2, y2)` | Distance between two 2D points |
| `distance3D(x1, y1, z1, x2, y2, z2)` | Distance between two 3D points |

### Comparison and Checks

| Function | Description |
|----------|-------------|
| `approxEq(a, b, tolerance)` | Check if two doubles are approximately equal |
| `isNan(x)` | Check if value is NaN |
| `isFinite(x)` | Check if value is finite |

### Angle Wrapping

| Function | Description |
|----------|-------------|
| `wrapAngle(angle)` | Wrap to [0, 2*pi) |
| `wrapAngleSigned(angle)` | Wrap to [-pi, pi) |

---

## Float (Single Precision) Variants

All functions above are also available in `float` precision with an `F` suffix:

```sindarin
var s: float = math.sinF(1.0)
var d: float = math.distance2DF(0.0, 0.0, 3.0, 4.0)  // 5.0
var safe: float = math.safeSqrtF(-1.0)  // 0.0
```

---

## Example: Vector Length and Angle

```sindarin
import "sdk/core/math" as math

fn main(): void =>
    var x: double = 3.0
    var y: double = 4.0

    var length: double = math.hypot(x, y)
    var angle: double = math.atan2(y, x)

    print($"Length: {length}\n")
    print($"Angle: {math.radToDeg(angle)} degrees\n")
```

---

## See Also

- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/core/math.sn`
