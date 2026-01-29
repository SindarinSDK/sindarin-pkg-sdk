---
title: "Time"
description: "Time and duration operations"
permalink: /sdk/time/time/
---

The built-in `Time` type has been deprecated. Please use the SDK-based `Time` type instead.

## Migration to SDK

Import the time module from the SDK:

```sindarin
import "sdk/time/time"
```

The SDK provides the `Time` struct with equivalent functionality:

```sindarin
import "sdk/time/time"

// Get current time
var now: Time = Time.now()

// Format and display
print($"Current time: {now.format("YYYY-MM-DD HH:mm:ss")}\n")

// Time arithmetic
var later: Time = now.addHours(2)
print($"Two hours from now: {later.toIso()}\n")

// Measure elapsed time
var start: Time = Time.now()
doSomeWork()
var elapsed: int = Time.now().diff(start)
print($"Elapsed: {elapsed}ms\n")
```

## SDK Time API

See the SDK time module documentation for the complete API reference:

- `Time.now()` - Get current local time
- `Time.utc()` - Get current UTC time
- `Time.fromMillis(ms)` - Create from epoch milliseconds
- `Time.fromSeconds(s)` - Create from epoch seconds
- `Time.sleep(ms)` - Sleep for milliseconds

Instance methods:
- `millis()`, `seconds()` - Get epoch time
- `year()`, `month()`, `day()` - Get date components
- `hour()`, `minute()`, `second()` - Get time components
- `weekday()` - Get day of week
- `format(pattern)`, `toIso()` - Formatting
- `add(ms)`, `addSeconds()`, `addMinutes()`, `addHours()`, `addDays()` - Arithmetic
- `diff(other)`, `isBefore()`, `isAfter()`, `equals()` - Comparison

---

## See Also

- [Date](date.md) - Calendar date operations
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/time/time.sn`
