---
title: "Date"
description: "Calendar date operations"
permalink: /sdk/time/date/
---

The built-in `Date` type has been deprecated. Please use the SDK-based `Date` type instead.

## Migration to SDK

Import the date module from the SDK:

```sindarin
import "sdk/time/date"
```

The SDK provides the `Date` struct with equivalent functionality:

```sindarin
import "sdk/time/date"

// Get current date
var today: Date = Date.today()

// Format and display
print($"Today is: {today.format("YYYY-MM-DD")}\n")

// Date arithmetic
var nextWeek: Date = today.addDays(7)
print($"Next week: {nextWeek.toIso()}\n")

// Days between dates
var birthday: Date = Date.fromYmd(2025, 6, 15)
var daysUntil: int = birthday.diffDays(today)
print($"Days until birthday: {daysUntil}\n")
```

## SDK Date API

See the SDK date module documentation for the complete API reference:

- `Date.today()` - Get current local date
- `Date.fromYmd(year, month, day)` - Create from components
- `Date.fromString(str)` - Parse from ISO string
- `Date.fromEpochDays(days)` - Create from epoch days
- `Date.isLeapYear(year)` - Check leap year
- `Date.daysInMonth(year, month)` - Get days in month

Instance methods:
- `year()`, `month()`, `day()` - Get components
- `weekday()`, `dayOfYear()`, `epochDays()` - Get derived values
- `daysInMonth()`, `isLeapYear()` - Query methods
- `isWeekend()`, `isWeekday()` - Day type checks
- `format(pattern)`, `toIso()`, `toString()` - Formatting
- `addDays()`, `addWeeks()`, `addMonths()`, `addYears()` - Arithmetic
- `diffDays()` - Days between dates
- `startOfMonth()`, `endOfMonth()`, `startOfYear()`, `endOfYear()` - Boundaries
- `isBefore()`, `isAfter()`, `equals()` - Comparison

---

## See Also

- [Time](time.md) - Time operations
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/time/date.sn`
