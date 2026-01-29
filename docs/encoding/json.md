---
title: "JSON"
description: "JSON parsing and serialization"
permalink: /sdk/encoding/json/
---

Provides JSON parsing, manipulation, and serialization using the yyjson library. The `Json` type represents any JSON value (object, array, string, number, boolean, or null) and supports both reading and mutation.

## Import

```sindarin
import "sdk/encoding/json"
```

---

## Parsing

```sindarin
# Parse from string
var doc: Json = Json.parse("{\"name\": \"Alice\", \"age\": 30}")

# Parse from file
var config: Json = Json.parseFile("config.json")
```

---

## Reading Values

```sindarin
var doc: Json = Json.parse("{\"name\": \"Alice\", \"age\": 30, \"active\": true}")

var name: str = doc.get("name").asString()    // "Alice"
var age: int = doc.get("age").asInt()          // 30
var active: bool = doc.get("active").asBool()  // true
```

### Value Extraction Methods

| Method | Return | Description |
|--------|--------|-------------|
| `asString()` | `str` | Get string value (empty if not a string) |
| `asInt()` | `int` | Get integer value (0 if not a number) |
| `asLong()` | `long` | Get long value (0 if not a number) |
| `asFloat()` | `double` | Get floating-point value (0.0 if not a number) |
| `asBool()` | `bool` | Get boolean value (false if not a boolean) |

---

## Type Checking

```sindarin
if doc.get("name").isString() =>
    print("name is a string\n")

if doc.get("scores").isArray() =>
    print($"has {doc.get("scores").length()} scores\n")
```

| Method | Description |
|--------|-------------|
| `isObject()` | Is a JSON object |
| `isArray()` | Is a JSON array |
| `isString()` | Is a string |
| `isNumber()` | Is a number (int or float) |
| `isInt()` | Is an integer |
| `isFloat()` | Is a floating-point number |
| `isBool()` | Is a boolean |
| `isNull()` | Is null |

---

## Creating JSON

### Static Factory Methods

```sindarin
var obj: Json = Json.object()
var arr: Json = Json.array()
var s: Json = Json.ofString("hello")
var n: Json = Json.ofInt(42)
var f: Json = Json.ofFloat(3.14)
var b: Json = Json.ofBool(true)
var null_val: Json = Json.ofNull()
```

| Method | Description |
|--------|-------------|
| `Json.object()` | Create empty object `{}` |
| `Json.array()` | Create empty array `[]` |
| `Json.ofString(value)` | Create string value |
| `Json.ofInt(value)` | Create integer value |
| `Json.ofFloat(value)` | Create floating-point value |
| `Json.ofBool(value)` | Create boolean value |
| `Json.ofNull()` | Create null value |

---

## Object Operations

### Access

```sindarin
var val: Json = doc.get("key")        // Get by key
var exists: bool = doc.has("key")     // Check key exists
var keys: str[] = doc.keys()          // Get all keys
var count: int = doc.length()         // Number of keys
```

### Mutation

```sindarin
var obj: Json = Json.object()
obj.set("name", Json.ofString("Bob"))
obj.set("age", Json.ofInt(25))
obj.remove("age")
```

---

## Array Operations

### Access

```sindarin
var arr: Json = doc.get("items")
var first: Json = arr.first()
var last: Json = arr.last()
var item: Json = arr.getAt(2)
var count: int = arr.length()
var empty: bool = arr.isEmpty()
```

### Mutation

```sindarin
var arr: Json = Json.array()
arr.append(Json.ofInt(1))
arr.append(Json.ofInt(2))
arr.prepend(Json.ofInt(0))
arr.insert(1, Json.ofInt(99))
arr.removeAt(2)
```

| Method | Description |
|--------|-------------|
| `append(value)` | Add to end |
| `prepend(value)` | Add to start |
| `insert(index, value)` | Insert at position |
| `removeAt(index)` | Remove at position |

---

## Serialization

```sindarin
# To string
var compact: str = doc.toString()        // {"name":"Alice","age":30}
var pretty: str = doc.toPrettyString()   // Formatted with indentation

# To file
doc.writeFile("output.json")
doc.writeFilePretty("output_pretty.json")
```

---

## Utility Methods

| Method | Return | Description |
|--------|--------|-------------|
| `copy()` | `Json` | Deep copy of the value |
| `typeName()` | `str` | Type as string ("object", "array", "string", "number", "bool", "null") |

---

## Example: Building and Serializing

```sindarin
import "sdk/encoding/json"

fn main(): void =>
    var user: Json = Json.object()
    user.set("name", Json.ofString("Alice"))
    user.set("age", Json.ofInt(30))
    user.set("active", Json.ofBool(true))

    var scores: Json = Json.array()
    scores.append(Json.ofInt(95))
    scores.append(Json.ofInt(87))
    scores.append(Json.ofInt(92))
    user.set("scores", scores)

    print(user.toPrettyString())
```

## Example: Parsing and Iterating

```sindarin
import "sdk/encoding/json"

fn main(): void =>
    var doc: Json = Json.parseFile("users.json")

    var keys: str[] = doc.keys()
    for i: int = 0; i < doc.length(); i += 1 =>
        var key: str = keys[i]
        var val: Json = doc.get(key)
        print($"{key}: {val.toString()}\n")
```

---

## Requirements

- yyjson library must be installed
- Linux: Install via vcpkg or package manager
- macOS: `brew install yyjson`
- Windows: Install via vcpkg

---

## See Also

- [YAML](yaml.md) - YAML parsing and serialization
- [XML](xml.md) - XML parsing and manipulation
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/encoding/json.sn`
