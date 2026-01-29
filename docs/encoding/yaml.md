---
title: "YAML"
description: "YAML parsing and serialization"
permalink: /sdk/encoding/yaml/
---

Provides YAML parsing, manipulation, and serialization using libyaml. The `Yaml` type represents a YAML node (scalar, sequence, or mapping) with full mutation support.

## Import

```sindarin
import "sdk/encoding/yaml"
```

---

## Parsing

```sindarin
# Parse from string
var doc: Yaml = Yaml.parse("name: Alice\nage: 30\n")

# Parse from file
var config: Yaml = Yaml.parseFile("config.yaml")
```

---

## Reading Values

```sindarin
var doc: Yaml = Yaml.parseFile("config.yaml")

var name: str = doc.get("name").value()     // Raw string value
var age: int = doc.get("age").asInt()        // Parse as integer
var rate: double = doc.get("rate").asFloat() // Parse as double
var debug: bool = doc.get("debug").asBool()  // Parse as bool
```

### Value Access Methods (Scalars)

| Method | Return | Description |
|--------|--------|-------------|
| `value()` | `str` | Raw scalar string value |
| `asInt()` | `int` | Parse as integer |
| `asLong()` | `long` | Parse as long |
| `asFloat()` | `double` | Parse as double |
| `asBool()` | `bool` | Parse as bool (true/false/yes/no/on/off) |

---

## Type Checking

```sindarin
if doc.isMapping() =>
    var keys: str[] = doc.keys()
    print($"Has {doc.length()} keys\n")

if node.isSequence() =>
    print($"Has {node.length()} items\n")

if node.isScalar() =>
    print($"Value: {node.value()}\n")
```

| Method | Description |
|--------|-------------|
| `isScalar()` | Is a scalar (string) node |
| `isSequence()` | Is a sequence (list) node |
| `isMapping()` | Is a mapping (dictionary) node |

---

## Creating YAML

```sindarin
# Scalars
var name: Yaml = Yaml.scalar("Alice")
var age: Yaml = Yaml.scalar("30")

# Sequences (lists)
var seq: Yaml = Yaml.sequence()
seq.append(Yaml.scalar("item1"))
seq.append(Yaml.scalar("item2"))

# Mappings (dictionaries)
var map: Yaml = Yaml.mapping()
map.set("name", Yaml.scalar("Alice"))
map.set("age", Yaml.scalar("30"))
```

| Method | Description |
|--------|-------------|
| `Yaml.scalar(value)` | Create a scalar node |
| `Yaml.sequence()` | Create an empty sequence |
| `Yaml.mapping()` | Create an empty mapping |

---

## Mapping Operations

### Access

```sindarin
var val: Yaml = doc.get("key")
var exists: bool = doc.has("key")
var keys: str[] = doc.keys()
var count: int = doc.length()
```

### Mutation

```sindarin
var map: Yaml = Yaml.mapping()
map.set("name", Yaml.scalar("Bob"))
map.set("active", Yaml.scalar("true"))
map.remove("active")
```

---

## Sequence Operations

### Access

```sindarin
var first: Yaml = seq.first()
var last: Yaml = seq.last()
var item: Yaml = seq.getAt(2)
var count: int = seq.length()
var empty: bool = seq.isEmpty()
```

### Mutation

```sindarin
var seq: Yaml = Yaml.sequence()
seq.append(Yaml.scalar("end"))
seq.prepend(Yaml.scalar("start"))
seq.removeAt(0)
```

| Method | Description |
|--------|-------------|
| `append(value)` | Add to end |
| `prepend(value)` | Add to start |
| `removeAt(index)` | Remove at position |

---

## Serialization

```sindarin
var output: str = doc.toString()
doc.writeFile("/tmp/output.yaml")
```

---

## Utility Methods

| Method | Return | Description |
|--------|--------|-------------|
| `copy()` | `Yaml` | Deep copy of the node |
| `typeName()` | `str` | Type as string ("scalar", "sequence", "mapping") |

---

## Example: Configuration File

```sindarin
import "sdk/encoding/yaml"

fn main(): void =>
    var config: Yaml = Yaml.parseFile("app.yaml")

    var host: str = config.get("server").get("host").value()
    var port: int = config.get("server").get("port").asInt()
    var debug: bool = config.get("debug").asBool()

    print($"Server: {host}:{port}\n")
    print($"Debug: {debug}\n")
```

## Example: Building YAML

```sindarin
import "sdk/encoding/yaml"

fn main(): void =>
    var config: Yaml = Yaml.mapping()

    var server: Yaml = Yaml.mapping()
    server.set("host", Yaml.scalar("localhost"))
    server.set("port", Yaml.scalar("8080"))
    config.set("server", server)

    var features: Yaml = Yaml.sequence()
    features.append(Yaml.scalar("auth"))
    features.append(Yaml.scalar("logging"))
    features.append(Yaml.scalar("metrics"))
    config.set("features", features)

    config.set("debug", Yaml.scalar("false"))

    print(config.toString())
    config.writeFile("/tmp/config.yaml")
```

---

## Requirements

- libyaml library must be installed
- Install via vcpkg (`make setup`)

---

## See Also

- [JSON](json.md) - JSON parsing and serialization
- [XML](xml.md) - XML parsing and manipulation
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/encoding/yaml.sn`
