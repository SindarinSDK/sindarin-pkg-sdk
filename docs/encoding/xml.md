---
title: "XML"
description: "XML parsing, XPath, and DOM manipulation"
permalink: /sdk/encoding/xml/
---

Provides XML parsing, DOM manipulation, XPath queries, and serialization using libxml2. The `Xml` type represents an XML node (element, document, or text) with full tree navigation and mutation support.

## Import

```sindarin
import "sdk/encoding/xml"
```

---

## Parsing

```sindarin
# Parse from string
var doc: Xml = Xml.parse("<root><item>Hello</item></root>")

# Parse from file
var config: Xml = Xml.parseFile("data.xml")
```

---

## Creating XML

```sindarin
# Create a document with root element
var doc: Xml = Xml.document("catalog")

# Create standalone elements
var item: Xml = Xml.element("item")
item.setAttr("id", "1")
item.setText("First item")
doc.addChild(item)
```

| Method | Description |
|--------|-------------|
| `Xml.document(rootName)` | Create a new document with root element |
| `Xml.element(name)` | Create a standalone element |

---

## Node Information

```sindarin
var name: str = node.name()        // Element name
var text: str = node.text()        // Text content
var type: str = node.typeName()    // "element", "text", "document", etc.
```

| Method | Return | Description |
|--------|--------|-------------|
| `name()` | `str` | Element/node name |
| `text()` | `str` | Combined text of node and descendants |
| `typeName()` | `str` | Node type as string |
| `isElement()` | `bool` | Is an element node |
| `isText()` | `bool` | Is a text node |
| `isDocument()` | `bool` | Is a document node |

---

## Attributes

```sindarin
node.setAttr("version", "1.0")
var ver: str = node.attr("version")

if node.hasAttr("id") =>
    print($"ID: {node.attr("id")}\n")

node.removeAttr("deprecated")
var names: str[] = node.attrs()
```

| Method | Description |
|--------|-------------|
| `attr(name)` | Get attribute value (empty if missing) |
| `hasAttr(name)` | Check if attribute exists |
| `setAttr(name, value)` | Set attribute value |
| `removeAttr(name)` | Remove an attribute |
| `attrs()` | Get all attribute names |

---

## Navigation

### Children

```sindarin
var children: Xml[] = node.children()
var first: Xml = node.firstChild()
var last: Xml = node.lastChild()
var count: int = node.childCount()
```

| Method | Return | Description |
|--------|--------|-------------|
| `children()` | `Xml[]` | All child element nodes |
| `firstChild()` | `Xml` | First child element |
| `lastChild()` | `Xml` | Last child element |
| `childCount()` | `int` | Number of child elements |
| `hasChildren()` | `bool` | Has child elements |

### Siblings and Parent

```sindarin
var parent: Xml = node.parent()
var next: Xml = node.next()
var prev: Xml = node.prev()
```

---

## XPath Queries

```sindarin
# Find first match
var item: Xml = doc.find("//item[@id='1']")
print(item.text())

# Find all matches
var items: Xml[] = doc.findAll("//item")
for i: int = 0; i < items.length; i += 1 =>
    print($"{items[i].attr("id")}: {items[i].text()}\n")
```

| Method | Return | Description |
|--------|--------|-------------|
| `find(xpath)` | `Xml` | First matching node |
| `findAll(xpath)` | `Xml[]` | All matching nodes |

---

## Mutation

```sindarin
var child: Xml = Xml.element("item")
child.setText("New item")
parent.addChild(child)

node.setName("renamed")
node.setText("Updated content")
node.remove()  // Remove from parent
```

| Method | Description |
|--------|-------------|
| `addChild(child)` | Append child element |
| `setText(content)` | Set text content |
| `setName(name)` | Rename element |
| `remove()` | Remove this node from its parent |

---

## Serialization

```sindarin
var compact: str = doc.toString()
var pretty: str = doc.toPrettyString()

doc.writeFile("output.xml")
doc.writeFilePretty("output_pretty.xml")
```

---

## Utility

| Method | Return | Description |
|--------|--------|-------------|
| `copy()` | `Xml` | Deep copy of the node |

---

## Example: Building an XML Document

```sindarin
import "sdk/encoding/xml"

fn main(): void =>
    var doc: Xml = Xml.document("catalog")
    doc.setAttr("version", "1.0")

    var book: Xml = Xml.element("book")
    book.setAttr("id", "1")

    var title: Xml = Xml.element("title")
    title.setText("The Sindarin Guide")
    book.addChild(title)

    var author: Xml = Xml.element("author")
    author.setText("J. Doe")
    book.addChild(author)

    doc.addChild(book)
    print(doc.toPrettyString())
```

## Example: Parsing and Querying

```sindarin
import "sdk/encoding/xml"

fn main(): void =>
    var doc: Xml = Xml.parseFile("books.xml")

    var books: Xml[] = doc.findAll("//book")
    for i: int = 0; i < books.length; i += 1 =>
        var title: Xml = books[i].find("title")
        var author: Xml = books[i].find("author")
        print($"{title.text()} by {author.text()}\n")
```

---

## Requirements

- libxml2 library must be installed
- Install via vcpkg (`make setup`)

---

## See Also

- [JSON](json.md) - JSON parsing and serialization
- [YAML](yaml.md) - YAML parsing and serialization
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/encoding/xml.sn`
