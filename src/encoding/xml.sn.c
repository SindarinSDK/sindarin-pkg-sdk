/* ==============================================================================
 * sdk/xml.sn.c - XML Implementation for Sindarin SDK using libxml2
 * ==============================================================================
 * This file provides the C implementation for the Xml type.
 * It is compiled via #pragma source and linked with Sindarin code.
 * ============================================================================== */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlmemory.h>

/* Include runtime arena for proper memory management */
#include "runtime/runtime_arena.h"
#include "runtime/arena/managed_arena.h"
#include "runtime/runtime_array.h"
#include "runtime/runtime_array_h.h"

/* ============================================================================
 * Xml Type Definition
 * ============================================================================ */

typedef struct SnXml {
    xmlDocPtr doc;       /* The XML document (owns memory when is_root) */
    xmlNodePtr node;     /* The current node within the document */
    int32_t is_root;     /* Whether this owns the document */
} SnXml;

/* ============================================================================
 * Parser Initialization
 * ============================================================================ */

static int sn_xml_initialized = 0;

static void sn_xml_cleanup(void)
{
    xmlCleanupParser();
}

static void sn_xml_init(void)
{
    if (!sn_xml_initialized) {
        xmlInitParser();
        atexit(sn_xml_cleanup);
        sn_xml_initialized = 1;
    }
}

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/* Create a new SnXml wrapper for a node within an existing document */
static SnXml *sn_xml_wrap(RtArena *arena, xmlDocPtr doc, xmlNodePtr node, int is_root)
{
    SnXml *x = rt_arena_alloc(arena, sizeof(SnXml));
    if (x == NULL) {
        fprintf(stderr, "Xml: memory allocation failed\n");
        exit(1);
    }
    x->doc = doc;
    x->node = node;
    x->is_root = is_root;
    return x;
}

/* Find the next sibling that is an element node */
static xmlNodePtr next_element_sibling(xmlNodePtr node)
{
    if (node == NULL) return NULL;
    xmlNodePtr cur = node->next;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) return cur;
        cur = cur->next;
    }
    return NULL;
}

/* Find the previous sibling that is an element node */
static xmlNodePtr prev_element_sibling(xmlNodePtr node)
{
    if (node == NULL) return NULL;
    xmlNodePtr cur = node->prev;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) return cur;
        cur = cur->prev;
    }
    return NULL;
}

/* Find the first child that is an element node */
static xmlNodePtr first_element_child(xmlNodePtr node)
{
    if (node == NULL) return NULL;
    xmlNodePtr cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) return cur;
        cur = cur->next;
    }
    return NULL;
}

/* Find the last child that is an element node */
static xmlNodePtr last_element_child(xmlNodePtr node)
{
    if (node == NULL) return NULL;
    xmlNodePtr cur = node->last;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) return cur;
        cur = cur->prev;
    }
    return NULL;
}

/* ============================================================================
 * Parsing Functions
 * ============================================================================ */

SnXml *sn_xml_parse(RtArena *arena, const char *text)
{
    if (arena == NULL) {
        fprintf(stderr, "Xml.parse: arena is NULL\n");
        exit(1);
    }
    if (text == NULL) {
        fprintf(stderr, "Xml.parse: text is NULL\n");
        exit(1);
    }

    sn_xml_init();

    xmlDocPtr doc = xmlParseMemory(text, (int)strlen(text));
    if (doc == NULL) {
        fprintf(stderr, "Xml.parse: failed to parse XML\n");
        exit(1);
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    return sn_xml_wrap(arena, doc, root, 1);
}

SnXml *sn_xml_parse_file(RtArena *arena, const char *path)
{
    if (arena == NULL) {
        fprintf(stderr, "Xml.parseFile: arena is NULL\n");
        exit(1);
    }
    if (path == NULL) {
        fprintf(stderr, "Xml.parseFile: path is NULL\n");
        exit(1);
    }

    sn_xml_init();

    xmlDocPtr doc = xmlParseFile(path);
    if (doc == NULL) {
        fprintf(stderr, "Xml.parseFile: failed to parse file: %s\n", path);
        exit(1);
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    return sn_xml_wrap(arena, doc, root, 1);
}

/* ============================================================================
 * Creation Functions
 * ============================================================================ */

SnXml *sn_xml_element(RtArena *arena, const char *name)
{
    if (arena == NULL) {
        fprintf(stderr, "Xml.element: arena is NULL\n");
        exit(1);
    }
    if (name == NULL) {
        fprintf(stderr, "Xml.element: name is NULL\n");
        exit(1);
    }

    sn_xml_init();

    /* Create a document to own the node */
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        fprintf(stderr, "Xml.element: failed to create document\n");
        exit(1);
    }

    xmlNodePtr node = xmlNewNode(NULL, BAD_CAST name);
    if (node == NULL) {
        xmlFreeDoc(doc);
        fprintf(stderr, "Xml.element: failed to create element\n");
        exit(1);
    }

    xmlDocSetRootElement(doc, node);
    return sn_xml_wrap(arena, doc, node, 1);
}

SnXml *sn_xml_document(RtArena *arena, const char *rootName)
{
    if (arena == NULL) {
        fprintf(stderr, "Xml.document: arena is NULL\n");
        exit(1);
    }
    if (rootName == NULL) {
        fprintf(stderr, "Xml.document: rootName is NULL\n");
        exit(1);
    }

    sn_xml_init();

    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        fprintf(stderr, "Xml.document: failed to create document\n");
        exit(1);
    }

    xmlNodePtr root = xmlNewNode(NULL, BAD_CAST rootName);
    if (root == NULL) {
        xmlFreeDoc(doc);
        fprintf(stderr, "Xml.document: failed to create root element\n");
        exit(1);
    }

    xmlDocSetRootElement(doc, root);
    return sn_xml_wrap(arena, doc, root, 1);
}

/* ============================================================================
 * Node Info Functions
 * ============================================================================ */

RtHandle sn_xml_name(RtManagedArena *arena, SnXml *x)
{
    if (x == NULL || x->node == NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }
    const char *name = (const char *)x->node->name;
    return rt_managed_strdup(arena, RT_HANDLE_NULL, name ? name : "");
}

RtHandle sn_xml_text(RtManagedArena *arena, SnXml *x)
{
    if (x == NULL || x->node == NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    xmlChar *content = xmlNodeGetContent(x->node);
    if (content == NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    RtHandle result = rt_managed_strdup(arena, RT_HANDLE_NULL, (const char *)content);
    xmlFree(content);
    return result;
}

RtHandle sn_xml_type_name(RtManagedArena *arena, SnXml *x)
{
    if (x == NULL || x->node == NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "null");
    }

    switch (x->node->type) {
        case XML_ELEMENT_NODE:       return rt_managed_strdup(arena, RT_HANDLE_NULL, "element");
        case XML_TEXT_NODE:          return rt_managed_strdup(arena, RT_HANDLE_NULL, "text");
        case XML_COMMENT_NODE:       return rt_managed_strdup(arena, RT_HANDLE_NULL, "comment");
        case XML_DOCUMENT_NODE:      return rt_managed_strdup(arena, RT_HANDLE_NULL, "document");
        case XML_ATTRIBUTE_NODE:     return rt_managed_strdup(arena, RT_HANDLE_NULL, "attribute");
        case XML_CDATA_SECTION_NODE: return rt_managed_strdup(arena, RT_HANDLE_NULL, "cdata");
        case XML_PI_NODE:            return rt_managed_strdup(arena, RT_HANDLE_NULL, "processing-instruction");
        default:                     return rt_managed_strdup(arena, RT_HANDLE_NULL, "unknown");
    }
}

bool sn_xml_is_element(SnXml *x)
{
    if (x == NULL || x->node == NULL) return false;
    return x->node->type == XML_ELEMENT_NODE;
}

bool sn_xml_is_text(SnXml *x)
{
    if (x == NULL || x->node == NULL) return false;
    return x->node->type == XML_TEXT_NODE;
}

bool sn_xml_is_document(SnXml *x)
{
    if (x == NULL || x->node == NULL) return false;
    return x->node->type == XML_DOCUMENT_NODE;
}

/* ============================================================================
 * Attribute Functions
 * ============================================================================ */

RtHandle sn_xml_attr(RtManagedArena *arena, SnXml *x, const char *name)
{
    if (x == NULL || x->node == NULL || name == NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }
    if (x->node->type != XML_ELEMENT_NODE) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    xmlChar *value = xmlGetProp(x->node, BAD_CAST name);
    if (value == NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    RtHandle result = rt_managed_strdup(arena, RT_HANDLE_NULL, (const char *)value);
    xmlFree(value);
    return result;
}

bool sn_xml_has_attr(SnXml *x, const char *name)
{
    if (x == NULL || x->node == NULL || name == NULL) return false;
    if (x->node->type != XML_ELEMENT_NODE) return false;
    return xmlHasProp(x->node, BAD_CAST name) != NULL;
}

void sn_xml_set_attr(SnXml *x, const char *name, const char *value)
{
    if (x == NULL || x->node == NULL || name == NULL || value == NULL) {
        fprintf(stderr, "Xml.setAttr: invalid arguments\n");
        return;
    }
    if (x->node->type != XML_ELEMENT_NODE) {
        fprintf(stderr, "Xml.setAttr: not an element node\n");
        return;
    }

    xmlSetProp(x->node, BAD_CAST name, BAD_CAST value);
}

void sn_xml_remove_attr(SnXml *x, const char *name)
{
    if (x == NULL || x->node == NULL || name == NULL) return;
    if (x->node->type != XML_ELEMENT_NODE) return;

    xmlAttrPtr attr = xmlHasProp(x->node, BAD_CAST name);
    if (attr != NULL) {
        xmlRemoveProp(attr);
    }
}

RtHandle sn_xml_attrs(RtManagedArena *arena, SnXml *x)
{
    if (x == NULL || x->node == NULL || x->node->type != XML_ELEMENT_NODE) {
        return rt_array_create_string_h(arena, 0, NULL);
    }

    RtHandle names = rt_array_create_string_h(arena, 0, NULL);

    xmlAttrPtr attr = x->node->properties;
    while (attr != NULL) {
        if (attr->name != NULL) {
            RtHandle name = rt_managed_strdup(arena, RT_HANDLE_NULL, (const char *)attr->name);
            char *name_ptr = (char *)rt_managed_pin(arena, name);
            names = rt_array_push_string_h(arena, names, name_ptr);
        }
        attr = attr->next;
    }

    return names;
}

/* ============================================================================
 * Child Navigation Functions
 * ============================================================================ */

RtHandle sn_xml_children(RtManagedArena *arena, SnXml *x)
{
    if (x == NULL || x->node == NULL) {
        return RT_HANDLE_NULL;
    }

    RtHandle children = RT_HANDLE_NULL;

    xmlNodePtr cur = x->node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            SnXml *child = sn_xml_wrap((RtArena *)arena, x->doc, cur, 0);
            children = rt_array_push_voidptr_h(arena, children, child);
        }
        cur = cur->next;
    }

    return children;
}

SnXml *sn_xml_first_child(RtArena *arena, SnXml *x)
{
    if (x == NULL || x->node == NULL) {
        return sn_xml_wrap(arena, NULL, NULL, 0);
    }

    xmlNodePtr child = first_element_child(x->node);
    return sn_xml_wrap(arena, x->doc, child, 0);
}

SnXml *sn_xml_last_child(RtArena *arena, SnXml *x)
{
    if (x == NULL || x->node == NULL) {
        return sn_xml_wrap(arena, NULL, NULL, 0);
    }

    xmlNodePtr child = last_element_child(x->node);
    return sn_xml_wrap(arena, x->doc, child, 0);
}

int64_t sn_xml_child_count(SnXml *x)
{
    if (x == NULL || x->node == NULL) return 0;

    int64_t count = 0;
    xmlNodePtr cur = x->node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) count++;
        cur = cur->next;
    }
    return count;
}

bool sn_xml_has_children(SnXml *x)
{
    if (x == NULL || x->node == NULL) return false;
    return first_element_child(x->node) != NULL;
}

/* ============================================================================
 * Sibling/Parent Navigation Functions
 * ============================================================================ */

SnXml *sn_xml_parent(RtArena *arena, SnXml *x)
{
    if (x == NULL || x->node == NULL || x->node->parent == NULL) {
        return sn_xml_wrap(arena, x ? x->doc : NULL, NULL, 0);
    }

    xmlNodePtr parent = x->node->parent;
    /* Don't navigate above the document node */
    if (parent->type == XML_DOCUMENT_NODE) {
        return sn_xml_wrap(arena, x->doc, NULL, 0);
    }

    return sn_xml_wrap(arena, x->doc, parent, 0);
}

SnXml *sn_xml_next(RtArena *arena, SnXml *x)
{
    if (x == NULL || x->node == NULL) {
        return sn_xml_wrap(arena, x ? x->doc : NULL, NULL, 0);
    }

    xmlNodePtr next = next_element_sibling(x->node);
    return sn_xml_wrap(arena, x->doc, next, 0);
}

SnXml *sn_xml_prev(RtArena *arena, SnXml *x)
{
    if (x == NULL || x->node == NULL) {
        return sn_xml_wrap(arena, x ? x->doc : NULL, NULL, 0);
    }

    xmlNodePtr prev = prev_element_sibling(x->node);
    return sn_xml_wrap(arena, x->doc, prev, 0);
}

/* ============================================================================
 * XPath Functions
 * ============================================================================ */

SnXml *sn_xml_find(RtArena *arena, SnXml *x, const char *xpath)
{
    if (x == NULL || x->doc == NULL || xpath == NULL) {
        return sn_xml_wrap(arena, x ? x->doc : NULL, NULL, 0);
    }

    sn_xml_init();

    xmlXPathContextPtr ctx = xmlXPathNewContext(x->doc);
    if (ctx == NULL) {
        return sn_xml_wrap(arena, x->doc, NULL, 0);
    }

    /* Set context node if we have one */
    if (x->node != NULL) {
        ctx->node = x->node;
    }

    xmlXPathObjectPtr result = xmlXPathEvalExpression(BAD_CAST xpath, ctx);
    if (result == NULL) {
        xmlXPathFreeContext(ctx);
        return sn_xml_wrap(arena, x->doc, NULL, 0);
    }

    SnXml *found = NULL;
    if (result->nodesetval != NULL && result->nodesetval->nodeNr > 0) {
        xmlNodePtr node = result->nodesetval->nodeTab[0];
        found = sn_xml_wrap(arena, x->doc, node, 0);
    } else {
        found = sn_xml_wrap(arena, x->doc, NULL, 0);
    }

    xmlXPathFreeObject(result);
    xmlXPathFreeContext(ctx);
    return found;
}

RtHandle sn_xml_find_all(RtManagedArena *arena, SnXml *x, const char *xpath)
{
    if (x == NULL || x->doc == NULL || xpath == NULL) {
        return RT_HANDLE_NULL;
    }

    sn_xml_init();

    xmlXPathContextPtr ctx = xmlXPathNewContext(x->doc);
    if (ctx == NULL) {
        return RT_HANDLE_NULL;
    }

    /* Set context node if we have one */
    if (x->node != NULL) {
        ctx->node = x->node;
    }

    xmlXPathObjectPtr result = xmlXPathEvalExpression(BAD_CAST xpath, ctx);
    if (result == NULL) {
        xmlXPathFreeContext(ctx);
        return RT_HANDLE_NULL;
    }

    RtHandle nodes = RT_HANDLE_NULL;

    if (result->nodesetval != NULL) {
        for (int i = 0; i < result->nodesetval->nodeNr; i++) {
            xmlNodePtr node = result->nodesetval->nodeTab[i];
            SnXml *wrapped = sn_xml_wrap((RtArena *)arena, x->doc, node, 0);
            nodes = rt_array_push_voidptr_h(arena, nodes, wrapped);
        }
    }

    xmlXPathFreeObject(result);
    xmlXPathFreeContext(ctx);
    return nodes;
}

/* ============================================================================
 * Mutation Functions
 * ============================================================================ */

void sn_xml_add_child(SnXml *x, SnXml *child)
{
    if (x == NULL || x->node == NULL || child == NULL || child->node == NULL) {
        fprintf(stderr, "Xml.addChild: invalid arguments\n");
        return;
    }
    if (x->node->type != XML_ELEMENT_NODE) {
        fprintf(stderr, "Xml.addChild: parent is not an element node\n");
        return;
    }

    /* If the child belongs to a different document, copy it */
    if (child->doc != x->doc) {
        xmlNodePtr copy = xmlDocCopyNode(child->node, x->doc, 1);
        if (copy == NULL) {
            fprintf(stderr, "Xml.addChild: failed to copy node\n");
            return;
        }
        xmlAddChild(x->node, copy);
    } else {
        /* Unlink from current parent if needed */
        xmlUnlinkNode(child->node);
        xmlAddChild(x->node, child->node);
    }
}

void sn_xml_set_text(SnXml *x, const char *content)
{
    if (x == NULL || x->node == NULL || content == NULL) {
        fprintf(stderr, "Xml.setText: invalid arguments\n");
        return;
    }

    xmlNodeSetContent(x->node, BAD_CAST content);
}

void sn_xml_set_name(SnXml *x, const char *name)
{
    if (x == NULL || x->node == NULL || name == NULL) {
        fprintf(stderr, "Xml.setName: invalid arguments\n");
        return;
    }
    if (x->node->type != XML_ELEMENT_NODE) {
        fprintf(stderr, "Xml.setName: not an element node\n");
        return;
    }

    xmlNodeSetName(x->node, BAD_CAST name);
}

void sn_xml_remove(SnXml *x)
{
    if (x == NULL || x->node == NULL) return;

    xmlUnlinkNode(x->node);
    xmlFreeNode(x->node);
    x->node = NULL;
}

/* ============================================================================
 * Serialization Functions
 * ============================================================================ */

RtHandle sn_xml_to_string(RtManagedArena *arena, SnXml *x)
{
    if (x == NULL || x->node == NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    xmlBufferPtr buf = xmlBufferCreate();
    if (buf == NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    int size = xmlNodeDump(buf, x->doc, x->node, 0, 0);
    if (size < 0) {
        xmlBufferFree(buf);
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    const char *content = (const char *)xmlBufferContent(buf);
    RtHandle result = rt_managed_strdup(arena, RT_HANDLE_NULL, content ? content : "");
    xmlBufferFree(buf);
    return result;
}

RtHandle sn_xml_to_pretty_string(RtManagedArena *arena, SnXml *x)
{
    if (x == NULL || x->node == NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    xmlBufferPtr buf = xmlBufferCreate();
    if (buf == NULL) {
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    int size = xmlNodeDump(buf, x->doc, x->node, 0, 1);
    if (size < 0) {
        xmlBufferFree(buf);
        return rt_managed_strdup(arena, RT_HANDLE_NULL, "");
    }

    const char *content = (const char *)xmlBufferContent(buf);
    RtHandle result = rt_managed_strdup(arena, RT_HANDLE_NULL, content ? content : "");
    xmlBufferFree(buf);
    return result;
}

void sn_xml_write_file(SnXml *x, const char *path)
{
    if (x == NULL || x->doc == NULL || path == NULL) {
        fprintf(stderr, "Xml.writeFile: invalid arguments\n");
        return;
    }

    int ret = xmlSaveFormatFileEnc(path, x->doc, "UTF-8", 0);
    if (ret < 0) {
        fprintf(stderr, "Xml.writeFile: failed to write file: %s\n", path);
    }
}

void sn_xml_write_file_pretty(SnXml *x, const char *path)
{
    if (x == NULL || x->doc == NULL || path == NULL) {
        fprintf(stderr, "Xml.writeFilePretty: invalid arguments\n");
        return;
    }

    int ret = xmlSaveFormatFileEnc(path, x->doc, "UTF-8", 1);
    if (ret < 0) {
        fprintf(stderr, "Xml.writeFilePretty: failed to write file: %s\n", path);
    }
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

SnXml *sn_xml_copy(RtArena *arena, SnXml *x)
{
    if (x == NULL || x->node == NULL) {
        return sn_xml_wrap(arena, NULL, NULL, 0);
    }

    sn_xml_init();

    /* Create a new document */
    xmlDocPtr newDoc = xmlNewDoc(BAD_CAST "1.0");
    if (newDoc == NULL) {
        fprintf(stderr, "Xml.copy: failed to create document\n");
        exit(1);
    }

    /* Deep copy the node into the new document */
    xmlNodePtr copy = xmlDocCopyNode(x->node, newDoc, 1);
    if (copy == NULL) {
        xmlFreeDoc(newDoc);
        fprintf(stderr, "Xml.copy: failed to copy node\n");
        exit(1);
    }

    xmlDocSetRootElement(newDoc, copy);
    return sn_xml_wrap(arena, newDoc, copy, 1);
}
