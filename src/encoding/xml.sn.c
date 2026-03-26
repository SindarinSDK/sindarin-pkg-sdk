/* ==============================================================================
 * sdk/xml.sn.c - XML Implementation for Sindarin SDK using libxml2
 * ==============================================================================
 * Minimal runtime version - no arena, uses calloc/strdup for allocations.
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

/* ============================================================================
 * Xml Type Definition
 * ============================================================================ */

typedef __sn__Xml SnXml;

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

/* Cast helpers for opaque pointer storage.
 * Fields use long long to prevent auto-free by the runtime release function. */
#define XML_DOC(x)  ((xmlDocPtr)(uintptr_t)(x)->doc)
#define XML_NODE(x) ((xmlNodePtr)(uintptr_t)(x)->node)
#define XML_SET_DOC(x, v)  ((x)->doc = (long long)(uintptr_t)(v))
#define XML_SET_NODE(x, v) ((x)->node = (long long)(uintptr_t)(v))

/* Create a new SnXml wrapper for a node within an existing document.
 * Returns a heap-allocated __sn__Xml pointer. */
static __sn__Xml *sn_xml_wrap(xmlDocPtr doc, xmlNodePtr node, int is_root)
{
    __sn__Xml *x = __sn__Xml__new();
    if (x == NULL) {
        fprintf(stderr, "Xml: memory allocation failed\n");
        exit(1);
    }
    XML_SET_DOC(x, doc);
    XML_SET_NODE(x, node);
    x->is_root = is_root;
    x->handle = 0;
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

__sn__Xml *sn_xml_parse(char *text)
{
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
    return sn_xml_wrap(doc, root, 1);
}

__sn__Xml *sn_xml_parse_file(char *path)
{
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
    return sn_xml_wrap(doc, root, 1);
}

/* ============================================================================
 * Creation Functions
 * ============================================================================ */

__sn__Xml *sn_xml_element(char *name)
{
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
    return sn_xml_wrap(doc, node, 1);
}

__sn__Xml *sn_xml_document(char *rootName)
{
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
    return sn_xml_wrap(doc, root, 1);
}

/* ============================================================================
 * Node Info Functions
 * ============================================================================ */

char *sn_xml_name(__sn__Xml *x)
{
    if (x == NULL) return strdup("");
    if (XML_NODE(x) == NULL) return strdup("");
    const char *name = (const char *)(XML_NODE(x))->name;
    return strdup(name ? name : "");
}

char *sn_xml_text(__sn__Xml *x)
{
    if (x == NULL) return strdup("");
    if (XML_NODE(x) == NULL) return strdup("");

    xmlChar *content = xmlNodeGetContent(XML_NODE(x));
    if (content == NULL) return strdup("");

    char *result = strdup((const char *)content);
    xmlFree(content);
    return result;
}

char *sn_xml_type_name(__sn__Xml *x)
{
    if (x == NULL) return strdup("null");
    if (XML_NODE(x) == NULL) return strdup("null");

    switch ((XML_NODE(x))->type) {
        case XML_ELEMENT_NODE:       return strdup("element");
        case XML_TEXT_NODE:          return strdup("text");
        case XML_COMMENT_NODE:       return strdup("comment");
        case XML_DOCUMENT_NODE:      return strdup("document");
        case XML_ATTRIBUTE_NODE:     return strdup("attribute");
        case XML_CDATA_SECTION_NODE: return strdup("cdata");
        case XML_PI_NODE:            return strdup("processing-instruction");
        default:                     return strdup("unknown");
    }
}

bool sn_xml_is_element(__sn__Xml *x)
{
    if (x == NULL) return false;
    if (XML_NODE(x) == NULL) return false;
    return (XML_NODE(x))->type == XML_ELEMENT_NODE;
}

bool sn_xml_is_text(__sn__Xml *x)
{
    if (x == NULL) return false;
    if (XML_NODE(x) == NULL) return false;
    return (XML_NODE(x))->type == XML_TEXT_NODE;
}

bool sn_xml_is_document(__sn__Xml *x)
{
    if (x == NULL) return false;
    if (XML_NODE(x) == NULL) return false;
    return (XML_NODE(x))->type == XML_DOCUMENT_NODE;
}

/* ============================================================================
 * Attribute Functions
 * ============================================================================ */

char *sn_xml_attr(__sn__Xml *x, char *name)
{
    if (x == NULL) return strdup("");
    if (XML_NODE(x) == NULL || name == NULL) return strdup("");
    if ((XML_NODE(x))->type != XML_ELEMENT_NODE) return strdup("");

    xmlChar *value = xmlGetProp(XML_NODE(x), BAD_CAST name);
    if (value == NULL) return strdup("");

    char *result = strdup((const char *)value);
    xmlFree(value);
    return result;
}

bool sn_xml_has_attr(__sn__Xml *x, char *name)
{
    if (x == NULL) return false;
    if (XML_NODE(x) == NULL || name == NULL) return false;
    if ((XML_NODE(x))->type != XML_ELEMENT_NODE) return false;
    return xmlHasProp(XML_NODE(x), BAD_CAST name) != NULL;
}

void sn_xml_set_attr(__sn__Xml *x, char *name, char *value)
{
    if (x == NULL) {
        fprintf(stderr, "Xml.setAttr: invalid arguments\n");
        return;
    }
    if (XML_NODE(x) == NULL || name == NULL || value == NULL) {
        fprintf(stderr, "Xml.setAttr: invalid arguments\n");
        return;
    }
    if ((XML_NODE(x))->type != XML_ELEMENT_NODE) {
        fprintf(stderr, "Xml.setAttr: not an element node\n");
        return;
    }

    xmlSetProp(XML_NODE(x), BAD_CAST name, BAD_CAST value);
}

void sn_xml_remove_attr(__sn__Xml *x, char *name)
{
    if (x == NULL) return;
    if (XML_NODE(x) == NULL || name == NULL) return;
    if ((XML_NODE(x))->type != XML_ELEMENT_NODE) return;

    xmlAttrPtr attr = xmlHasProp(XML_NODE(x), BAD_CAST name);
    if (attr != NULL) {
        xmlRemoveProp(attr);
    }
}

SnArray *sn_xml_attrs(__sn__Xml *x)
{
    SnArray *names = sn_array_new(sizeof(char *), 16);
    names->elem_tag = SN_TAG_STRING;
    names->elem_release = (void (*)(void *))sn_cleanup_str;
    names->elem_copy = sn_copy_str;

    if (x == NULL) return names;
    if (XML_NODE(x) == NULL || (XML_NODE(x))->type != XML_ELEMENT_NODE) {
        return names;
    }

    xmlAttrPtr attr = (XML_NODE(x))->properties;
    while (attr != NULL) {
        if (attr->name != NULL) {
            char *name = strdup((const char *)attr->name);
            sn_array_push(names, &name);
        }
        attr = attr->next;
    }

    return names;
}

/* ============================================================================
 * Child Navigation Functions
 * ============================================================================ */

SnArray *sn_xml_children(__sn__Xml *x)
{
    SnArray *children = sn_array_new(sizeof(__sn__Xml *), 16);
    children->elem_tag = SN_TAG_STRUCT;

    if (x == NULL) return children;
    if (XML_NODE(x) == NULL) return children;

    xmlNodePtr cur = (XML_NODE(x))->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            __sn__Xml *child = sn_xml_wrap(XML_DOC(x), cur, 0);
            sn_array_push(children, &child);
        }
        cur = cur->next;
    }

    return children;
}

__sn__Xml *sn_xml_first_child(__sn__Xml *x)
{
    if (x == NULL) return sn_xml_wrap(NULL, NULL, 0);
    if (XML_NODE(x) == NULL) return sn_xml_wrap(NULL, NULL, 0);

    xmlNodePtr child = first_element_child(XML_NODE(x));
    return sn_xml_wrap(XML_DOC(x), child, 0);
}

__sn__Xml *sn_xml_last_child(__sn__Xml *x)
{
    if (x == NULL) return sn_xml_wrap(NULL, NULL, 0);
    if (XML_NODE(x) == NULL) return sn_xml_wrap(NULL, NULL, 0);

    xmlNodePtr child = last_element_child(XML_NODE(x));
    return sn_xml_wrap(XML_DOC(x), child, 0);
}

long long sn_xml_child_count(__sn__Xml *x)
{
    if (x == NULL) return 0;
    if (XML_NODE(x) == NULL) return 0;

    long long count = 0;
    xmlNodePtr cur = (XML_NODE(x))->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) count++;
        cur = cur->next;
    }
    return count;
}

bool sn_xml_has_children(__sn__Xml *x)
{
    if (x == NULL) return false;
    if (XML_NODE(x) == NULL) return false;
    return first_element_child(XML_NODE(x)) != NULL;
}

/* ============================================================================
 * Sibling/Parent Navigation Functions
 * ============================================================================ */

__sn__Xml *sn_xml_parent(__sn__Xml *x)
{
    if (x == NULL) return sn_xml_wrap(NULL, NULL, 0);
    if (XML_NODE(x) == NULL || (XML_NODE(x))->parent == NULL) {
        return sn_xml_wrap(XML_DOC(x), NULL, 0);
    }

    xmlNodePtr parent = (XML_NODE(x))->parent;
    /* Don't navigate above the document node */
    if (parent->type == XML_DOCUMENT_NODE) {
        return sn_xml_wrap(XML_DOC(x), NULL, 0);
    }

    return sn_xml_wrap(XML_DOC(x), parent, 0);
}

__sn__Xml *sn_xml_next(__sn__Xml *x)
{
    if (x == NULL) return sn_xml_wrap(NULL, NULL, 0);
    if (XML_NODE(x) == NULL) return sn_xml_wrap(XML_DOC(x), NULL, 0);

    xmlNodePtr next = next_element_sibling(XML_NODE(x));
    return sn_xml_wrap(XML_DOC(x), next, 0);
}

__sn__Xml *sn_xml_prev(__sn__Xml *x)
{
    if (x == NULL) return sn_xml_wrap(NULL, NULL, 0);
    if (XML_NODE(x) == NULL) return sn_xml_wrap(XML_DOC(x), NULL, 0);

    xmlNodePtr prev = prev_element_sibling(XML_NODE(x));
    return sn_xml_wrap(XML_DOC(x), prev, 0);
}

/* ============================================================================
 * XPath Functions
 * ============================================================================ */

__sn__Xml *sn_xml_find(__sn__Xml *x, char *xpath)
{
    if (x == NULL) return sn_xml_wrap(NULL, NULL, 0);
    if (XML_DOC(x) == NULL || xpath == NULL) {
        return sn_xml_wrap(XML_DOC(x), NULL, 0);
    }

    sn_xml_init();

    xmlXPathContextPtr ctx = xmlXPathNewContext(XML_DOC(x));
    if (ctx == NULL) {
        return sn_xml_wrap(XML_DOC(x), NULL, 0);
    }

    /* Set context node if we have one */
    if (XML_NODE(x) != NULL) {
        ctx->node = XML_NODE(x);
    }

    xmlXPathObjectPtr result = xmlXPathEvalExpression(BAD_CAST xpath, ctx);
    if (result == NULL) {
        xmlXPathFreeContext(ctx);
        return sn_xml_wrap(XML_DOC(x), NULL, 0);
    }

    __sn__Xml *found = NULL;
    if (result->nodesetval != NULL && result->nodesetval->nodeNr > 0) {
        xmlNodePtr node = result->nodesetval->nodeTab[0];
        found = sn_xml_wrap(XML_DOC(x), node, 0);
    } else {
        found = sn_xml_wrap(XML_DOC(x), NULL, 0);
    }

    xmlXPathFreeObject(result);
    xmlXPathFreeContext(ctx);
    return found;
}

SnArray *sn_xml_find_all(__sn__Xml *x, char *xpath)
{
    SnArray *nodes = sn_array_new(sizeof(__sn__Xml *), 16);
    nodes->elem_tag = SN_TAG_STRUCT;

    if (x == NULL) return nodes;
    if (XML_DOC(x) == NULL || xpath == NULL) return nodes;

    sn_xml_init();

    xmlXPathContextPtr ctx = xmlXPathNewContext(XML_DOC(x));
    if (ctx == NULL) return nodes;

    /* Set context node if we have one */
    if (XML_NODE(x) != NULL) {
        ctx->node = XML_NODE(x);
    }

    xmlXPathObjectPtr result = xmlXPathEvalExpression(BAD_CAST xpath, ctx);
    if (result == NULL) {
        xmlXPathFreeContext(ctx);
        return nodes;
    }

    if (result->nodesetval != NULL) {
        for (int i = 0; i < result->nodesetval->nodeNr; i++) {
            xmlNodePtr node = result->nodesetval->nodeTab[i];
            __sn__Xml *wrapped = sn_xml_wrap(XML_DOC(x), node, 0);
            sn_array_push(nodes, &wrapped);
        }
    }

    xmlXPathFreeObject(result);
    xmlXPathFreeContext(ctx);
    return nodes;
}

/* ============================================================================
 * Mutation Functions
 * ============================================================================ */

void sn_xml_add_child(__sn__Xml *x, __sn__Xml *child)
{
    if (x == NULL || child == NULL) {
        fprintf(stderr, "Xml.addChild: invalid arguments\n");
        return;
    }
    if (XML_NODE(x) == NULL || XML_NODE(child) == NULL) {
        fprintf(stderr, "Xml.addChild: invalid arguments\n");
        return;
    }
    if ((XML_NODE(x))->type != XML_ELEMENT_NODE) {
        fprintf(stderr, "Xml.addChild: parent is not an element node\n");
        return;
    }

    /* If the child belongs to a different document, copy it */
    if (XML_DOC(child) != XML_DOC(x)) {
        xmlNodePtr copy = xmlDocCopyNode(XML_NODE(child), XML_DOC(x), 1);
        if (copy == NULL) {
            fprintf(stderr, "Xml.addChild: failed to copy node\n");
            return;
        }
        xmlAddChild(XML_NODE(x), copy);
    } else {
        /* Unlink from current parent if needed */
        xmlUnlinkNode(XML_NODE(child));
        xmlAddChild(XML_NODE(x), XML_NODE(child));
    }
}

void sn_xml_set_text(__sn__Xml *x, char *content)
{
    if (x == NULL) {
        fprintf(stderr, "Xml.setText: invalid arguments\n");
        return;
    }
    if (XML_NODE(x) == NULL || content == NULL) {
        fprintf(stderr, "Xml.setText: invalid arguments\n");
        return;
    }

    xmlNodeSetContent(XML_NODE(x), BAD_CAST content);
}

void sn_xml_set_name(__sn__Xml *x, char *name)
{
    if (x == NULL) {
        fprintf(stderr, "Xml.setName: invalid arguments\n");
        return;
    }
    if (XML_NODE(x) == NULL || name == NULL) {
        fprintf(stderr, "Xml.setName: invalid arguments\n");
        return;
    }
    if ((XML_NODE(x))->type != XML_ELEMENT_NODE) {
        fprintf(stderr, "Xml.setName: not an element node\n");
        return;
    }

    xmlNodeSetName(XML_NODE(x), BAD_CAST name);
}

void sn_xml_remove(__sn__Xml *x)
{
    if (x == NULL) return;
    if (XML_NODE(x) == NULL) return;

    xmlUnlinkNode(XML_NODE(x));
    xmlFreeNode(XML_NODE(x));
    XML_SET_NODE(x, NULL);
}

/* ============================================================================
 * Serialization Functions
 * ============================================================================ */

char *sn_xml_to_string(__sn__Xml *x)
{
    if (x == NULL) return strdup("");
    if (XML_NODE(x) == NULL) return strdup("");

    xmlBufferPtr buf = xmlBufferCreate();
    if (buf == NULL) return strdup("");

    int size = xmlNodeDump(buf, XML_DOC(x), XML_NODE(x), 0, 0);
    if (size < 0) {
        xmlBufferFree(buf);
        return strdup("");
    }

    const char *content = (const char *)xmlBufferContent(buf);
    char *result = strdup(content ? content : "");
    xmlBufferFree(buf);
    return result;
}

char *sn_xml_to_pretty_string(__sn__Xml *x)
{
    if (x == NULL) return strdup("");
    if (XML_NODE(x) == NULL) return strdup("");

    xmlBufferPtr buf = xmlBufferCreate();
    if (buf == NULL) return strdup("");

    int size = xmlNodeDump(buf, XML_DOC(x), XML_NODE(x), 0, 1);
    if (size < 0) {
        xmlBufferFree(buf);
        return strdup("");
    }

    const char *content = (const char *)xmlBufferContent(buf);
    char *result = strdup(content ? content : "");
    xmlBufferFree(buf);
    return result;
}

void sn_xml_write_file(__sn__Xml *x, char *path)
{
    if (x == NULL) {
        fprintf(stderr, "Xml.writeFile: invalid arguments\n");
        return;
    }
    if (XML_DOC(x) == NULL || path == NULL) {
        fprintf(stderr, "Xml.writeFile: invalid arguments\n");
        return;
    }

    int ret = xmlSaveFormatFileEnc(path, XML_DOC(x), "UTF-8", 0);
    if (ret < 0) {
        fprintf(stderr, "Xml.writeFile: failed to write file: %s\n", path);
    }
}

void sn_xml_write_file_pretty(__sn__Xml *x, char *path)
{
    if (x == NULL) {
        fprintf(stderr, "Xml.writeFilePretty: invalid arguments\n");
        return;
    }
    if (XML_DOC(x) == NULL || path == NULL) {
        fprintf(stderr, "Xml.writeFilePretty: invalid arguments\n");
        return;
    }

    int ret = xmlSaveFormatFileEnc(path, XML_DOC(x), "UTF-8", 1);
    if (ret < 0) {
        fprintf(stderr, "Xml.writeFilePretty: failed to write file: %s\n", path);
    }
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

__sn__Xml *sn_xml_copy(__sn__Xml *x)
{
    if (x == NULL) return sn_xml_wrap(NULL, NULL, 0);
    if (XML_NODE(x) == NULL) return sn_xml_wrap(NULL, NULL, 0);

    sn_xml_init();

    /* Create a new document */
    xmlDocPtr newDoc = xmlNewDoc(BAD_CAST "1.0");
    if (newDoc == NULL) {
        fprintf(stderr, "Xml.copy: failed to create document\n");
        exit(1);
    }

    /* Deep copy the node into the new document */
    xmlNodePtr copy = xmlDocCopyNode(XML_NODE(x), newDoc, 1);
    if (copy == NULL) {
        xmlFreeDoc(newDoc);
        fprintf(stderr, "Xml.copy: failed to copy node\n");
        exit(1);
    }

    xmlDocSetRootElement(newDoc, copy);
    return sn_xml_wrap(newDoc, copy, 1);
}

/* ============================================================================
 * Dispose Function
 * ============================================================================
 * Releases the xmlDoc immediately. Only frees internal resources --
 * the struct itself is freed by sn_auto_Xml cleanup.
 * ============================================================================ */

void sn_xml_dispose(__sn__Xml *x)
{
    if (x == NULL) return;
    if (XML_DOC(x) != NULL && x->is_root) {
        xmlFreeDoc(XML_DOC(x));
    }
    XML_SET_DOC(x, NULL);
    XML_SET_NODE(x, NULL);
}
