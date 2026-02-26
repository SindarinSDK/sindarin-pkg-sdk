/* ==============================================================================
 * sdk/yaml.sn.c - YAML Implementation for Sindarin SDK using libyaml
 * ==============================================================================
 * This file provides the C implementation for the Yaml type.
 * It uses a custom tree structure for full mutation support, with libyaml
 * handling parsing and serialization.
 * ============================================================================== */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#include <yaml.h>

/* Include runtime arena for proper memory management */
#include "runtime/array/runtime_array_v2.h"

/* ============================================================================
 * Internal Tree Data Structures
 * ============================================================================ */

typedef enum {
    SN_YAML_SCALAR = 0,
    SN_YAML_SEQUENCE = 1,
    SN_YAML_MAPPING = 2
} SnYamlType;

typedef struct SnYamlNode SnYamlNode;

typedef struct SnYamlPair {
    char *key;
    SnYamlNode *value;
} SnYamlPair;

struct SnYamlNode {
    SnYamlType type;
    /* Scalar */
    char *scalar_value;
    /* Sequence */
    SnYamlNode **seq_items;
    int seq_count;
    int seq_capacity;
    /* Mapping */
    SnYamlPair *map_pairs;
    int map_count;
    int map_capacity;
};

/* ============================================================================
 * Yaml Wrapper Type (matches SnYaml in yaml.sn)
 * ============================================================================ */

typedef struct SnYaml {
    SnYamlNode *root;       /* Root node of the tree (for ownership) */
    SnYamlNode *node;       /* Current node */
    int32_t is_root;        /* Whether this wrapper owns the tree */
    RtHandleV2 *handle;     /* Self-reference for dispose */
} SnYaml;

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

static char *sn_yaml_strdup(const char *s)
{
    if (s == NULL) return NULL;
    size_t len = strlen(s);
    char *dup = (char *)malloc(len + 1);
    if (dup == NULL) {
        fprintf(stderr, "Yaml: memory allocation failed\n");
        exit(1);
    }
    memcpy(dup, s, len + 1);
    return dup;
}

static SnYamlNode *sn_yaml_node_new(SnYamlType type)
{
    SnYamlNode *node = (SnYamlNode *)calloc(1, sizeof(SnYamlNode));
    if (node == NULL) {
        fprintf(stderr, "Yaml: memory allocation failed\n");
        exit(1);
    }
    node->type = type;
    return node;
}

static SnYamlNode *sn_yaml_node_new_scalar(const char *value)
{
    SnYamlNode *node = sn_yaml_node_new(SN_YAML_SCALAR);
    node->scalar_value = sn_yaml_strdup(value ? value : "");
    return node;
}

static SnYamlNode *sn_yaml_node_new_sequence(void)
{
    SnYamlNode *node = sn_yaml_node_new(SN_YAML_SEQUENCE);
    node->seq_capacity = 8;
    node->seq_items = (SnYamlNode **)calloc(node->seq_capacity, sizeof(SnYamlNode *));
    if (node->seq_items == NULL) {
        fprintf(stderr, "Yaml: memory allocation failed\n");
        exit(1);
    }
    return node;
}

static SnYamlNode *sn_yaml_node_new_mapping(void)
{
    SnYamlNode *node = sn_yaml_node_new(SN_YAML_MAPPING);
    node->map_capacity = 8;
    node->map_pairs = (SnYamlPair *)calloc(node->map_capacity, sizeof(SnYamlPair));
    if (node->map_pairs == NULL) {
        fprintf(stderr, "Yaml: memory allocation failed\n");
        exit(1);
    }
    return node;
}

static void sn_yaml_seq_append(SnYamlNode *seq, SnYamlNode *item)
{
    if (seq->seq_count >= seq->seq_capacity) {
        seq->seq_capacity *= 2;
        seq->seq_items = (SnYamlNode **)realloc(seq->seq_items,
            seq->seq_capacity * sizeof(SnYamlNode *));
        if (seq->seq_items == NULL) {
            fprintf(stderr, "Yaml: memory allocation failed\n");
            exit(1);
        }
    }
    seq->seq_items[seq->seq_count++] = item;
}

static void sn_yaml_map_set(SnYamlNode *map, const char *key, SnYamlNode *value)
{
    /* Check if key already exists */
    for (int i = 0; i < map->map_count; i++) {
        if (map->map_pairs[i].key && strcmp(map->map_pairs[i].key, key) == 0) {
            map->map_pairs[i].value = value;
            return;
        }
    }
    /* Append new pair */
    if (map->map_count >= map->map_capacity) {
        map->map_capacity *= 2;
        map->map_pairs = (SnYamlPair *)realloc(map->map_pairs,
            map->map_capacity * sizeof(SnYamlPair));
        if (map->map_pairs == NULL) {
            fprintf(stderr, "Yaml: memory allocation failed\n");
            exit(1);
        }
    }
    map->map_pairs[map->map_count].key = sn_yaml_strdup(key);
    map->map_pairs[map->map_count].value = value;
    map->map_count++;
}

/* Recursively free a YAML node tree */
static void sn_yaml_node_free(SnYamlNode *node)
{
    if (node == NULL) return;

    switch (node->type) {
        case SN_YAML_SCALAR:
            free(node->scalar_value);
            break;
        case SN_YAML_SEQUENCE:
            for (int i = 0; i < node->seq_count; i++) {
                sn_yaml_node_free(node->seq_items[i]);
            }
            free(node->seq_items);
            break;
        case SN_YAML_MAPPING:
            for (int i = 0; i < node->map_count; i++) {
                free(node->map_pairs[i].key);
                sn_yaml_node_free(node->map_pairs[i].value);
            }
            free(node->map_pairs);
            break;
    }
    free(node);
}

/* ============================================================================
 * Cleanup Callback for YAML node trees
 * ============================================================================
 * When a Yaml with is_root=1 is allocated, we register a cleanup callback
 * that frees the malloc'd node tree when the arena is destroyed (e.g., when
 * a thread terminates). This prevents memory leaks from accumulating.
 * ============================================================================ */

static void sn_yaml_tree_cleanup(RtHandleV2 *data)
{
    SnYaml *y = (SnYaml *)data->ptr;
    if (y != NULL && y->is_root && y->root != NULL) {
        sn_yaml_node_free(y->root);
        y->root = NULL;
        y->node = NULL;
    }
}

/* Create a new SnYaml wrapper for a node within an existing tree.
 * If is_root is true, registers a cleanup callback to free the node tree
 * when the arena is destroyed (e.g., when the thread terminates). */
static RtHandleV2 *sn_yaml_wrap(RtArenaV2 *arena, SnYamlNode *root, SnYamlNode *node, int is_root)
{
    RtHandleV2 *_h = rt_arena_v2_alloc(arena, sizeof(SnYaml));
    SnYaml *y = (SnYaml *)_h->ptr;
    y->root = root;
    y->node = node;
    y->is_root = is_root;
    y->handle = _h;

    /* Register cleanup callback to free the node tree when arena is destroyed.
     * This prevents memory leaks when Yaml objects go out of scope.
     * Priority 100 ensures Yaml cleanup happens after user cleanup callbacks. */
    if (is_root && root != NULL) {
        rt_arena_v2_on_cleanup(arena, _h, sn_yaml_tree_cleanup, 100);
    }

    return _h;
}

/* ============================================================================
 * Dispose Function
 * ============================================================================
 * Releases the YAML node tree and arena handle immediately. This allows
 * deterministic cleanup of YAML values in long-lived arenas.
 *
 * Two-tier cleanup:
 * 1. Explicit: User calls .dispose() - node tree freed, handle reclaimable
 * 2. Implicit: Arena destruction - cleanup callback fires (safety net)
 *
 * If dispose() is called first, it sets root=NULL so the arena cleanup
 * callback becomes a no-op (no double-free).
 * ============================================================================ */

void sn_yaml_dispose(SnYaml *y)
{
    if (y == NULL) return;
    if (y->is_root && y->root != NULL) {
        sn_yaml_node_free(y->root);
        y->root = NULL;
        y->node = NULL;
    }
    if (y->handle != NULL) {
        RtHandleV2 *h = y->handle;
        y->handle = NULL;
        rt_arena_v2_remove_cleanup(h->arena, h);
        rt_arena_v2_free(h);
    }
}

/* ============================================================================
 * Parsing: Build tree from libyaml document API
 * ============================================================================ */

static SnYamlNode *sn_yaml_build_tree(yaml_document_t *doc, yaml_node_t *ynode)
{
    if (ynode == NULL) return sn_yaml_node_new_scalar("");

    switch (ynode->type) {
        case YAML_SCALAR_NODE: {
            const char *val = (const char *)ynode->data.scalar.value;
            return sn_yaml_node_new_scalar(val ? val : "");
        }
        case YAML_SEQUENCE_NODE: {
            SnYamlNode *seq = sn_yaml_node_new_sequence();
            yaml_node_item_t *item;
            for (item = ynode->data.sequence.items.start;
                 item < ynode->data.sequence.items.top; item++) {
                yaml_node_t *child = yaml_document_get_node(doc, *item);
                SnYamlNode *child_node = sn_yaml_build_tree(doc, child);
                sn_yaml_seq_append(seq, child_node);
            }
            return seq;
        }
        case YAML_MAPPING_NODE: {
            SnYamlNode *map = sn_yaml_node_new_mapping();
            yaml_node_pair_t *pair;
            for (pair = ynode->data.mapping.pairs.start;
                 pair < ynode->data.mapping.pairs.top; pair++) {
                yaml_node_t *key_node = yaml_document_get_node(doc, pair->key);
                yaml_node_t *val_node = yaml_document_get_node(doc, pair->value);
                const char *key_str = "";
                if (key_node && key_node->type == YAML_SCALAR_NODE) {
                    key_str = (const char *)key_node->data.scalar.value;
                }
                SnYamlNode *val = sn_yaml_build_tree(doc, val_node);
                sn_yaml_map_set(map, key_str ? key_str : "", val);
            }
            return map;
        }
        default:
            return sn_yaml_node_new_scalar("");
    }
}

/* ============================================================================
 * Parsing Functions
 * ============================================================================ */

RtHandleV2 *sn_yaml_parse(RtArenaV2 *arena, const char *text)
{
    if (arena == NULL) {
        fprintf(stderr, "Yaml.parse: arena is NULL\n");
        exit(1);
    }
    if (text == NULL) {
        fprintf(stderr, "Yaml.parse: text is NULL\n");
        exit(1);
    }

    yaml_parser_t parser;
    yaml_document_t document;

    if (!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "Yaml.parse: failed to initialize parser\n");
        exit(1);
    }

    yaml_parser_set_input_string(&parser, (const unsigned char *)text, strlen(text));

    if (!yaml_parser_load(&parser, &document)) {
        fprintf(stderr, "Yaml.parse: %s at line %zu\n",
                parser.problem ? parser.problem : "parse error",
                parser.problem_mark.line + 1);
        yaml_parser_delete(&parser);
        exit(1);
    }

    yaml_node_t *root_node = yaml_document_get_root_node(&document);
    SnYamlNode *tree = NULL;
    if (root_node) {
        tree = sn_yaml_build_tree(&document, root_node);
    } else {
        tree = sn_yaml_node_new_scalar("");
    }

    yaml_document_delete(&document);
    yaml_parser_delete(&parser);

    return sn_yaml_wrap(arena, tree, tree, 1);
}

RtHandleV2 *sn_yaml_parse_file(RtArenaV2 *arena, const char *path)
{
    if (arena == NULL) {
        fprintf(stderr, "Yaml.parseFile: arena is NULL\n");
        exit(1);
    }
    if (path == NULL) {
        fprintf(stderr, "Yaml.parseFile: path is NULL\n");
        exit(1);
    }

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        fprintf(stderr, "Yaml.parseFile: cannot open file '%s': %s\n", path, strerror(errno));
        exit(1);
    }

    yaml_parser_t parser;
    yaml_document_t document;

    if (!yaml_parser_initialize(&parser)) {
        fclose(f);
        fprintf(stderr, "Yaml.parseFile: failed to initialize parser\n");
        exit(1);
    }

    yaml_parser_set_input_file(&parser, f);

    if (!yaml_parser_load(&parser, &document)) {
        fprintf(stderr, "Yaml.parseFile: %s at line %zu (file: %s)\n",
                parser.problem ? parser.problem : "parse error",
                parser.problem_mark.line + 1, path);
        yaml_parser_delete(&parser);
        fclose(f);
        exit(1);
    }

    yaml_node_t *root_node = yaml_document_get_root_node(&document);
    SnYamlNode *tree = NULL;
    if (root_node) {
        tree = sn_yaml_build_tree(&document, root_node);
    } else {
        tree = sn_yaml_node_new_scalar("");
    }

    yaml_document_delete(&document);
    yaml_parser_delete(&parser);
    fclose(f);

    return sn_yaml_wrap(arena, tree, tree, 1);
}

/* ============================================================================
 * Creation Functions
 * ============================================================================ */

RtHandleV2 *sn_yaml_scalar(RtArenaV2 *arena, const char *value)
{
    if (arena == NULL) {
        fprintf(stderr, "Yaml.scalar: arena is NULL\n");
        exit(1);
    }
    SnYamlNode *node = sn_yaml_node_new_scalar(value ? value : "");
    return sn_yaml_wrap(arena, node, node, 1);
}

RtHandleV2 *sn_yaml_sequence(RtArenaV2 *arena)
{
    if (arena == NULL) {
        fprintf(stderr, "Yaml.sequence: arena is NULL\n");
        exit(1);
    }
    SnYamlNode *node = sn_yaml_node_new_sequence();
    return sn_yaml_wrap(arena, node, node, 1);
}

RtHandleV2 *sn_yaml_mapping(RtArenaV2 *arena)
{
    if (arena == NULL) {
        fprintf(stderr, "Yaml.mapping: arena is NULL\n");
        exit(1);
    }
    SnYamlNode *node = sn_yaml_node_new_mapping();
    return sn_yaml_wrap(arena, node, node, 1);
}

/* ============================================================================
 * Type Checking Functions
 * ============================================================================ */

bool sn_yaml_is_scalar(SnYaml *y)
{
    if (y == NULL || y->node == NULL) return false;
    return y->node->type == SN_YAML_SCALAR;
}

bool sn_yaml_is_sequence(SnYaml *y)
{
    if (y == NULL || y->node == NULL) return false;
    return y->node->type == SN_YAML_SEQUENCE;
}

bool sn_yaml_is_mapping(SnYaml *y)
{
    if (y == NULL || y->node == NULL) return false;
    return y->node->type == SN_YAML_MAPPING;
}

/* ============================================================================
 * Value Access Functions (Scalars)
 * ============================================================================ */

RtHandleV2 *sn_yaml_value(RtArenaV2 *arena, SnYaml *y)
{
    if (y == NULL || y->node == NULL || y->node->type != SN_YAML_SCALAR) {
        return rt_arena_v2_strdup(arena, "");
    }
    return rt_arena_v2_strdup(arena, y->node->scalar_value ? y->node->scalar_value : "");
}

int64_t sn_yaml_as_int(SnYaml *y)
{
    if (y == NULL || y->node == NULL || y->node->type != SN_YAML_SCALAR) return 0;
    if (y->node->scalar_value == NULL) return 0;
    char *end;
    long long val = strtoll(y->node->scalar_value, &end, 10);
    if (end == y->node->scalar_value) return 0;
    return (int64_t)val;
}

int64_t sn_yaml_as_long(SnYaml *y)
{
    if (y == NULL || y->node == NULL || y->node->type != SN_YAML_SCALAR) return 0;
    if (y->node->scalar_value == NULL) return 0;
    char *end;
    long long val = strtoll(y->node->scalar_value, &end, 10);
    if (end == y->node->scalar_value) return 0;
    return (int64_t)val;
}

double sn_yaml_as_float(SnYaml *y)
{
    if (y == NULL || y->node == NULL || y->node->type != SN_YAML_SCALAR) return 0.0;
    if (y->node->scalar_value == NULL) return 0.0;
    char *end;
    double val = strtod(y->node->scalar_value, &end);
    if (end == y->node->scalar_value) return 0.0;
    return val;
}

static bool sn_yaml_str_icase_eq(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

bool sn_yaml_as_bool(SnYaml *y)
{
    if (y == NULL || y->node == NULL || y->node->type != SN_YAML_SCALAR) return false;
    if (y->node->scalar_value == NULL) return false;
    const char *s = y->node->scalar_value;
    if (sn_yaml_str_icase_eq(s, "true")) return true;
    if (sn_yaml_str_icase_eq(s, "yes")) return true;
    if (sn_yaml_str_icase_eq(s, "on")) return true;
    if (sn_yaml_str_icase_eq(s, "1")) return true;
    return false;
}

/* ============================================================================
 * Mapping Access Functions
 * ============================================================================ */

RtHandleV2 *sn_yaml_get(RtArenaV2 *arena, SnYaml *y, const char *key)
{
    if (y == NULL || y->node == NULL || key == NULL) {
        return sn_yaml_wrap(arena, y ? y->root : NULL, NULL, 0);
    }
    if (y->node->type != SN_YAML_MAPPING) {
        return sn_yaml_wrap(arena, y->root, NULL, 0);
    }

    for (int i = 0; i < y->node->map_count; i++) {
        if (y->node->map_pairs[i].key && strcmp(y->node->map_pairs[i].key, key) == 0) {
            return sn_yaml_wrap(arena, y->root, y->node->map_pairs[i].value, 0);
        }
    }
    return sn_yaml_wrap(arena, y->root, NULL, 0);
}

bool sn_yaml_has(SnYaml *y, const char *key)
{
    if (y == NULL || y->node == NULL || key == NULL) return false;
    if (y->node->type != SN_YAML_MAPPING) return false;

    for (int i = 0; i < y->node->map_count; i++) {
        if (y->node->map_pairs[i].key && strcmp(y->node->map_pairs[i].key, key) == 0) {
            return true;
        }
    }
    return false;
}

RtHandleV2 *sn_yaml_keys(RtArenaV2 *arena, SnYaml *y)
{
    if (y == NULL || y->node == NULL || y->node->type != SN_YAML_MAPPING) {
        return rt_array_create_string_v2(arena, 0, NULL);
    }

    RtHandleV2 *keys = rt_array_create_string_v2(arena, 0, NULL);
    for (int i = 0; i < y->node->map_count; i++) {
        RtHandleV2 *dup = rt_arena_v2_strdup(arena, y->node->map_pairs[i].key ? y->node->map_pairs[i].key : "");
        keys = rt_array_push_string_v2(arena, keys, dup);
    }
    return keys;
}

/* ============================================================================
 * Sequence Access Functions
 * ============================================================================ */

RtHandleV2 *sn_yaml_get_at(RtArenaV2 *arena, SnYaml *y, int64_t index)
{
    if (y == NULL || y->node == NULL) {
        return sn_yaml_wrap(arena, y ? y->root : NULL, NULL, 0);
    }
    if (y->node->type != SN_YAML_SEQUENCE) {
        return sn_yaml_wrap(arena, y->root, NULL, 0);
    }
    if (index < 0 || index >= y->node->seq_count) {
        return sn_yaml_wrap(arena, y->root, NULL, 0);
    }
    return sn_yaml_wrap(arena, y->root, y->node->seq_items[index], 0);
}

RtHandleV2 *sn_yaml_first(RtArenaV2 *arena, SnYaml *y)
{
    if (y == NULL || y->node == NULL || y->node->type != SN_YAML_SEQUENCE || y->node->seq_count == 0) {
        return sn_yaml_wrap(arena, y ? y->root : NULL, NULL, 0);
    }
    return sn_yaml_wrap(arena, y->root, y->node->seq_items[0], 0);
}

RtHandleV2 *sn_yaml_last(RtArenaV2 *arena, SnYaml *y)
{
    if (y == NULL || y->node == NULL || y->node->type != SN_YAML_SEQUENCE || y->node->seq_count == 0) {
        return sn_yaml_wrap(arena, y ? y->root : NULL, NULL, 0);
    }
    return sn_yaml_wrap(arena, y->root, y->node->seq_items[y->node->seq_count - 1], 0);
}

/* ============================================================================
 * Size Functions
 * ============================================================================ */

int64_t sn_yaml_length(SnYaml *y)
{
    if (y == NULL || y->node == NULL) return 0;
    if (y->node->type == SN_YAML_SEQUENCE) return (int64_t)y->node->seq_count;
    if (y->node->type == SN_YAML_MAPPING) return (int64_t)y->node->map_count;
    return 0;
}

/* ============================================================================
 * Mutation Functions (Mapping)
 * ============================================================================ */

void sn_yaml_set(SnYaml *y, const char *key, SnYaml *value)
{
    if (y == NULL || y->node == NULL || key == NULL || value == NULL) {
        fprintf(stderr, "Yaml.set: invalid arguments\n");
        return;
    }
    if (y->node->type != SN_YAML_MAPPING) {
        fprintf(stderr, "Yaml.set: not a mapping\n");
        return;
    }
    sn_yaml_map_set(y->node, key, value->node);
    /* Transfer ownership: the node is now part of y's tree */
    value->is_root = 0;
    value->root = NULL;
}

void sn_yaml_remove(SnYaml *y, const char *key)
{
    if (y == NULL || y->node == NULL || key == NULL) return;
    if (y->node->type != SN_YAML_MAPPING) return;

    for (int i = 0; i < y->node->map_count; i++) {
        if (y->node->map_pairs[i].key && strcmp(y->node->map_pairs[i].key, key) == 0) {
            free(y->node->map_pairs[i].key);
            /* Shift remaining pairs */
            for (int j = i; j < y->node->map_count - 1; j++) {
                y->node->map_pairs[j] = y->node->map_pairs[j + 1];
            }
            y->node->map_count--;
            return;
        }
    }
}

/* ============================================================================
 * Mutation Functions (Sequence)
 * ============================================================================ */

void sn_yaml_append(SnYaml *y, SnYaml *value)
{
    if (y == NULL || y->node == NULL || value == NULL) {
        fprintf(stderr, "Yaml.append: invalid arguments\n");
        return;
    }
    if (y->node->type != SN_YAML_SEQUENCE) {
        fprintf(stderr, "Yaml.append: not a sequence\n");
        return;
    }
    sn_yaml_seq_append(y->node, value->node);
    /* Transfer ownership: the node is now part of y's tree */
    value->is_root = 0;
    value->root = NULL;
}

void sn_yaml_prepend(SnYaml *y, SnYaml *value)
{
    if (y == NULL || y->node == NULL || value == NULL) {
        fprintf(stderr, "Yaml.prepend: invalid arguments\n");
        return;
    }
    if (y->node->type != SN_YAML_SEQUENCE) {
        fprintf(stderr, "Yaml.prepend: not a sequence\n");
        return;
    }

    /* Ensure capacity */
    if (y->node->seq_count >= y->node->seq_capacity) {
        y->node->seq_capacity *= 2;
        y->node->seq_items = (SnYamlNode **)realloc(y->node->seq_items,
            y->node->seq_capacity * sizeof(SnYamlNode *));
        if (y->node->seq_items == NULL) {
            fprintf(stderr, "Yaml: memory allocation failed\n");
            exit(1);
        }
    }
    /* Shift all items right */
    for (int i = y->node->seq_count; i > 0; i--) {
        y->node->seq_items[i] = y->node->seq_items[i - 1];
    }
    y->node->seq_items[0] = value->node;
    y->node->seq_count++;
    /* Transfer ownership: the node is now part of y's tree */
    value->is_root = 0;
    value->root = NULL;
}

void sn_yaml_remove_at(SnYaml *y, int64_t index)
{
    if (y == NULL || y->node == NULL) return;
    if (y->node->type != SN_YAML_SEQUENCE) return;
    if (index < 0 || index >= y->node->seq_count) return;

    /* Shift remaining items */
    for (int i = (int)index; i < y->node->seq_count - 1; i++) {
        y->node->seq_items[i] = y->node->seq_items[i + 1];
    }
    y->node->seq_count--;
}

/* ============================================================================
 * Serialization: Walk tree and emit via libyaml emitter
 * ============================================================================ */

typedef struct {
    unsigned char *buffer;
    size_t size;
    size_t capacity;
} SnYamlBuffer;

static int sn_yaml_write_handler(void *data, unsigned char *buffer, size_t size)
{
    SnYamlBuffer *buf = (SnYamlBuffer *)data;
    while (buf->size + size > buf->capacity) {
        buf->capacity = buf->capacity ? buf->capacity * 2 : 1024;
        buf->buffer = (unsigned char *)realloc(buf->buffer, buf->capacity);
        if (buf->buffer == NULL) {
            return 0;
        }
    }
    memcpy(buf->buffer + buf->size, buffer, size);
    buf->size += size;
    return 1;
}

static int sn_yaml_emit_node(yaml_emitter_t *emitter, SnYamlNode *node)
{
    yaml_event_t event;

    if (node == NULL) {
        yaml_scalar_event_initialize(&event, NULL, NULL,
            (yaml_char_t *)"", 0, 1, 1, YAML_ANY_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return 0;
        return 1;
    }

    switch (node->type) {
        case SN_YAML_SCALAR: {
            const char *val = node->scalar_value ? node->scalar_value : "";
            yaml_scalar_event_initialize(&event, NULL, NULL,
                (yaml_char_t *)val, (int)strlen(val), 1, 1, YAML_ANY_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return 0;
            break;
        }
        case SN_YAML_SEQUENCE: {
            yaml_sequence_start_event_initialize(&event, NULL, NULL, 1, YAML_ANY_SEQUENCE_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return 0;
            for (int i = 0; i < node->seq_count; i++) {
                if (!sn_yaml_emit_node(emitter, node->seq_items[i])) return 0;
            }
            yaml_sequence_end_event_initialize(&event);
            if (!yaml_emitter_emit(emitter, &event)) return 0;
            break;
        }
        case SN_YAML_MAPPING: {
            yaml_mapping_start_event_initialize(&event, NULL, NULL, 1, YAML_ANY_MAPPING_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return 0;
            for (int i = 0; i < node->map_count; i++) {
                const char *key = node->map_pairs[i].key ? node->map_pairs[i].key : "";
                yaml_scalar_event_initialize(&event, NULL, NULL,
                    (yaml_char_t *)key, (int)strlen(key), 1, 1, YAML_ANY_SCALAR_STYLE);
                if (!yaml_emitter_emit(emitter, &event)) return 0;
                if (!sn_yaml_emit_node(emitter, node->map_pairs[i].value)) return 0;
            }
            yaml_mapping_end_event_initialize(&event);
            if (!yaml_emitter_emit(emitter, &event)) return 0;
            break;
        }
    }
    return 1;
}

static char *sn_yaml_serialize(SnYamlNode *node, size_t *out_len)
{
    yaml_emitter_t emitter;
    yaml_event_t event;
    SnYamlBuffer buf = {NULL, 0, 0};

    if (!yaml_emitter_initialize(&emitter)) {
        return sn_yaml_strdup("");
    }

    yaml_emitter_set_output(&emitter, sn_yaml_write_handler, &buf);
    yaml_emitter_set_unicode(&emitter, 1);

    /* Stream start */
    yaml_stream_start_event_initialize(&event, YAML_UTF8_ENCODING);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    /* Document start */
    yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 1);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    /* Emit tree */
    if (!sn_yaml_emit_node(&emitter, node)) goto error;

    /* Document end */
    yaml_document_end_event_initialize(&event, 1);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    /* Stream end */
    yaml_stream_end_event_initialize(&event);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_emitter_delete(&emitter);

    /* Null-terminate */
    if (buf.buffer) {
        buf.buffer = (unsigned char *)realloc(buf.buffer, buf.size + 1);
        buf.buffer[buf.size] = '\0';
    }
    if (out_len) *out_len = buf.size;

    /* Remove trailing newline if present for cleaner output */
    if (buf.size > 0 && buf.buffer[buf.size - 1] == '\n') {
        buf.buffer[buf.size - 1] = '\0';
        if (out_len) (*out_len)--;
    }

    return (char *)buf.buffer;

error:
    yaml_emitter_delete(&emitter);
    free(buf.buffer);
    return sn_yaml_strdup("");
}

RtHandleV2 *sn_yaml_to_string(RtArenaV2 *arena, SnYaml *y)
{
    if (y == NULL || y->node == NULL) {
        return rt_arena_v2_strdup(arena, "");
    }

    size_t len;
    char *str = sn_yaml_serialize(y->node, &len);
    RtHandleV2 *result = rt_arena_v2_strdup(arena, str ? str : "");
    free(str);
    return result;
}

void sn_yaml_write_file(SnYaml *y, const char *path)
{
    if (y == NULL || y->node == NULL || path == NULL) {
        fprintf(stderr, "Yaml.writeFile: invalid arguments\n");
        return;
    }

    FILE *f = fopen(path, "w");
    if (f == NULL) {
        fprintf(stderr, "Yaml.writeFile: cannot open file '%s': %s\n", path, strerror(errno));
        return;
    }

    yaml_emitter_t emitter;
    yaml_event_t event;

    if (!yaml_emitter_initialize(&emitter)) {
        fprintf(stderr, "Yaml.writeFile: failed to initialize emitter\n");
        fclose(f);
        return;
    }

    yaml_emitter_set_output_file(&emitter, f);
    yaml_emitter_set_unicode(&emitter, 1);

    /* Stream start */
    yaml_stream_start_event_initialize(&event, YAML_UTF8_ENCODING);
    if (!yaml_emitter_emit(&emitter, &event)) goto write_error;

    /* Document start */
    yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 1);
    if (!yaml_emitter_emit(&emitter, &event)) goto write_error;

    /* Emit tree */
    if (!sn_yaml_emit_node(&emitter, y->node)) goto write_error;

    /* Document end */
    yaml_document_end_event_initialize(&event, 1);
    if (!yaml_emitter_emit(&emitter, &event)) goto write_error;

    /* Stream end */
    yaml_stream_end_event_initialize(&event);
    if (!yaml_emitter_emit(&emitter, &event)) goto write_error;

    yaml_emitter_delete(&emitter);
    fclose(f);
    return;

write_error:
    fprintf(stderr, "Yaml.writeFile: emitter error: %s\n", emitter.problem ? emitter.problem : "unknown");
    yaml_emitter_delete(&emitter);
    fclose(f);
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

static SnYamlNode *sn_yaml_deep_copy_node(SnYamlNode *node)
{
    if (node == NULL) return NULL;

    switch (node->type) {
        case SN_YAML_SCALAR:
            return sn_yaml_node_new_scalar(node->scalar_value);
        case SN_YAML_SEQUENCE: {
            SnYamlNode *copy = sn_yaml_node_new_sequence();
            for (int i = 0; i < node->seq_count; i++) {
                SnYamlNode *child_copy = sn_yaml_deep_copy_node(node->seq_items[i]);
                sn_yaml_seq_append(copy, child_copy);
            }
            return copy;
        }
        case SN_YAML_MAPPING: {
            SnYamlNode *copy = sn_yaml_node_new_mapping();
            for (int i = 0; i < node->map_count; i++) {
                SnYamlNode *val_copy = sn_yaml_deep_copy_node(node->map_pairs[i].value);
                sn_yaml_map_set(copy, node->map_pairs[i].key ? node->map_pairs[i].key : "", val_copy);
            }
            return copy;
        }
    }
    return sn_yaml_node_new_scalar("");
}

RtHandleV2 *sn_yaml_copy(RtArenaV2 *arena, SnYaml *y)
{
    if (y == NULL || y->node == NULL) {
        return sn_yaml_scalar(arena, "");
    }
    SnYamlNode *copy = sn_yaml_deep_copy_node(y->node);
    return sn_yaml_wrap(arena, copy, copy, 1);
}

RtHandleV2 *sn_yaml_type_name(RtArenaV2 *arena, SnYaml *y)
{
    if (y == NULL || y->node == NULL) {
        return rt_arena_v2_strdup(arena, "scalar");
    }
    switch (y->node->type) {
        case SN_YAML_SCALAR: return rt_arena_v2_strdup(arena, "scalar");
        case SN_YAML_SEQUENCE: return rt_arena_v2_strdup(arena, "sequence");
        case SN_YAML_MAPPING: return rt_arena_v2_strdup(arena, "mapping");
    }
    return rt_arena_v2_strdup(arena, "scalar");
}
