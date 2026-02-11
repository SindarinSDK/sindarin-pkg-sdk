/* ==============================================================================
 * sdk/json.sn.c - JSON Implementation for Sindarin SDK using yyjson
 * ==============================================================================
 * This file provides the C implementation for the Json type.
 * It is compiled via #pragma source and linked with Sindarin code.
 * ============================================================================== */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include <yyjson.h>

/* Include runtime arena for proper memory management */
#include "runtime/array/runtime_array_v2.h"

/* ============================================================================
 * Json Type Definition
 * ============================================================================ */

typedef struct SnJson {
    yyjson_mut_doc *doc;    /* The mutable document (owns memory) */
    yyjson_mut_val *val;    /* The current value within the document */
    int32_t is_root;        /* Whether this is the root owner of the doc */
} SnJson;

/* ============================================================================
 * Cleanup Callback for yyjson documents
 * ============================================================================
 * When a Json with is_root=1 is allocated, we register a cleanup callback
 * that frees the yyjson_mut_doc when the arena is destroyed (e.g., when
 * a thread terminates). This prevents memory leaks from accumulating.
 * ============================================================================ */

static void sn_json_doc_cleanup(RtHandleV2 *data)
{
    rt_handle_v2_pin(data);
    SnJson *j = (SnJson *)data->ptr;
    if (j != NULL && j->doc != NULL) {
        yyjson_mut_doc_free(j->doc);
        j->doc = NULL;
    }
}

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/* Create a new SnJson wrapper for a value within an existing document.
 * If is_root is true, registers a cleanup callback to free the yyjson doc
 * when the arena is destroyed (e.g., when the thread terminates). */
static SnJson *sn_json_wrap(RtArenaV2 *arena, yyjson_mut_doc *doc, yyjson_mut_val *val, int is_root)
{
    RtHandleV2 *_h = rt_arena_v2_alloc(arena, sizeof(SnJson));
    rt_handle_v2_pin(_h);
    SnJson *j = (SnJson *)_h->ptr;
    j->doc = doc;
    j->val = val;
    j->is_root = is_root;

    /* Register cleanup callback to free the yyjson doc when arena is destroyed.
     * This prevents memory leaks when Json objects go out of scope.
     * Priority 100 ensures Json cleanup happens after user cleanup callbacks. */
    if (is_root && doc != NULL) {
        rt_arena_v2_on_cleanup(arena, _h, sn_json_doc_cleanup, 100);
    }

    return j;
}

/* Create a new empty document and wrap it */
static SnJson *sn_json_new_doc(RtArenaV2 *arena)
{
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (doc == NULL) {
        fprintf(stderr, "Json: failed to create document\n");
        exit(1);
    }
    return sn_json_wrap(arena, doc, NULL, 1);
}

/* ============================================================================
 * Parsing Functions
 * ============================================================================ */

SnJson *sn_json_parse(RtArenaV2 *arena, const char *text)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.parse: arena is NULL\n");
        exit(1);
    }
    if (text == NULL) {
        fprintf(stderr, "Json.parse: text is NULL\n");
        exit(1);
    }

    /* Parse as immutable first */
    yyjson_read_err err;
    yyjson_doc *idoc = yyjson_read_opts((char *)text, strlen(text), 0, NULL, &err);
    if (idoc == NULL) {
        fprintf(stderr, "Json.parse: %s at position %zu\n", err.msg, err.pos);
        exit(1);
    }

    /* Convert to mutable for read-write operations */
    yyjson_mut_doc *doc = yyjson_doc_mut_copy(idoc, NULL);
    yyjson_doc_free(idoc);

    if (doc == NULL) {
        fprintf(stderr, "Json.parse: failed to create mutable document\n");
        exit(1);
    }

    yyjson_mut_val *root = yyjson_mut_doc_get_root(doc);
    return sn_json_wrap(arena, doc, root, 1);
}

SnJson *sn_json_parse_file(RtArenaV2 *arena, const char *path)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.parseFile: arena is NULL\n");
        exit(1);
    }
    if (path == NULL) {
        fprintf(stderr, "Json.parseFile: path is NULL\n");
        exit(1);
    }

    /* Read and parse file */
    yyjson_read_err err;
    yyjson_doc *idoc = yyjson_read_file(path, 0, NULL, &err);
    if (idoc == NULL) {
        fprintf(stderr, "Json.parseFile: %s (file: %s)\n", err.msg, path);
        exit(1);
    }

    /* Convert to mutable */
    yyjson_mut_doc *doc = yyjson_doc_mut_copy(idoc, NULL);
    yyjson_doc_free(idoc);

    if (doc == NULL) {
        fprintf(stderr, "Json.parseFile: failed to create mutable document\n");
        exit(1);
    }

    yyjson_mut_val *root = yyjson_mut_doc_get_root(doc);
    return sn_json_wrap(arena, doc, root, 1);
}

/* ============================================================================
 * Creation Functions
 * ============================================================================ */

SnJson *sn_json_new_object(RtArenaV2 *arena)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.object: arena is NULL\n");
        exit(1);
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (doc == NULL) {
        fprintf(stderr, "Json.object: failed to create document\n");
        exit(1);
    }

    yyjson_mut_val *obj = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, obj);

    return sn_json_wrap(arena, doc, obj, 1);
}

SnJson *sn_json_new_array(RtArenaV2 *arena)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.array: arena is NULL\n");
        exit(1);
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (doc == NULL) {
        fprintf(stderr, "Json.array: failed to create document\n");
        exit(1);
    }

    yyjson_mut_val *arr = yyjson_mut_arr(doc);
    yyjson_mut_doc_set_root(doc, arr);

    return sn_json_wrap(arena, doc, arr, 1);
}

SnJson *sn_json_new_null(RtArenaV2 *arena)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.null: arena is NULL\n");
        exit(1);
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (doc == NULL) {
        fprintf(stderr, "Json.null: failed to create document\n");
        exit(1);
    }

    yyjson_mut_val *val = yyjson_mut_null(doc);
    yyjson_mut_doc_set_root(doc, val);

    return sn_json_wrap(arena, doc, val, 1);
}

SnJson *sn_json_new_bool(RtArenaV2 *arena, bool value)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.bool: arena is NULL\n");
        exit(1);
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (doc == NULL) {
        fprintf(stderr, "Json.bool: failed to create document\n");
        exit(1);
    }

    yyjson_mut_val *val = yyjson_mut_bool(doc, value);
    yyjson_mut_doc_set_root(doc, val);

    return sn_json_wrap(arena, doc, val, 1);
}

SnJson *sn_json_new_int(RtArenaV2 *arena, int64_t value)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.int: arena is NULL\n");
        exit(1);
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (doc == NULL) {
        fprintf(stderr, "Json.int: failed to create document\n");
        exit(1);
    }

    yyjson_mut_val *val = yyjson_mut_sint(doc, value);
    yyjson_mut_doc_set_root(doc, val);

    return sn_json_wrap(arena, doc, val, 1);
}

SnJson *sn_json_new_float(RtArenaV2 *arena, double value)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.float: arena is NULL\n");
        exit(1);
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (doc == NULL) {
        fprintf(stderr, "Json.float: failed to create document\n");
        exit(1);
    }

    yyjson_mut_val *val = yyjson_mut_real(doc, value);
    yyjson_mut_doc_set_root(doc, val);

    return sn_json_wrap(arena, doc, val, 1);
}

SnJson *sn_json_new_string(RtArenaV2 *arena, const char *value)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.string: arena is NULL\n");
        exit(1);
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (doc == NULL) {
        fprintf(stderr, "Json.string: failed to create document\n");
        exit(1);
    }

    yyjson_mut_val *val = yyjson_mut_strcpy(doc, value ? value : "");
    yyjson_mut_doc_set_root(doc, val);

    return sn_json_wrap(arena, doc, val, 1);
}

/* ============================================================================
 * Type Checking Functions
 * ============================================================================ */

bool sn_json_is_object(SnJson *j)
{
    if (j == NULL || j->val == NULL) return false;
    return yyjson_mut_is_obj(j->val);
}

bool sn_json_is_array(SnJson *j)
{
    if (j == NULL || j->val == NULL) return false;
    return yyjson_mut_is_arr(j->val);
}

bool sn_json_is_string(SnJson *j)
{
    if (j == NULL || j->val == NULL) return false;
    return yyjson_mut_is_str(j->val);
}

bool sn_json_is_number(SnJson *j)
{
    if (j == NULL || j->val == NULL) return false;
    return yyjson_mut_is_num(j->val);
}

bool sn_json_is_int(SnJson *j)
{
    if (j == NULL || j->val == NULL) return false;
    return yyjson_mut_is_int(j->val);
}

bool sn_json_is_float(SnJson *j)
{
    if (j == NULL || j->val == NULL) return false;
    return yyjson_mut_is_real(j->val);
}

bool sn_json_is_bool(SnJson *j)
{
    if (j == NULL || j->val == NULL) return false;
    return yyjson_mut_is_bool(j->val);
}

bool sn_json_is_null(SnJson *j)
{
    if (j == NULL || j->val == NULL) return true;
    return yyjson_mut_is_null(j->val);
}

/* ============================================================================
 * Value Extraction Functions
 * ============================================================================ */

RtHandleV2 *sn_json_as_string(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->val == NULL) {
        return rt_arena_v2_strdup(arena, "");
    }
    if (!yyjson_mut_is_str(j->val)) {
        return rt_arena_v2_strdup(arena, "");
    }
    const char *str = yyjson_mut_get_str(j->val);
    return rt_arena_v2_strdup(arena, str ? str : "");
}

int64_t sn_json_as_int(SnJson *j)
{
    if (j == NULL || j->val == NULL) return 0;
    if (!yyjson_mut_is_num(j->val)) return 0;
    return yyjson_mut_get_sint(j->val);
}

int64_t sn_json_as_long(SnJson *j)
{
    if (j == NULL || j->val == NULL) return 0;
    if (!yyjson_mut_is_num(j->val)) return 0;
    return yyjson_mut_get_sint(j->val);
}

double sn_json_as_float(SnJson *j)
{
    if (j == NULL || j->val == NULL) return 0.0;
    if (!yyjson_mut_is_num(j->val)) return 0.0;
    return yyjson_mut_get_real(j->val);
}

bool sn_json_as_bool(SnJson *j)
{
    if (j == NULL || j->val == NULL) return false;
    if (!yyjson_mut_is_bool(j->val)) return false;
    return yyjson_mut_get_bool(j->val);
}

/* ============================================================================
 * Object/Array Access Functions
 * ============================================================================ */

SnJson *sn_json_get(RtArenaV2 *arena, SnJson *j, const char *key)
{
    if (j == NULL || j->val == NULL || key == NULL) {
        return sn_json_wrap(arena, j ? j->doc : NULL, NULL, 0);
    }
    if (!yyjson_mut_is_obj(j->val)) {
        return sn_json_wrap(arena, j->doc, NULL, 0);
    }

    yyjson_mut_val *val = yyjson_mut_obj_get(j->val, key);
    return sn_json_wrap(arena, j->doc, val, 0);
}

bool sn_json_has(SnJson *j, const char *key)
{
    if (j == NULL || j->val == NULL || key == NULL) return false;
    if (!yyjson_mut_is_obj(j->val)) return false;
    return yyjson_mut_obj_get(j->val, key) != NULL;
}

RtHandleV2 *sn_json_keys(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->val == NULL || !yyjson_mut_is_obj(j->val)) {
        return rt_array_create_string_v2(arena, 0, NULL);
    }

    /* Start with empty string array */
    RtHandleV2 *keys = rt_array_create_string_v2(arena, 0, NULL);

    yyjson_mut_obj_iter iter;
    yyjson_mut_obj_iter_init(j->val, &iter);
    yyjson_mut_val *key;

    while ((key = yyjson_mut_obj_iter_next(&iter)) != NULL) {
        const char *key_str = yyjson_mut_get_str(key);
        keys = rt_array_push_string_v2(arena, keys, key_str ? key_str : "");
    }

    return keys;
}

SnJson *sn_json_get_at(RtArenaV2 *arena, SnJson *j, int64_t index)
{
    if (j == NULL || j->val == NULL) {
        return sn_json_wrap(arena, j ? j->doc : NULL, NULL, 0);
    }
    if (!yyjson_mut_is_arr(j->val)) {
        return sn_json_wrap(arena, j->doc, NULL, 0);
    }
    if (index < 0 || (size_t)index >= yyjson_mut_arr_size(j->val)) {
        return sn_json_wrap(arena, j->doc, NULL, 0);
    }

    yyjson_mut_val *val = yyjson_mut_arr_get(j->val, (size_t)index);
    return sn_json_wrap(arena, j->doc, val, 0);
}

SnJson *sn_json_first(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->val == NULL || !yyjson_mut_is_arr(j->val)) {
        return sn_json_wrap(arena, j ? j->doc : NULL, NULL, 0);
    }
    yyjson_mut_val *val = yyjson_mut_arr_get_first(j->val);
    return sn_json_wrap(arena, j->doc, val, 0);
}

SnJson *sn_json_last(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->val == NULL || !yyjson_mut_is_arr(j->val)) {
        return sn_json_wrap(arena, j ? j->doc : NULL, NULL, 0);
    }
    yyjson_mut_val *val = yyjson_mut_arr_get_last(j->val);
    return sn_json_wrap(arena, j->doc, val, 0);
}

/* ============================================================================
 * Size Functions
 * ============================================================================ */

int64_t sn_json_length(SnJson *j)
{
    if (j == NULL || j->val == NULL) return 0;

    if (yyjson_mut_is_obj(j->val)) {
        return (int64_t)yyjson_mut_obj_size(j->val);
    }
    if (yyjson_mut_is_arr(j->val)) {
        return (int64_t)yyjson_mut_arr_size(j->val);
    }
    return 0;
}

/* ============================================================================
 * Mutation Functions (Object)
 * ============================================================================ */

void sn_json_set(SnJson *j, const char *key, SnJson *value)
{
    if (j == NULL || j->val == NULL || key == NULL || value == NULL) {
        fprintf(stderr, "Json.set: invalid arguments\n");
        return;
    }
    if (!yyjson_mut_is_obj(j->val)) {
        fprintf(stderr, "Json.set: not an object\n");
        return;
    }

    /* Copy the value into this document */
    yyjson_mut_val *val_copy = yyjson_mut_val_mut_copy(j->doc, value->val);
    yyjson_mut_val *key_val = yyjson_mut_strcpy(j->doc, key);

    /* Remove existing key if present, then add new */
    yyjson_mut_obj_remove_key(j->val, key);
    yyjson_mut_obj_add(j->val, key_val, val_copy);
}

void sn_json_remove(SnJson *j, const char *key)
{
    if (j == NULL || j->val == NULL || key == NULL) return;
    if (!yyjson_mut_is_obj(j->val)) return;

    yyjson_mut_obj_remove_key(j->val, key);
}

/* ============================================================================
 * Mutation Functions (Array)
 * ============================================================================ */

void sn_json_append(SnJson *j, SnJson *value)
{
    if (j == NULL || j->val == NULL || value == NULL) {
        fprintf(stderr, "Json.append: invalid arguments\n");
        return;
    }
    if (!yyjson_mut_is_arr(j->val)) {
        fprintf(stderr, "Json.append: not an array\n");
        return;
    }

    /* Copy the value into this document */
    yyjson_mut_val *val_copy = yyjson_mut_val_mut_copy(j->doc, value->val);
    yyjson_mut_arr_append(j->val, val_copy);
}

void sn_json_prepend(SnJson *j, SnJson *value)
{
    if (j == NULL || j->val == NULL || value == NULL) {
        fprintf(stderr, "Json.prepend: invalid arguments\n");
        return;
    }
    if (!yyjson_mut_is_arr(j->val)) {
        fprintf(stderr, "Json.prepend: not an array\n");
        return;
    }

    /* Copy the value into this document */
    yyjson_mut_val *val_copy = yyjson_mut_val_mut_copy(j->doc, value->val);
    yyjson_mut_arr_prepend(j->val, val_copy);
}

void sn_json_insert(SnJson *j, int64_t index, SnJson *value)
{
    if (j == NULL || j->val == NULL || value == NULL) {
        fprintf(stderr, "Json.insert: invalid arguments\n");
        return;
    }
    if (!yyjson_mut_is_arr(j->val)) {
        fprintf(stderr, "Json.insert: not an array\n");
        return;
    }

    /* Copy the value into this document */
    yyjson_mut_val *val_copy = yyjson_mut_val_mut_copy(j->doc, value->val);
    yyjson_mut_arr_insert(j->val, val_copy, (size_t)index);
}

void sn_json_remove_at(SnJson *j, int64_t index)
{
    if (j == NULL || j->val == NULL) return;
    if (!yyjson_mut_is_arr(j->val)) return;
    if (index < 0 || (size_t)index >= yyjson_mut_arr_size(j->val)) return;

    yyjson_mut_arr_remove(j->val, (size_t)index);
}

/* ============================================================================
 * Serialization Functions
 * ============================================================================ */

RtHandleV2 *sn_json_to_string(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->val == NULL) {
        return rt_arena_v2_strdup(arena, "null");
    }

    size_t len;
    char *str = yyjson_mut_val_write(j->val, 0, &len);
    if (str == NULL) {
        return rt_arena_v2_strdup(arena, "null");
    }

    RtHandleV2 *result = rt_arena_v2_strdup(arena, str);
    free(str);
    return result;
}

RtHandleV2 *sn_json_to_pretty_string(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->val == NULL) {
        return rt_arena_v2_strdup(arena, "null");
    }

    size_t len;
    char *str = yyjson_mut_val_write(j->val, YYJSON_WRITE_PRETTY, &len);
    if (str == NULL) {
        return rt_arena_v2_strdup(arena, "null");
    }

    RtHandleV2 *result = rt_arena_v2_strdup(arena, str);
    free(str);
    return result;
}

void sn_json_write_file(SnJson *j, const char *path)
{
    if (j == NULL || j->val == NULL || path == NULL) {
        fprintf(stderr, "Json.writeFile: invalid arguments\n");
        return;
    }

    yyjson_write_err err;
    bool success = yyjson_mut_write_file(path, j->doc, 0, NULL, &err);
    if (!success) {
        fprintf(stderr, "Json.writeFile: %s (file: %s)\n", err.msg, path);
    }
}

void sn_json_write_file_pretty(SnJson *j, const char *path)
{
    if (j == NULL || j->val == NULL || path == NULL) {
        fprintf(stderr, "Json.writeFilePretty: invalid arguments\n");
        return;
    }

    yyjson_write_err err;
    bool success = yyjson_mut_write_file(path, j->doc, YYJSON_WRITE_PRETTY, NULL, &err);
    if (!success) {
        fprintf(stderr, "Json.writeFilePretty: %s (file: %s)\n", err.msg, path);
    }
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

SnJson *sn_json_copy(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->val == NULL) {
        return sn_json_new_null(arena);
    }

    /* Create a new document with a deep copy of the value */
    yyjson_mut_doc *new_doc = yyjson_mut_doc_new(NULL);
    if (new_doc == NULL) {
        fprintf(stderr, "Json.copy: failed to create document\n");
        exit(1);
    }

    yyjson_mut_val *val_copy = yyjson_mut_val_mut_copy(new_doc, j->val);
    yyjson_mut_doc_set_root(new_doc, val_copy);

    return sn_json_wrap(arena, new_doc, val_copy, 1);
}

RtHandleV2 *sn_json_type_name(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->val == NULL) {
        return rt_arena_v2_strdup(arena, "null");
    }

    if (yyjson_mut_is_obj(j->val)) return rt_arena_v2_strdup(arena, "object");
    if (yyjson_mut_is_arr(j->val)) return rt_arena_v2_strdup(arena, "array");
    if (yyjson_mut_is_str(j->val)) return rt_arena_v2_strdup(arena, "string");
    if (yyjson_mut_is_bool(j->val)) return rt_arena_v2_strdup(arena, "bool");
    if (yyjson_mut_is_null(j->val)) return rt_arena_v2_strdup(arena, "null");
    if (yyjson_mut_is_num(j->val)) return rt_arena_v2_strdup(arena, "number");

    return rt_arena_v2_strdup(arena, "unknown");
}
