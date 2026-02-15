/* ==============================================================================
 * sdk/json.sn.c - JSON Implementation for Sindarin SDK using json-c
 * ==============================================================================
 * This file provides the C implementation for the Json type.
 * It is compiled via #pragma source and linked with Sindarin code.
 *
 * Uses json-c's reference-counted json_object instead of yyjson's pool
 * allocator. This allows removed values to be freed immediately, eliminating
 * unbounded memory growth in long-lived JSON arrays/objects.
 * ============================================================================== */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include <json-c/json.h>

/* Include runtime arena for proper memory management */
#include "runtime/array/runtime_array_v2.h"

/* ============================================================================
 * Json Type Definition
 * ============================================================================ */

typedef struct SnJson {
    json_object *obj;       /* The json-c object (ref-counted) */
    RtHandleV2 *handle;     /* Self-reference to own arena handle (for dispose) */
    int32_t is_root;        /* Whether this wrapper owns a json-c reference */
} SnJson;

/* ============================================================================
 * Cleanup Callback for json-c objects
 * ============================================================================
 * When a Json wrapper is allocated, we register a cleanup callback that
 * releases the json-c reference when the arena is destroyed. This prevents
 * memory leaks when Json objects go out of scope without explicit dispose.
 * ============================================================================ */

static void sn_json_cleanup(RtHandleV2 *data)
{
    SnJson *j = (SnJson *)data->ptr;
    if (j != NULL && j->obj != NULL) {
        json_object_put(j->obj);
        j->obj = NULL;
    }
}

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/* Create a new SnJson wrapper for a json-c object.
 * If the object is non-NULL, registers a cleanup callback to release the
 * json-c reference when the arena is destroyed. */
static SnJson *sn_json_wrap(RtArenaV2 *arena, json_object *obj, int is_root)
{
    RtHandleV2 *_h = rt_arena_v2_alloc(arena, sizeof(SnJson));
    SnJson *j = (SnJson *)_h->ptr;
    j->obj = obj;
    j->handle = _h;
    j->is_root = is_root;

    /* Register cleanup callback to release json-c reference when arena is
     * destroyed. This prevents memory leaks when Json objects go out of scope.
     * Priority 100 ensures Json cleanup happens after user cleanup callbacks. */
    if (obj != NULL) {
        rt_arena_v2_on_cleanup(arena, _h, sn_json_cleanup, 100);
    }

    return j;
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

    json_tokener *tok = json_tokener_new();
    if (tok == NULL) {
        fprintf(stderr, "Json.parse: failed to create tokener\n");
        exit(1);
    }

    json_object *obj = json_tokener_parse_ex(tok, text, (int)strlen(text));
    enum json_tokener_error err = json_tokener_get_error(tok);

    if (err != json_tokener_success) {
        fprintf(stderr, "Json.parse: %s\n", json_tokener_error_desc(err));
        json_tokener_free(tok);
        exit(1);
    }

    json_tokener_free(tok);
    return sn_json_wrap(arena, obj, 1);
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

    json_object *obj = json_object_from_file(path);
    if (obj == NULL) {
        const char *err = json_util_get_last_err();
        fprintf(stderr, "Json.parseFile: %s (file: %s)\n",
                err ? err : "unknown error", path);
        exit(1);
    }

    return sn_json_wrap(arena, obj, 1);
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

    json_object *obj = json_object_new_object();
    if (obj == NULL) {
        fprintf(stderr, "Json.object: failed to create object\n");
        exit(1);
    }

    return sn_json_wrap(arena, obj, 1);
}

SnJson *sn_json_new_array(RtArenaV2 *arena)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.array: arena is NULL\n");
        exit(1);
    }

    json_object *obj = json_object_new_array();
    if (obj == NULL) {
        fprintf(stderr, "Json.array: failed to create array\n");
        exit(1);
    }

    return sn_json_wrap(arena, obj, 1);
}

SnJson *sn_json_new_null(RtArenaV2 *arena)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.null: arena is NULL\n");
        exit(1);
    }

    /* json-c represents null as NULL pointer. No cleanup needed. */
    return sn_json_wrap(arena, NULL, 1);
}

SnJson *sn_json_new_bool(RtArenaV2 *arena, bool value)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.bool: arena is NULL\n");
        exit(1);
    }

    json_object *obj = json_object_new_boolean(value);
    if (obj == NULL) {
        fprintf(stderr, "Json.bool: failed to create boolean\n");
        exit(1);
    }

    return sn_json_wrap(arena, obj, 1);
}

SnJson *sn_json_new_int(RtArenaV2 *arena, int64_t value)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.int: arena is NULL\n");
        exit(1);
    }

    json_object *obj = json_object_new_int64(value);
    if (obj == NULL) {
        fprintf(stderr, "Json.int: failed to create integer\n");
        exit(1);
    }

    return sn_json_wrap(arena, obj, 1);
}

SnJson *sn_json_new_float(RtArenaV2 *arena, double value)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.float: arena is NULL\n");
        exit(1);
    }

    json_object *obj = json_object_new_double(value);
    if (obj == NULL) {
        fprintf(stderr, "Json.float: failed to create float\n");
        exit(1);
    }

    return sn_json_wrap(arena, obj, 1);
}

SnJson *sn_json_new_string(RtArenaV2 *arena, const char *value)
{
    if (arena == NULL) {
        fprintf(stderr, "Json.string: arena is NULL\n");
        exit(1);
    }

    json_object *obj = json_object_new_string(value ? value : "");
    if (obj == NULL) {
        fprintf(stderr, "Json.string: failed to create string\n");
        exit(1);
    }

    return sn_json_wrap(arena, obj, 1);
}

/* ============================================================================
 * Type Checking Functions
 * ============================================================================ */

bool sn_json_is_object(SnJson *j)
{
    if (j == NULL || j->obj == NULL) return false;
    return json_object_is_type(j->obj, json_type_object);
}

bool sn_json_is_array(SnJson *j)
{
    if (j == NULL || j->obj == NULL) return false;
    return json_object_is_type(j->obj, json_type_array);
}

bool sn_json_is_string(SnJson *j)
{
    if (j == NULL || j->obj == NULL) return false;
    return json_object_is_type(j->obj, json_type_string);
}

bool sn_json_is_number(SnJson *j)
{
    if (j == NULL || j->obj == NULL) return false;
    return json_object_is_type(j->obj, json_type_int)
        || json_object_is_type(j->obj, json_type_double);
}

bool sn_json_is_int(SnJson *j)
{
    if (j == NULL || j->obj == NULL) return false;
    return json_object_is_type(j->obj, json_type_int);
}

bool sn_json_is_float(SnJson *j)
{
    if (j == NULL || j->obj == NULL) return false;
    return json_object_is_type(j->obj, json_type_double);
}

bool sn_json_is_bool(SnJson *j)
{
    if (j == NULL || j->obj == NULL) return false;
    return json_object_is_type(j->obj, json_type_boolean);
}

bool sn_json_is_null(SnJson *j)
{
    if (j == NULL || j->obj == NULL) return true;
    return json_object_is_type(j->obj, json_type_null);
}

/* ============================================================================
 * Value Extraction Functions
 * ============================================================================ */

RtHandleV2 *sn_json_as_string(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->obj == NULL) {
        return rt_arena_v2_strdup(arena, "");
    }
    if (!json_object_is_type(j->obj, json_type_string)) {
        return rt_arena_v2_strdup(arena, "");
    }
    const char *str = json_object_get_string(j->obj);
    return rt_arena_v2_strdup(arena, str ? str : "");
}

int64_t sn_json_as_int(SnJson *j)
{
    if (j == NULL || j->obj == NULL) return 0;
    if (!json_object_is_type(j->obj, json_type_int)
        && !json_object_is_type(j->obj, json_type_double)) return 0;
    return json_object_get_int64(j->obj);
}

int64_t sn_json_as_long(SnJson *j)
{
    if (j == NULL || j->obj == NULL) return 0;
    if (!json_object_is_type(j->obj, json_type_int)
        && !json_object_is_type(j->obj, json_type_double)) return 0;
    return json_object_get_int64(j->obj);
}

double sn_json_as_float(SnJson *j)
{
    if (j == NULL || j->obj == NULL) return 0.0;
    if (!json_object_is_type(j->obj, json_type_double)
        && !json_object_is_type(j->obj, json_type_int)) return 0.0;
    return json_object_get_double(j->obj);
}

bool sn_json_as_bool(SnJson *j)
{
    if (j == NULL || j->obj == NULL) return false;
    if (!json_object_is_type(j->obj, json_type_boolean)) return false;
    return json_object_get_boolean(j->obj);
}

/* ============================================================================
 * Object/Array Access Functions
 * ============================================================================ */

SnJson *sn_json_get(RtArenaV2 *arena, SnJson *j, const char *key)
{
    if (j == NULL || j->obj == NULL || key == NULL) {
        return sn_json_wrap(arena, NULL, 0);
    }
    if (!json_object_is_type(j->obj, json_type_object)) {
        return sn_json_wrap(arena, NULL, 0);
    }

    json_object *val = NULL;
    if (!json_object_object_get_ex(j->obj, key, &val)) {
        return sn_json_wrap(arena, NULL, 0);
    }

    /* Increment refcount - child wrapper owns a reference */
    if (val != NULL) {
        json_object_get(val);
    }
    return sn_json_wrap(arena, val, 0);
}

bool sn_json_has(SnJson *j, const char *key)
{
    if (j == NULL || j->obj == NULL || key == NULL) return false;
    if (!json_object_is_type(j->obj, json_type_object)) return false;
    return json_object_object_get_ex(j->obj, key, NULL);
}

RtHandleV2 *sn_json_keys(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->obj == NULL || !json_object_is_type(j->obj, json_type_object)) {
        return rt_array_create_string_v2(arena, 0, NULL);
    }

    RtHandleV2 *keys = rt_array_create_string_v2(arena, 0, NULL);

    json_object_iter iter;
    json_object_object_foreachC(j->obj, iter) {
        RtHandleV2 *key_h = rt_arena_v2_strdup(arena, iter.key ? iter.key : "");
        keys = rt_array_push_string_v2(arena, keys, key_h);
    }

    return keys;
}

SnJson *sn_json_get_at(RtArenaV2 *arena, SnJson *j, int64_t index)
{
    if (j == NULL || j->obj == NULL) {
        return sn_json_wrap(arena, NULL, 0);
    }
    if (!json_object_is_type(j->obj, json_type_array)) {
        return sn_json_wrap(arena, NULL, 0);
    }
    size_t len = json_object_array_length(j->obj);
    if (index < 0 || (size_t)index >= len) {
        return sn_json_wrap(arena, NULL, 0);
    }

    json_object *val = json_object_array_get_idx(j->obj, (size_t)index);
    /* Increment refcount - child wrapper owns a reference */
    if (val != NULL) {
        json_object_get(val);
    }
    return sn_json_wrap(arena, val, 0);
}

SnJson *sn_json_first(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->obj == NULL || !json_object_is_type(j->obj, json_type_array)) {
        return sn_json_wrap(arena, NULL, 0);
    }
    size_t len = json_object_array_length(j->obj);
    if (len == 0) {
        return sn_json_wrap(arena, NULL, 0);
    }

    json_object *val = json_object_array_get_idx(j->obj, 0);
    if (val != NULL) {
        json_object_get(val);
    }
    return sn_json_wrap(arena, val, 0);
}

SnJson *sn_json_last(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->obj == NULL || !json_object_is_type(j->obj, json_type_array)) {
        return sn_json_wrap(arena, NULL, 0);
    }
    size_t len = json_object_array_length(j->obj);
    if (len == 0) {
        return sn_json_wrap(arena, NULL, 0);
    }

    json_object *val = json_object_array_get_idx(j->obj, len - 1);
    if (val != NULL) {
        json_object_get(val);
    }
    return sn_json_wrap(arena, val, 0);
}

/* ============================================================================
 * Size Functions
 * ============================================================================ */

int64_t sn_json_length(SnJson *j)
{
    if (j == NULL || j->obj == NULL) return 0;

    if (json_object_is_type(j->obj, json_type_object)) {
        return (int64_t)json_object_object_length(j->obj);
    }
    if (json_object_is_type(j->obj, json_type_array)) {
        return (int64_t)json_object_array_length(j->obj);
    }
    return 0;
}

/* ============================================================================
 * Mutation Functions (Object)
 * ============================================================================ */

void sn_json_set(SnJson *j, const char *key, SnJson *value)
{
    if (j == NULL || j->obj == NULL || key == NULL || value == NULL) {
        fprintf(stderr, "Json.set: invalid arguments\n");
        return;
    }
    if (!json_object_is_type(j->obj, json_type_object)) {
        fprintf(stderr, "Json.set: not an object\n");
        return;
    }

    /* Deep copy the value (same value semantics as before) */
    json_object *copy = NULL;
    if (value->obj != NULL) {
        if (json_object_deep_copy(value->obj, &copy, NULL) != 0) {
            fprintf(stderr, "Json.set: failed to copy value\n");
            return;
        }
    }

    /* Remove existing key if present, then add new.
     * json_object_object_del frees the old value via json_object_put. */
    json_object_object_del(j->obj, key);
    json_object_object_add(j->obj, key, copy);
}

void sn_json_remove(SnJson *j, const char *key)
{
    if (j == NULL || j->obj == NULL || key == NULL) return;
    if (!json_object_is_type(j->obj, json_type_object)) return;

    /* json_object_object_del calls json_object_put on the removed value,
     * freeing it immediately if no other references exist. */
    json_object_object_del(j->obj, key);
}

/* ============================================================================
 * Mutation Functions (Array)
 * ============================================================================ */

void sn_json_append(SnJson *j, SnJson *value)
{
    if (j == NULL || j->obj == NULL || value == NULL) {
        fprintf(stderr, "Json.append: invalid arguments\n");
        return;
    }
    if (!json_object_is_type(j->obj, json_type_array)) {
        fprintf(stderr, "Json.append: not an array\n");
        return;
    }

    /* Deep copy the value - ownership transfers to parent array */
    json_object *copy = NULL;
    if (value->obj != NULL) {
        if (json_object_deep_copy(value->obj, &copy, NULL) != 0) {
            fprintf(stderr, "Json.append: failed to copy value\n");
            return;
        }
    }

    json_object_array_add(j->obj, copy);
}

void sn_json_prepend(SnJson *j, SnJson *value)
{
    if (j == NULL || j->obj == NULL || value == NULL) {
        fprintf(stderr, "Json.prepend: invalid arguments\n");
        return;
    }
    if (!json_object_is_type(j->obj, json_type_array)) {
        fprintf(stderr, "Json.prepend: not an array\n");
        return;
    }

    /* Deep copy the value - ownership transfers to parent array */
    json_object *copy = NULL;
    if (value->obj != NULL) {
        if (json_object_deep_copy(value->obj, &copy, NULL) != 0) {
            fprintf(stderr, "Json.prepend: failed to copy value\n");
            return;
        }
    }

    json_object_array_insert_idx(j->obj, 0, copy);
}

void sn_json_insert(SnJson *j, int64_t index, SnJson *value)
{
    if (j == NULL || j->obj == NULL || value == NULL) {
        fprintf(stderr, "Json.insert: invalid arguments\n");
        return;
    }
    if (!json_object_is_type(j->obj, json_type_array)) {
        fprintf(stderr, "Json.insert: not an array\n");
        return;
    }

    /* Deep copy the value - ownership transfers to parent array */
    json_object *copy = NULL;
    if (value->obj != NULL) {
        if (json_object_deep_copy(value->obj, &copy, NULL) != 0) {
            fprintf(stderr, "Json.insert: failed to copy value\n");
            return;
        }
    }

    json_object_array_insert_idx(j->obj, (size_t)index, copy);
}

void sn_json_remove_at(SnJson *j, int64_t index)
{
    if (j == NULL || j->obj == NULL) return;
    if (!json_object_is_type(j->obj, json_type_array)) return;
    size_t len = json_object_array_length(j->obj);
    if (index < 0 || (size_t)index >= len) return;

    /* json_object_array_del_idx calls json_object_put on the removed element,
     * freeing it immediately if no other references exist.
     * This is the key fix - removed values are properly freed, not left in a pool. */
    json_object_array_del_idx(j->obj, (size_t)index, 1);
}

/* ============================================================================
 * Serialization Functions
 * ============================================================================ */

RtHandleV2 *sn_json_to_string(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->obj == NULL) {
        return rt_arena_v2_strdup(arena, "null");
    }

    /* json_object_to_json_string_ext returns internal buffer - copy to arena */
    const char *str = json_object_to_json_string_ext(j->obj, JSON_C_TO_STRING_PLAIN);
    if (str == NULL) {
        return rt_arena_v2_strdup(arena, "null");
    }

    return rt_arena_v2_strdup(arena, str);
}

RtHandleV2 *sn_json_to_pretty_string(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->obj == NULL) {
        return rt_arena_v2_strdup(arena, "null");
    }

    const char *str = json_object_to_json_string_ext(j->obj, JSON_C_TO_STRING_PRETTY);
    if (str == NULL) {
        return rt_arena_v2_strdup(arena, "null");
    }

    return rt_arena_v2_strdup(arena, str);
}

void sn_json_write_file(SnJson *j, const char *path)
{
    if (j == NULL || j->obj == NULL || path == NULL) {
        fprintf(stderr, "Json.writeFile: invalid arguments\n");
        return;
    }

    if (json_object_to_file_ext(path, j->obj, JSON_C_TO_STRING_PLAIN) != 0) {
        const char *err = json_util_get_last_err();
        fprintf(stderr, "Json.writeFile: %s (file: %s)\n",
                err ? err : "unknown error", path);
    }
}

void sn_json_write_file_pretty(SnJson *j, const char *path)
{
    if (j == NULL || j->obj == NULL || path == NULL) {
        fprintf(stderr, "Json.writeFilePretty: invalid arguments\n");
        return;
    }

    if (json_object_to_file_ext(path, j->obj, JSON_C_TO_STRING_PRETTY) != 0) {
        const char *err = json_util_get_last_err();
        fprintf(stderr, "Json.writeFilePretty: %s (file: %s)\n",
                err ? err : "unknown error", path);
    }
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

SnJson *sn_json_copy(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->obj == NULL) {
        return sn_json_new_null(arena);
    }

    json_object *copy = NULL;
    if (json_object_deep_copy(j->obj, &copy, NULL) != 0) {
        fprintf(stderr, "Json.copy: failed to deep copy\n");
        exit(1);
    }

    return sn_json_wrap(arena, copy, 1);
}

RtHandleV2 *sn_json_type_name(RtArenaV2 *arena, SnJson *j)
{
    if (j == NULL || j->obj == NULL) {
        return rt_arena_v2_strdup(arena, "null");
    }

    if (json_object_is_type(j->obj, json_type_object))  return rt_arena_v2_strdup(arena, "object");
    if (json_object_is_type(j->obj, json_type_array))   return rt_arena_v2_strdup(arena, "array");
    if (json_object_is_type(j->obj, json_type_string))  return rt_arena_v2_strdup(arena, "string");
    if (json_object_is_type(j->obj, json_type_boolean)) return rt_arena_v2_strdup(arena, "bool");
    if (json_object_is_type(j->obj, json_type_null))    return rt_arena_v2_strdup(arena, "null");
    if (json_object_is_type(j->obj, json_type_int))     return rt_arena_v2_strdup(arena, "number");
    if (json_object_is_type(j->obj, json_type_double))  return rt_arena_v2_strdup(arena, "number");

    return rt_arena_v2_strdup(arena, "unknown");
}

/* ============================================================================
 * Dispose Function
 * ============================================================================
 * Releases the json-c reference and arena handle immediately. This allows
 * deterministic cleanup of JSON values in long-lived arenas.
 *
 * Two-tier cleanup:
 * 1. Explicit: User calls .dispose() - json_object freed, handle reclaimable
 * 2. Implicit: Arena destruction - cleanup callback fires (safety net)
 *
 * If dispose() is called first, it sets obj=NULL so the arena cleanup
 * callback becomes a no-op (no double-free).
 * ============================================================================ */

void sn_json_dispose(SnJson *j)
{
    if (j == NULL) return;

    if (j->obj != NULL) {
        json_object_put(j->obj);
        j->obj = NULL;
    }

    if (j->handle != NULL) {
        RtHandleV2 *h = j->handle;
        j->handle = NULL;
        /* Remove cleanup callback to avoid redundant no-op during arena destruction */
        rt_arena_v2_remove_cleanup(h->arena, h);
        rt_arena_v2_free(h);
    }
}
