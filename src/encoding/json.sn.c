/* ==============================================================================
 * sdk/json.sn.c - JSON Implementation for Sindarin SDK using json-c
 * ==============================================================================
 * Minimal runtime version - no arena, uses calloc/strdup for allocations.
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

/* ============================================================================
 * Json Type Definition
 * ============================================================================ */

typedef __sn__Json SnJson;

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/* Cast helpers for opaque pointer storage.
 * Fields use long long to prevent auto-free by the runtime release function. */
#define JSON_OBJ(j) ((json_object *)(uintptr_t)(j)->obj)
#define JSON_SET_OBJ(j, v) ((j)->obj = (long long)(uintptr_t)(v))

/* Create a new SnJson wrapper for a json-c object.
 * Returns a heap-allocated SnJson pointer. */
static __sn__Json *sn_json_wrap(json_object *obj, int is_root)
{
    __sn__Json *j = (__sn__Json *)calloc(1, sizeof(__sn__Json));
    if (j == NULL) {
        fprintf(stderr, "Json: memory allocation failed\n");
        exit(1);
    }
    JSON_SET_OBJ(j, obj);
    j->handle = 0;
    j->is_root = is_root;
    return j;
}

/* ============================================================================
 * Parsing Functions
 * ============================================================================ */

__sn__Json *sn_json_parse(char *text)
{
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
    return sn_json_wrap(obj, 1);
}

__sn__Json *sn_json_parse_file(char *path)
{
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

    return sn_json_wrap(obj, 1);
}

/* ============================================================================
 * Creation Functions
 * ============================================================================ */

__sn__Json *sn_json_new_object(void)
{
    json_object *obj = json_object_new_object();
    if (obj == NULL) {
        fprintf(stderr, "Json.object: failed to create object\n");
        exit(1);
    }
    return sn_json_wrap(obj, 1);
}

__sn__Json *sn_json_new_array(void)
{
    json_object *obj = json_object_new_array();
    if (obj == NULL) {
        fprintf(stderr, "Json.array: failed to create array\n");
        exit(1);
    }
    return sn_json_wrap(obj, 1);
}

__sn__Json *sn_json_new_null(void)
{
    /* json-c represents null as NULL pointer. */
    return sn_json_wrap(NULL, 1);
}

__sn__Json *sn_json_new_bool(bool value)
{
    json_object *obj = json_object_new_boolean(value);
    if (obj == NULL) {
        fprintf(stderr, "Json.bool: failed to create boolean\n");
        exit(1);
    }
    return sn_json_wrap(obj, 1);
}

__sn__Json *sn_json_new_int(long long value)
{
    json_object *obj = json_object_new_int64((int64_t)value);
    if (obj == NULL) {
        fprintf(stderr, "Json.int: failed to create integer\n");
        exit(1);
    }
    return sn_json_wrap(obj, 1);
}

__sn__Json *sn_json_new_float(double value)
{
    json_object *obj = json_object_new_double(value);
    if (obj == NULL) {
        fprintf(stderr, "Json.float: failed to create float\n");
        exit(1);
    }
    return sn_json_wrap(obj, 1);
}

__sn__Json *sn_json_new_string(char *value)
{
    json_object *obj = json_object_new_string(value ? value : "");
    if (obj == NULL) {
        fprintf(stderr, "Json.string: failed to create string\n");
        exit(1);
    }
    return sn_json_wrap(obj, 1);
}

/* ============================================================================
 * Type Checking Functions
 * ============================================================================ */

bool sn_json_is_object(__sn__Json *j)
{
    if (j == NULL) return false;
    if (JSON_OBJ(j) == NULL) return false;
    return json_object_is_type(JSON_OBJ(j), json_type_object);
}

bool sn_json_is_array(__sn__Json *j)
{
    if (j == NULL) return false;
    if (JSON_OBJ(j) == NULL) return false;
    return json_object_is_type(JSON_OBJ(j), json_type_array);
}

bool sn_json_is_string(__sn__Json *j)
{
    if (j == NULL) return false;
    if (JSON_OBJ(j) == NULL) return false;
    return json_object_is_type(JSON_OBJ(j), json_type_string);
}

bool sn_json_is_number(__sn__Json *j)
{
    if (j == NULL) return false;
    if (JSON_OBJ(j) == NULL) return false;
    return json_object_is_type(JSON_OBJ(j), json_type_int)
        || json_object_is_type(JSON_OBJ(j), json_type_double);
}

bool sn_json_is_int(__sn__Json *j)
{
    if (j == NULL) return false;
    if (JSON_OBJ(j) == NULL) return false;
    return json_object_is_type(JSON_OBJ(j), json_type_int);
}

bool sn_json_is_float(__sn__Json *j)
{
    if (j == NULL) return false;
    if (JSON_OBJ(j) == NULL) return false;
    return json_object_is_type(JSON_OBJ(j), json_type_double);
}

bool sn_json_is_bool(__sn__Json *j)
{
    if (j == NULL) return false;
    if (JSON_OBJ(j) == NULL) return false;
    return json_object_is_type(JSON_OBJ(j), json_type_boolean);
}

bool sn_json_is_null(__sn__Json *j)
{
    if (j == NULL) return true;
    if (JSON_OBJ(j) == NULL) return true;
    return json_object_is_type(JSON_OBJ(j), json_type_null);
}

/* ============================================================================
 * Value Extraction Functions
 * ============================================================================ */

char *sn_json_as_string(__sn__Json *j)
{
    if (j == NULL) return strdup("");
    if (JSON_OBJ(j) == NULL) return strdup("");
    if (!json_object_is_type(JSON_OBJ(j), json_type_string)) {
        return strdup("");
    }
    const char *str = json_object_get_string(JSON_OBJ(j));
    return strdup(str ? str : "");
}

long long sn_json_as_int(__sn__Json *j)
{
    if (j == NULL) return 0;
    if (JSON_OBJ(j) == NULL) return 0;
    if (!json_object_is_type(JSON_OBJ(j), json_type_int)
        && !json_object_is_type(JSON_OBJ(j), json_type_double)) return 0;
    return (long long)json_object_get_int64(JSON_OBJ(j));
}

long long sn_json_as_long(__sn__Json *j)
{
    if (j == NULL) return 0;
    if (JSON_OBJ(j) == NULL) return 0;
    if (!json_object_is_type(JSON_OBJ(j), json_type_int)
        && !json_object_is_type(JSON_OBJ(j), json_type_double)) return 0;
    return (long long)json_object_get_int64(JSON_OBJ(j));
}

double sn_json_as_float(__sn__Json *j)
{
    if (j == NULL) return 0.0;
    if (JSON_OBJ(j) == NULL) return 0.0;
    if (!json_object_is_type(JSON_OBJ(j), json_type_double)
        && !json_object_is_type(JSON_OBJ(j), json_type_int)) return 0.0;
    return json_object_get_double(JSON_OBJ(j));
}

bool sn_json_as_bool(__sn__Json *j)
{
    if (j == NULL) return false;
    if (JSON_OBJ(j) == NULL) return false;
    if (!json_object_is_type(JSON_OBJ(j), json_type_boolean)) return false;
    return json_object_get_boolean(JSON_OBJ(j));
}

/* ============================================================================
 * Object/Array Access Functions
 * ============================================================================ */

__sn__Json *sn_json_get(__sn__Json *j, char *key)
{
    if (j == NULL || key == NULL) {
        return sn_json_wrap(NULL, 0);
    }
    if (JSON_OBJ(j) == NULL) {
        return sn_json_wrap(NULL, 0);
    }
    if (!json_object_is_type(JSON_OBJ(j), json_type_object)) {
        return sn_json_wrap(NULL, 0);
    }

    json_object *val = NULL;
    if (!json_object_object_get_ex(JSON_OBJ(j), key, &val)) {
        return sn_json_wrap(NULL, 0);
    }

    /* Increment refcount - child wrapper owns a reference */
    if (val != NULL) {
        json_object_get(val);
    }
    return sn_json_wrap(val, 0);
}

bool sn_json_has(__sn__Json *j, char *key)
{
    if (j == NULL || key == NULL) return false;
    if (JSON_OBJ(j) == NULL) return false;
    if (!json_object_is_type(JSON_OBJ(j), json_type_object)) return false;
    return json_object_object_get_ex(JSON_OBJ(j), key, NULL);
}

SnArray *sn_json_keys(__sn__Json *j)
{
    SnArray *keys = sn_array_new(sizeof(char *), 16);
    keys->elem_tag = SN_TAG_STRING;
    keys->elem_release = (void (*)(void *))sn_cleanup_str;
    keys->elem_copy = sn_copy_str;

    if (j == NULL) return keys;
    if (JSON_OBJ(j) == NULL || !json_object_is_type(JSON_OBJ(j), json_type_object)) {
        return keys;
    }

    json_object_iter iter;
    json_object_object_foreachC(JSON_OBJ(j), iter) {
        char *key = strdup(iter.key ? iter.key : "");
        sn_array_push(keys, &key);
    }

    return keys;
}

__sn__Json *sn_json_get_at(__sn__Json *j, long long index)
{
    if (j == NULL) {
        return sn_json_wrap(NULL, 0);
    }
    if (JSON_OBJ(j) == NULL) {
        return sn_json_wrap(NULL, 0);
    }
    if (!json_object_is_type(JSON_OBJ(j), json_type_array)) {
        return sn_json_wrap(NULL, 0);
    }
    size_t len = json_object_array_length(JSON_OBJ(j));
    if (index < 0 || (size_t)index >= len) {
        return sn_json_wrap(NULL, 0);
    }

    json_object *val = json_object_array_get_idx(JSON_OBJ(j), (size_t)index);
    /* Increment refcount - child wrapper owns a reference */
    if (val != NULL) {
        json_object_get(val);
    }
    return sn_json_wrap(val, 0);
}

__sn__Json *sn_json_first(__sn__Json *j)
{
    if (j == NULL) {
        return sn_json_wrap(NULL, 0);
    }
    if (JSON_OBJ(j) == NULL || !json_object_is_type(JSON_OBJ(j), json_type_array)) {
        return sn_json_wrap(NULL, 0);
    }
    size_t len = json_object_array_length(JSON_OBJ(j));
    if (len == 0) {
        return sn_json_wrap(NULL, 0);
    }

    json_object *val = json_object_array_get_idx(JSON_OBJ(j), 0);
    if (val != NULL) {
        json_object_get(val);
    }
    return sn_json_wrap(val, 0);
}

__sn__Json *sn_json_last(__sn__Json *j)
{
    if (j == NULL) {
        return sn_json_wrap(NULL, 0);
    }
    if (JSON_OBJ(j) == NULL || !json_object_is_type(JSON_OBJ(j), json_type_array)) {
        return sn_json_wrap(NULL, 0);
    }
    size_t len = json_object_array_length(JSON_OBJ(j));
    if (len == 0) {
        return sn_json_wrap(NULL, 0);
    }

    json_object *val = json_object_array_get_idx(JSON_OBJ(j), len - 1);
    if (val != NULL) {
        json_object_get(val);
    }
    return sn_json_wrap(val, 0);
}

/* ============================================================================
 * Size Functions
 * ============================================================================ */

long long sn_json_length(__sn__Json *j)
{
    if (j == NULL) return 0;
    if (JSON_OBJ(j) == NULL) return 0;

    if (json_object_is_type(JSON_OBJ(j), json_type_object)) {
        return (long long)json_object_object_length(JSON_OBJ(j));
    }
    if (json_object_is_type(JSON_OBJ(j), json_type_array)) {
        return (long long)json_object_array_length(JSON_OBJ(j));
    }
    return 0;
}

/* ============================================================================
 * Mutation Functions (Object)
 * ============================================================================ */

void sn_json_set(__sn__Json *j, char *key, __sn__Json *value)
{
    if (j == NULL || key == NULL || value == NULL) {
        fprintf(stderr, "Json.set: invalid arguments\n");
        return;
    }
    if (JSON_OBJ(j) == NULL) {
        fprintf(stderr, "Json.set: invalid arguments\n");
        return;
    }
    if (!json_object_is_type(JSON_OBJ(j), json_type_object)) {
        fprintf(stderr, "Json.set: not an object\n");
        return;
    }

    /* Increment refcount — parent takes a shared reference */
    json_object *obj = JSON_OBJ(value);
    if (obj != NULL) {
        json_object_get(obj);
    }

    /* Remove existing key if present, then add new.
     * json_object_object_del frees the old value via json_object_put. */
    json_object_object_del(JSON_OBJ(j), key);
    json_object_object_add(JSON_OBJ(j), key, obj);
}

void sn_json_remove(__sn__Json *j, char *key)
{
    if (j == NULL || key == NULL) return;
    if (JSON_OBJ(j) == NULL) return;
    if (!json_object_is_type(JSON_OBJ(j), json_type_object)) return;

    /* json_object_object_del calls json_object_put on the removed value,
     * freeing it immediately if no other references exist. */
    json_object_object_del(JSON_OBJ(j), key);
}

/* ============================================================================
 * Mutation Functions (Array)
 * ============================================================================ */

void sn_json_append(__sn__Json *j, __sn__Json *value)
{
    if (j == NULL || value == NULL) {
        fprintf(stderr, "Json.append: invalid arguments\n");
        return;
    }
    if (JSON_OBJ(j) == NULL) {
        fprintf(stderr, "Json.append: invalid arguments\n");
        return;
    }
    if (!json_object_is_type(JSON_OBJ(j), json_type_array)) {
        fprintf(stderr, "Json.append: not an array\n");
        return;
    }

    /* Increment refcount — array takes a shared reference, caller keeps theirs.
     * json_object_put on either side decrements independently. */
    json_object *obj = JSON_OBJ(value);
    if (obj != NULL) {
        json_object_get(obj);
    }

    json_object_array_add(JSON_OBJ(j), obj);
}

void sn_json_prepend(__sn__Json *j, __sn__Json *value)
{
    if (j == NULL || value == NULL) {
        fprintf(stderr, "Json.prepend: invalid arguments\n");
        return;
    }
    if (JSON_OBJ(j) == NULL) {
        fprintf(stderr, "Json.prepend: invalid arguments\n");
        return;
    }
    if (!json_object_is_type(JSON_OBJ(j), json_type_array)) {
        fprintf(stderr, "Json.prepend: not an array\n");
        return;
    }

    json_object *obj = JSON_OBJ(value);
    if (obj != NULL) {
        json_object_get(obj);
    }

    json_object_array_insert_idx(JSON_OBJ(j), 0, obj);
}

void sn_json_insert(__sn__Json *j, long long index, __sn__Json *value)
{
    if (j == NULL || value == NULL) {
        fprintf(stderr, "Json.insert: invalid arguments\n");
        return;
    }
    if (JSON_OBJ(j) == NULL) {
        fprintf(stderr, "Json.insert: invalid arguments\n");
        return;
    }
    if (!json_object_is_type(JSON_OBJ(j), json_type_array)) {
        fprintf(stderr, "Json.insert: not an array\n");
        return;
    }

    json_object *obj = JSON_OBJ(value);
    if (obj != NULL) {
        json_object_get(obj);
    }

    json_object_array_insert_idx(JSON_OBJ(j), (size_t)index, obj);
}

void sn_json_remove_at(__sn__Json *j, long long index)
{
    if (j == NULL) return;
    if (JSON_OBJ(j) == NULL) return;
    if (!json_object_is_type(JSON_OBJ(j), json_type_array)) return;
    size_t len = json_object_array_length(JSON_OBJ(j));
    if (index < 0 || (size_t)index >= len) return;

    /* json_object_array_del_idx calls json_object_put on the removed element,
     * freeing it immediately if no other references exist. */
    json_object_array_del_idx(JSON_OBJ(j), (size_t)index, 1);
}

/* ============================================================================
 * Serialization Functions
 * ============================================================================ */

char *sn_json_to_string(__sn__Json *j)
{
    if (j == NULL) return strdup("null");
    if (JSON_OBJ(j) == NULL) return strdup("null");

    /* json_object_to_json_string_ext returns internal buffer - copy it */
    const char *str = json_object_to_json_string_ext(JSON_OBJ(j), JSON_C_TO_STRING_PLAIN);
    if (str == NULL) return strdup("null");

    return strdup(str);
}

char *sn_json_to_pretty_string(__sn__Json *j)
{
    if (j == NULL) return strdup("null");
    if (JSON_OBJ(j) == NULL) return strdup("null");

    const char *str = json_object_to_json_string_ext(JSON_OBJ(j), JSON_C_TO_STRING_PRETTY);
    if (str == NULL) return strdup("null");

    return strdup(str);
}

void sn_json_write_file(__sn__Json *j, char *path)
{
    if (j == NULL || path == NULL) {
        fprintf(stderr, "Json.writeFile: invalid arguments\n");
        return;
    }
    if (JSON_OBJ(j) == NULL) {
        fprintf(stderr, "Json.writeFile: invalid arguments\n");
        return;
    }

    if (json_object_to_file_ext(path, JSON_OBJ(j), JSON_C_TO_STRING_PLAIN) != 0) {
        const char *err = json_util_get_last_err();
        fprintf(stderr, "Json.writeFile: %s (file: %s)\n",
                err ? err : "unknown error", path);
    }
}

void sn_json_write_file_pretty(__sn__Json *j, char *path)
{
    if (j == NULL || path == NULL) {
        fprintf(stderr, "Json.writeFilePretty: invalid arguments\n");
        return;
    }
    if (JSON_OBJ(j) == NULL) {
        fprintf(stderr, "Json.writeFilePretty: invalid arguments\n");
        return;
    }

    if (json_object_to_file_ext(path, JSON_OBJ(j), JSON_C_TO_STRING_PRETTY) != 0) {
        const char *err = json_util_get_last_err();
        fprintf(stderr, "Json.writeFilePretty: %s (file: %s)\n",
                err ? err : "unknown error", path);
    }
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

__sn__Json *sn_json_copy(__sn__Json *j)
{
    if (j == NULL) {
        return sn_json_new_null();
    }
    if (JSON_OBJ(j) == NULL) {
        return sn_json_new_null();
    }

    json_object *copy = NULL;
    if (json_object_deep_copy(JSON_OBJ(j), &copy, NULL) != 0) {
        fprintf(stderr, "Json.copy: failed to deep copy\n");
        exit(1);
    }

    return sn_json_wrap(copy, 1);
}

char *sn_json_type_name(__sn__Json *j)
{
    if (j == NULL) return strdup("null");
    if (JSON_OBJ(j) == NULL) return strdup("null");

    if (json_object_is_type(JSON_OBJ(j), json_type_object))  return strdup("object");
    if (json_object_is_type(JSON_OBJ(j), json_type_array))   return strdup("array");
    if (json_object_is_type(JSON_OBJ(j), json_type_string))  return strdup("string");
    if (json_object_is_type(JSON_OBJ(j), json_type_boolean)) return strdup("bool");
    if (json_object_is_type(JSON_OBJ(j), json_type_null))    return strdup("null");
    if (json_object_is_type(JSON_OBJ(j), json_type_int))     return strdup("number");
    if (json_object_is_type(JSON_OBJ(j), json_type_double))  return strdup("number");

    return strdup("unknown");
}

/* ============================================================================
 * Dispose Function
 * ============================================================================
 * Releases the json-c reference immediately. Only frees internal resources --
 * the struct itself is freed by sn_auto_Json cleanup.
 * ============================================================================ */

void sn_json_dispose(__sn__Json *j)
{
    if (j == NULL) return;

    if (JSON_OBJ(j) != NULL) {
        json_object_put(JSON_OBJ(j));
        JSON_SET_OBJ(j, NULL);
    }
}
