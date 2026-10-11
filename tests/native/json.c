#undef NDEBUG
#define SN_SDK_JSON_STANDALONE 1
#include "json.native.h"
#include "sn_abi.h"
#include <json-c/json.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int wire_destroyed, object_destroyed;
static void destroy_wire(void *value, uintptr_t context)
{
    assert(context == 37);
    wire_destroyed++;
    sn_sdk_json_release(value);
}
static void destroy_object(struct json_object *value, void *context)
{
    (void)value;
    assert(context == &object_destroyed);
    object_destroyed++;
}
int main(void)
{
    _Static_assert(sizeof(SnSdkJsonRecord) == 32, "Json canonical layout");
    assert(sn_sdk_json_refs(NULL) == 0 && sn_sdk_json_retain(NULL) == NULL);
    /* Legacy Json.copy(nil) produces a non-nil Json null wrapper. */
    SnSdkJsonRecord *nil_copy = sn_sdk_json_copy(NULL);
    assert(nil_copy && sn_json_is_null(nil_copy) && sn_sdk_json_refs(nil_copy) == 1);
    sn_sdk_json_release(nil_copy);
    sn_sdk_json_release(NULL);
    SnSdkJsonRecord *empty = sn_sdk_json_create();
    assert(empty && empty->obj == 0 && empty->handle == 0 && empty->is_root == 0);
    sn_sdk_json_release(empty);
    SnSdkJsonRecord *root = sn_json_parse("{\"child\":{\"count\":7},\"text\":\"saved\"}");
    SnSdkJsonRecord *alias = sn_sdk_json_retain(root);
    assert(alias == root && sn_sdk_json_refs(root) == 2);
    SnSdkJsonRecord *child = sn_json_get(alias, "child");
    SnSdkJsonRecord *copy = sn_sdk_json_copy(root);
    assert(copy != root && copy->obj != root->obj && sn_sdk_json_refs(copy) == 1);
    SnSdkJsonRecord *copy_child = sn_json_get(copy, "child");
    SnSdkJsonRecord *number = sn_json_new_int(19);
    sn_json_set(copy_child, "count", number);
    sn_sdk_json_release(number);
    SnSdkJsonRecord *count = sn_json_get(child, "count");
    assert(sn_json_as_int(count) == 7);
    sn_sdk_json_release(count);
    count = sn_json_get(copy_child, "count");
    assert(sn_json_as_int(count) == 19);
    sn_sdk_json_release(count);
    sn_sdk_json_release(copy_child);
    sn_sdk_json_release(copy);
    SnSdkJsonRecord *text_value = sn_json_get(root, "text");
    char *text = sn_json_as_string(text_value);
    sn_sdk_json_release(text_value);
    SnArray *keys = sn_json_keys(root);
    assert(keys->len == 2);
    sn_array_free(keys);
    sn_json_remove(alias, "child");
    sn_sdk_json_release(alias);
    SnAbiValue *wire = NULL;
    assert(sn_abi_v1_resource_new_typed("SindarinSDK/sindarin-pkg-sdk:encoding.Json@1", root, destroy_wire, 37, &wire) == 0);
    SnAbiValue *credit = sn_abi_v1_retain(wire);
    sn_abi_v1_release(wire);
    assert(wire_destroyed == 0);
    sn_abi_v1_release(credit);
    assert(wire_destroyed == 1);
    count = sn_json_get(child, "count");
    assert(sn_json_as_int(count) == 7);
    sn_sdk_json_release(count);
    sn_sdk_json_release(child);
    assert(!strcmp(text, "saved"));
    free(text);
    SnSdkJsonRecord *null_value = sn_json_new_null();
    copy = sn_sdk_json_copy(null_value);
    assert(copy != null_value && sn_json_is_null(copy));
    sn_sdk_json_release(copy);
    sn_json_dispose(null_value);
    sn_json_dispose(null_value);
    sn_sdk_json_release(null_value);
    SnSdkJsonRecord *array = sn_json_new_array();
    child = sn_json_new_string("array child");
    sn_json_append(array, child);
    sn_sdk_json_release(child);
    child = sn_json_first(array);
    SnSdkJsonRecord *last = sn_json_last(array);
    sn_json_remove_at(array, 0);
    sn_sdk_json_release(array);
    text = sn_json_as_string(child);
    assert(!strcmp(text, "array child"));
    free(text);
    text = sn_json_as_string(last);
    assert(!strcmp(text, "array child"));
    free(text);
    sn_sdk_json_release(child);
    sn_sdk_json_release(last);
    for (int i = 0; i < 40; i++) {
        root = sn_json_new_object();
        child = sn_json_new_object();
        json_object_set_userdata((struct json_object *)(uintptr_t)child->obj, &object_destroyed, destroy_object);
        sn_json_set(root, "child", child);
        SnSdkJsonRecord *saved = sn_json_get(root, "child");
        sn_sdk_json_release(child);
        sn_json_dispose(root);
        sn_json_dispose(root);
        sn_sdk_json_release(root);
        assert(object_destroyed == i);
        sn_sdk_json_release(saved);
        assert(object_destroyed == i + 1);
    }
    puts("SDK canonical Json: pass");
}
