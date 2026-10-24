#undef NDEBUG
#define SN_SDK_YAML_STANDALONE 1
#include "encoding/yaml.native.h"
#include "sn_abi.h"
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void text_is(SnSdkYamlRecord *value, const char *expected)
{
    char *text = sn_yaml_value(value);
    assert(text && strcmp(text, expected) == 0);
    free(text);
}
static void *credits(void *pointer)
{
    for (int i = 0; i < 10000; i++) {
        assert(sn_sdk_yaml_retain(pointer) == pointer);
        sn_sdk_yaml_release(pointer);
    }
    return NULL;
}
static int destroyed;
static void destroy(void *pointer, uintptr_t context)
{
    assert(context == 17);
    destroyed++;
    sn_sdk_yaml_release(pointer);
}
int main(void)
{
    assert(sizeof(SnSdkYamlRecord) == 40 && offsetof(SnSdkYamlRecord, root) == 8);
    assert(offsetof(SnSdkYamlRecord, node) == 16 && offsetof(SnSdkYamlRecord, is_root) == 24);
    assert(offsetof(SnSdkYamlRecord, handle) == 32);
    assert(sn_sdk_yaml_retain(NULL) == NULL && sn_sdk_yaml_refs(NULL) == 0);
    sn_sdk_yaml_release(NULL);
    SnSdkYamlRecord *nil_copy = sn_sdk_yaml_copy(NULL);
    assert(nil_copy && nil_copy->node && nil_copy->is_root == 1);
    text_is(nil_copy, "");
    sn_sdk_yaml_release(nil_copy);
    SnSdkYamlRecord *empty = sn_sdk_yaml_create();
    assert(empty && sn_sdk_yaml_refs(empty) == 1 && !empty->root && !empty->node && !empty->handle);
    sn_sdk_yaml_release(empty);

    SnSdkYamlRecord *root = sn_yaml_parse("name: first\nsequence: [one, two]\n");
    SnSdkYamlRecord *name = sn_yaml_get(root, "name");
    SnSdkYamlRecord *sequence = sn_yaml_get(root, "sequence");
    SnSdkYamlRecord *first = sn_yaml_first(sequence);
    SnSdkYamlRecord *last = sn_yaml_last(sequence);
    SnArray *keys = sn_yaml_keys(root);
    assert(keys && keys->len == 2 && root->handle == 0 && name->handle == 0);
    SnSdkYamlRecord *copy = sn_sdk_yaml_copy(root);
    SnSdkYamlRecord *replacement = sn_yaml_scalar("second");
    sn_yaml_set(root, "name", replacement);
    assert(replacement->is_root == 0 && replacement->root == 0);
    text_is(name, "first");
    sn_sdk_yaml_release(replacement);
    sn_yaml_remove(root, "name");
    text_is(name, "first");
    SnSdkYamlRecord *alias = sn_sdk_yaml_retain(root);
    assert(alias == root && sn_sdk_yaml_refs(root) == 2);
    sn_yaml_dispose(root);
    sn_yaml_dispose(alias);
    assert(!alias->root && !alias->node && alias->is_root == 1);
    sn_sdk_yaml_release(root);
    sn_sdk_yaml_release(alias);
    assert(strcmp(((char **)keys->data)[0], "name") == 0);
    text_is(first, "one");
    text_is(last, "two");
    sn_yaml_remove_at(sequence, 0);
    text_is(first, "one");
    sn_yaml_remove_at(sequence, 0);
    text_is(last, "two");
    sn_sdk_yaml_release(sequence);
    sn_sdk_yaml_release(first);
    sn_sdk_yaml_release(last);
    sn_sdk_yaml_release(name);
    sn_array_free(keys);
    name = sn_yaml_get(copy, "name");
    text_is(name, "first");
    sn_sdk_yaml_release(copy);
    text_is(name, "first");
    sn_sdk_yaml_release(name);

    root = sn_yaml_sequence();
    SnSdkYamlRecord *scalar = sn_yaml_scalar("shared");
    sn_yaml_append(root, scalar);
    sn_yaml_prepend(root, scalar);
    assert(sn_yaml_length(root) == 2);
    first = sn_yaml_get_at(root, 0);
    last = sn_yaml_get_at(root, 1);
    assert(first->node == last->node && first->node == scalar->node);
    sn_yaml_dispose(scalar); /* Transferred children retain their legacy no-op dispose. */
    text_is(scalar, "shared");
    sn_sdk_yaml_release(scalar);
    sn_sdk_yaml_release(root);
    text_is(first, "shared");
    sn_sdk_yaml_release(first);
    text_is(last, "shared");
    sn_sdk_yaml_release(last);

    root = sn_yaml_scalar("threaded");
    pthread_t workers[4];
    for (int i = 0; i < 4; i++) assert(pthread_create(&workers[i], NULL, credits, root) == 0);
    for (int i = 0; i < 4; i++) assert(pthread_join(workers[i], NULL) == 0);
    assert(sn_sdk_yaml_refs(root) == 1);
    SnAbiValue *wire = NULL;
    assert(sn_abi_v1_resource_new_typed("sdk/Yaml@1", root, destroy, 17, &wire) == 0);
    SnAbiValue *wire_alias = sn_abi_v1_retain(wire);
    sn_abi_v1_release(wire);
    assert(destroyed == 0);
    void *pointer = NULL;
    assert(sn_abi_v1_resource_data_typed(wire_alias, "sdk/Yaml@1", &pointer) == 0 && pointer == root);
    sn_sdk_yaml_retain(pointer);
    sn_abi_v1_release(wire_alias);
    assert(destroyed == 1);
    text_is(pointer, "threaded");
    sn_sdk_yaml_release(pointer);
    puts("SDK canonical Yaml: pass");
}
