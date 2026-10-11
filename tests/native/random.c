#undef NDEBUG
#define SN_SDK_RANDOM_STANDALONE 1
#include "random.native.h"
#include "sn_abi.h"
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int destroyed;
static void destroy_random(void *value, uintptr_t context)
{
    assert(context == 23);
    destroyed++;
    sn_sdk_random_release(value);
}
static void *retain_random(void *value)
{
    for (int i = 0; i < 10000; i++) {
        assert(sn_sdk_random_retain(value) == value);
        sn_sdk_random_release(value);
    }
    return NULL;
}
int main(void)
{
    _Static_assert(sizeof(SnSdkRandomRecord) == 16, "Random layout on supported 64-bit targets");
    assert(sn_sdk_random_refs(NULL) == 0 && sn_sdk_random_retain(NULL) == NULL);
    sn_sdk_random_release(NULL);
    SnSdkRandomRecord *empty = sn_sdk_random_create();
    assert(empty && empty->state == 0 && sn_sdk_random_refs(empty) == 1);
    sn_sdk_random_release(empty);
    SnSdkRandomRecord *rng = sn_random_create_with_seed(42);
    SnSdkRandomRecord *same = sn_random_create_with_seed(42);
    assert(rng && same && rng->is_seeded == 1 && rng->state != 0);
    pthread_t threads[4];
    for (int i = 0; i < 4; i++) assert(pthread_create(&threads[i], NULL, retain_random, rng) == 0);
    for (int i = 0; i < 4; i++) assert(pthread_join(threads[i], NULL) == 0);
    assert(sn_sdk_random_refs(rng) == 1);
    SnSdkRandomRecord *alias = sn_sdk_random_retain(rng);
    assert(alias == rng && alias->state == rng->state && sn_sdk_random_refs(rng) == 2);
    SnArray *numbers = sn_random_int_many(alias, 10, 20, 4);
    for (int i = 0; i < 4; i++) assert(*(long long *)sn_array_get(numbers, i) == sn_random_int(same, 10, 20));
    SnArray *booleans = sn_random_bool_many(rng, 9);
    assert(booleans && booleans->elem_size == sizeof(bool) && sn_array_length(booleans) == 9);
    SnArray *bytes = sn_random_bytes(rng, 7);
    assert(bytes && bytes->elem_size == 1 && sn_array_length(bytes) == 7);
    sn_array_free(booleans); sn_array_free(bytes);
    SnArray *values = sn_array_new(sizeof(char *), 2);
    values->elem_tag = SN_TAG_STRING;
    values->elem_release = (void (*)(void *))sn_cleanup_str;
    values->elem_copy = sn_copy_str;
    char *a = strdup("alpha"), *b = strdup("beta");
    sn_array_push(values, &a); sn_array_push(values, &b);
    SnArray *texts = sn_random_sample_str(rng, values, 2);
    sn_array_free(values);
    assert(texts && texts->elem_release && texts->elem_copy);
    assert((!strcmp(*(char **)sn_array_get(texts, 0), "alpha") && !strcmp(*(char **)sn_array_get(texts, 1), "beta")) ||
           (!strcmp(*(char **)sn_array_get(texts, 0), "beta") && !strcmp(*(char **)sn_array_get(texts, 1), "alpha")));
    SnAbiValue *wire = NULL;
    assert(sn_abi_v1_resource_new_typed("SindarinSDK/sindarin-pkg-sdk:core.Random@1", rng, destroy_random, 23, &wire) == 0);
    SnAbiValue *credit = sn_abi_v1_retain(wire);
    void *pointer = NULL;
    assert(sn_abi_v1_resource_data_typed(credit, "SindarinSDK/sindarin-pkg-sdk:core.Random@1", &pointer) == 0 && pointer == rng);
    sn_sdk_random_release(alias); sn_abi_v1_release(wire);
    assert(destroyed == 0 && sn_sdk_random_refs(pointer) == 1);
    sn_abi_v1_release(credit); assert(destroyed == 1);
    assert(sn_array_length(numbers) == 4 && *(long long *)sn_array_get(numbers, 0) >= 10);
    sn_array_free(numbers); sn_array_free(texts);
    sn_random_free(same); sn_random_free(same);
    assert(same->state == 0 && same->is_seeded == 0);
    sn_sdk_random_release(same);
    for (int i = 0; i < 40; i++) {
        SnSdkRandomRecord *next = sn_random_create_with_seed(i);
        assert(sn_sdk_random_refs(next) == 1 && next->state != 0);
        sn_sdk_random_release(next);
    }
    puts("SDK canonical Random: pass");
    return 0;
}
