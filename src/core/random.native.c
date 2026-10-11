/* Canonical C storage; original operations remain in random.sn.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define SN_SDK_RANDOM_STANDALONE 1
#include "random.sn.c"

SnSdkRandomRecord *sn_sdk_random_create(void) { return sn_sdk_random_new(); }
int sn_sdk_random_refs(SnSdkRandomRecord *value) { return value ? __atomic_load_n(&value->__rc__, __ATOMIC_RELAXED) : 0; }
SnSdkRandomRecord *sn_sdk_random_retain(SnSdkRandomRecord *value)
{
    if (value) __atomic_fetch_add(&value->__rc__, 1, __ATOMIC_RELAXED);
    return value;
}
void sn_sdk_random_release(SnSdkRandomRecord *value)
{
    if (value && __atomic_sub_fetch(&value->__rc__, 1, __ATOMIC_ACQ_REL) == 0) {
        sn_random_free(value);
        free(value);
    }
}
