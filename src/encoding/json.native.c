/* Canonical C Json storage; original operations remain in json.sn.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define SN_SDK_JSON_STANDALONE 1
#include "json.sn.c"
SnSdkJsonRecord *sn_sdk_json_create(void) { return sn_sdk_json_new(); }
int sn_sdk_json_refs(SnSdkJsonRecord *value) { return value ? __atomic_load_n(&value->__rc__, __ATOMIC_RELAXED) : 0; }
SnSdkJsonRecord *sn_sdk_json_retain(SnSdkJsonRecord *value)
{
    if (value) __atomic_fetch_add(&value->__rc__, 1, __ATOMIC_RELAXED);
    return value;
}
void sn_sdk_json_release(SnSdkJsonRecord *value)
{
    if (value && __atomic_sub_fetch(&value->__rc__, 1, __ATOMIC_ACQ_REL) == 0) {
        sn_json_dispose(value);
        free(value);
    }
}
SnSdkJsonRecord *sn_sdk_json_copy(const SnSdkJsonRecord *value)
{
    return sn_json_copy((SnSdkJsonRecord *)value);
}
