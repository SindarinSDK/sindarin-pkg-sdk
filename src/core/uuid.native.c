/* Canonical C UUID storage; original operations remain in uuid.sn.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define SN_SDK_UUID_STANDALONE 1
#include "uuid.sn.c"
SnSdkUuidRecord *sn_sdk_uuid_create(void) { return sn_sdk_uuid_new(); }
int sn_sdk_uuid_refs(SnSdkUuidRecord *value) { return value ? __atomic_load_n(&value->__rc__, __ATOMIC_RELAXED) : 0; }
SnSdkUuidRecord *sn_sdk_uuid_retain(SnSdkUuidRecord *value)
{
    if (value) __atomic_fetch_add(&value->__rc__, 1, __ATOMIC_RELAXED);
    return value;
}
void sn_sdk_uuid_release(SnSdkUuidRecord *value)
{
    if (value && __atomic_sub_fetch(&value->__rc__, 1, __ATOMIC_ACQ_REL) == 0) free(value);
}
SnSdkUuidRecord *sn_sdk_uuid_copy(const SnSdkUuidRecord *value)
{
    if (!value) return NULL;
    SnSdkUuidRecord *copy = sn_sdk_uuid_create();
    if (copy) { copy->high = value->high; copy->low = value->low; }
    return copy;
}
