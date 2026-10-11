/* Independent canonical C module; operation bodies remain in date.sn.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define SN_SDK_DATE_STANDALONE 1
#include "date.sn.c"

SnSdkDateRecord *sn_sdk_date_create(void) { return sn_sdk_date_new(); }
int sn_sdk_date_refs(SnSdkDateRecord *value) { return value ? __atomic_load_n(&value->__rc__, __ATOMIC_RELAXED) : 0; }
SnSdkDateRecord *sn_sdk_date_retain(SnSdkDateRecord *value)
{
    if (value) __atomic_fetch_add(&value->__rc__, 1, __ATOMIC_RELAXED);
    return value;
}
void sn_sdk_date_release(SnSdkDateRecord *value)
{
    if (value && __atomic_sub_fetch(&value->__rc__, 1, __ATOMIC_ACQ_REL) == 0) free(value);
}
