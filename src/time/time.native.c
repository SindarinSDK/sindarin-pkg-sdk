/* Independent canonical C module; operation bodies remain in time.sn.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define SN_SDK_TIME_STANDALONE 1
#include "time.sn.c"

SnSdkTimeRecord *sn_sdk_time_create(void) { return sn_sdk_time_new(); }
int sn_sdk_time_refs(SnSdkTimeRecord *value) { return value ? __atomic_load_n(&value->__rc__, __ATOMIC_RELAXED) : 0; }
SnSdkTimeRecord *sn_sdk_time_retain(SnSdkTimeRecord *value)
{
    if (value) __atomic_fetch_add(&value->__rc__, 1, __ATOMIC_RELAXED);
    return value;
}
void sn_sdk_time_release(SnSdkTimeRecord *value)
{
    if (value && __atomic_sub_fetch(&value->__rc__, 1, __ATOMIC_ACQ_REL) == 0) free(value);
}
