/* Canonical C Process storage; original operations remain in process.sn.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define SN_SDK_PROCESS_STANDALONE 1
#include "process.sn.c"
SnSdkProcessRecord *sn_sdk_process_create(void) { return sn_sdk_process_new(); }
int sn_sdk_process_refs(SnSdkProcessRecord *value) { return value ? __atomic_load_n(&value->__rc__,__ATOMIC_RELAXED) : 0; }
SnSdkProcessRecord *sn_sdk_process_retain(SnSdkProcessRecord *value)
{
    if(value) __atomic_fetch_add(&value->__rc__,1,__ATOMIC_RELAXED);
    return value;
}
void sn_sdk_process_release(SnSdkProcessRecord *value)
{
    if(value && __atomic_sub_fetch(&value->__rc__,1,__ATOMIC_ACQ_REL)==0) {
        free(value->stdout_str);free(value->stderr_str);free(value);
    }
}
SnSdkProcessRecord *sn_sdk_process_copy(const SnSdkProcessRecord *value)
{
    if(!value) return NULL;
    SnSdkProcessRecord *copy=sn_sdk_process_create();
    if(!copy) return NULL;
    copy->exit_code=value->exit_code;
    copy->stdout_str=value->stdout_str ? strdup(value->stdout_str) : NULL;
    copy->stderr_str=value->stderr_str ? strdup(value->stderr_str) : NULL;
    if((value->stdout_str && !copy->stdout_str) || (value->stderr_str && !copy->stderr_str)) {
        sn_sdk_process_release(copy);return NULL;
    }
    return copy;
}
