/* Canonical C StringBuilder storage; original operations remain in text.sn.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define SN_SDK_TEXT_STANDALONE 1
#include "text.sn.c"
SnSdkStringBuilderRecord *sn_sdk_text_create(void) { return sn_sdk_text_new(); }
int sn_sdk_text_refs(SnSdkStringBuilderRecord *value) { return value ? __atomic_load_n(&value->__rc__,__ATOMIC_RELAXED) : 0; }
SnSdkStringBuilderRecord *sn_sdk_text_retain(SnSdkStringBuilderRecord *value)
{
    if(value) __atomic_fetch_add(&value->__rc__,1,__ATOMIC_RELAXED);
    return value;
}
void sn_sdk_text_release(SnSdkStringBuilderRecord *value)
{
    if(value && __atomic_sub_fetch(&value->__rc__,1,__ATOMIC_ACQ_REL)==0) {
        sn_text_dispose(value);
        free(value);
    }
}
SnSdkStringBuilderRecord *sn_sdk_text_copy(const SnSdkStringBuilderRecord *value)
{
    if(!value) return NULL;
    SnSdkStringBuilderRecord *copy=sn_sdk_text_create();
    if(!copy) return NULL;
    if(value->buf) {
        char *buffer=malloc((size_t)value->cap);
        if(!buffer) { sn_sdk_text_release(copy);return NULL; }
        memcpy(buffer,(const void *)(uintptr_t)value->buf,(size_t)value->len+1);
        copy->buf=(long long)(uintptr_t)buffer;
        copy->cap=value->cap;
        copy->len=value->len;
    }
    return copy;
}
