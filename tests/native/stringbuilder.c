#undef NDEBUG
#define SN_SDK_TEXT_STANDALONE 1
#include "text.native.h"
#include "sn_abi.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int destroyed;
static void destroy_builder(void *value,uintptr_t context)
{
    assert(context==31);destroyed++;sn_sdk_text_release(value);
}
int main(void)
{
    _Static_assert(sizeof(SnSdkStringBuilderRecord)==32,"StringBuilder canonical layout");
    assert(sn_sdk_text_retain(NULL)==NULL && sn_sdk_text_refs(NULL)==0);sn_sdk_text_release(NULL);
    SnSdkStringBuilderRecord *empty=sn_sdk_text_create();assert(empty && empty->buf==0 && sn_sdk_text_refs(empty)==1);sn_sdk_text_release(empty);
    SnSdkStringBuilderRecord *builder=sn_text_new_with_capacity(2);
    assert(builder && builder->cap==2 && sn_sdk_text_refs(builder)==1);
    SnSdkStringBuilderRecord *alias=sn_sdk_text_retain(builder);assert(alias==builder && sn_sdk_text_refs(builder)==2);
    sn_text_append(alias,"hello");sn_text_append_int(alias,42);sn_text_append_bool(alias,true);
    assert(sn_text_length(builder)==11 && builder->cap>=12);
    assert(sn_sdk_text_copy(NULL)==NULL);
    SnSdkStringBuilderRecord *copy=sn_sdk_text_copy(builder);
    assert(copy && copy!=builder && copy->buf!=builder->buf && copy->len==builder->len && sn_sdk_text_refs(copy)==1);
    sn_text_append(copy,"copy");assert(sn_text_length(builder)==11 && sn_text_length(copy)==15);sn_sdk_text_release(copy);
    char *text=sn_text_to_string(builder);assert(!strcmp(text,"hello42true"));
    sn_text_clear(alias);assert(builder->len==0 && builder->buf!=0 && !strcmp(text,"hello42true"));
    sn_text_append(builder,"second");
    SnAbiValue *wire=NULL;assert(sn_abi_v1_resource_new_typed("SindarinSDK/sindarin-pkg-sdk:encoding.StringBuilder@1",builder,destroy_builder,31,&wire)==0);
    SnAbiValue *credit=sn_abi_v1_retain(wire);sn_sdk_text_release(alias);sn_abi_v1_release(wire);assert(destroyed==0);
    void *pointer=NULL;assert(sn_abi_v1_resource_data_typed(credit,"SindarinSDK/sindarin-pkg-sdk:encoding.StringBuilder@1",&pointer)==0 && pointer==builder);
    assert(sn_sdk_text_refs(pointer)==1 && ((SnSdkStringBuilderRecord *)pointer)->len==6);
    sn_abi_v1_release(credit);assert(destroyed==1 && !strcmp(text,"hello42true"));free(text);
    builder=sn_text_new();sn_text_append(builder,"manual");sn_text_dispose(builder);sn_text_dispose(builder);
    assert(builder->buf==0 && builder->cap==0 && builder->len==0);sn_sdk_text_release(builder);
    for(int i=0;i<40;i++){builder=sn_text_new();sn_text_append(builder,"last credit");sn_sdk_text_release(builder);}
    puts("SDK canonical StringBuilder: pass");
}
