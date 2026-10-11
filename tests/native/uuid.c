#undef NDEBUG
#define SN_SDK_UUID_STANDALONE 1
#include "uuid.native.h"
#include "sn_abi.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int destroyed;
static void destroy_uuid(void *value, uintptr_t context)
{
    assert(context == 29);
    destroyed++;
    sn_sdk_uuid_release(value);
}
int main(void)
{
    _Static_assert(sizeof(SnSdkUuidRecord) == 24, "UUID canonical layout");
    assert(sn_sdk_uuid_refs(NULL)==0 && sn_sdk_uuid_retain(NULL)==NULL);
    sn_sdk_uuid_release(NULL);
    SnSdkUuidRecord *empty=sn_sdk_uuid_create();
    assert(empty && sn_sdk_uuid_refs(empty)==1 && empty->high==0 && empty->low==0);
    sn_sdk_uuid_release(empty);
    SnSdkUuidRecord *dns=sn_uuid_namespace_dns();
    assert(dns && sn_sdk_uuid_refs(dns)==1);
    assert(sn_sdk_uuid_copy(NULL)==NULL);
    SnSdkUuidRecord *copy=sn_sdk_uuid_copy(dns);
    assert(copy && copy!=dns && sn_sdk_uuid_refs(copy)==1 && copy->high==dns->high && copy->low==dns->low);
    copy->high=3;assert(copy->high!=dns->high);
    sn_sdk_uuid_release(copy);
    SnSdkUuidRecord *alias=sn_sdk_uuid_retain(dns);
    assert(alias==dns && sn_sdk_uuid_refs(dns)==2);
    SnSdkUuidRecord *derived=sn_uuid_v5(alias,"example.com");
    char *text=sn_uuid_to_string(derived);
    assert(!strcmp(text,"cfbff0d1-9375-5685-968c-48ce8b15ae17"));
    assert(sn_uuid_get_version(derived)==5 && sn_uuid_get_variant(derived)==1);
    char *hex=sn_uuid_to_hex(derived), *base64=sn_uuid_to_base64(derived);
    SnSdkUuidRecord *from_hex=sn_uuid_from_hex(hex), *from_base64=sn_uuid_from_base64(base64);
    assert(sn_uuid_equals(derived,from_hex) && sn_uuid_equals(derived,from_base64));
    sn_sdk_uuid_release(from_hex);sn_sdk_uuid_release(from_base64);
    free(hex);free(base64);
    SnAbiValue *wire=NULL;
    assert(sn_abi_v1_resource_new_typed("SindarinSDK/sindarin-pkg-sdk:core.UUID@1",dns,destroy_uuid,29,&wire)==0);
    SnAbiValue *credit=sn_abi_v1_retain(wire);
    void *pointer=NULL;
    assert(sn_abi_v1_resource_data_typed(credit,"SindarinSDK/sindarin-pkg-sdk:core.UUID@1",&pointer)==0 && pointer==dns);
    sn_sdk_uuid_release(alias);sn_abi_v1_release(wire);
    assert(destroyed==0 && sn_sdk_uuid_refs(pointer)==1);
    sn_abi_v1_release(credit);assert(destroyed==1);
    assert(!strcmp(text,"cfbff0d1-9375-5685-968c-48ce8b15ae17"));
    free(text);sn_sdk_uuid_release(derived);
    for(int i=0;i<40;i++) {
        SnSdkUuidRecord *values[]={sn_uuid_namespace_dns(),sn_uuid_namespace_url(),sn_uuid_namespace_oid(),sn_uuid_namespace_x500()};
        for(int j=0;j<4;j++){assert(sn_sdk_uuid_refs(values[j])==1);sn_sdk_uuid_release(values[j]);}
    }
    SnSdkUuidRecord *v4=sn_uuid_v4(), *v7=sn_uuid_v7();
    assert(sn_uuid_get_version(v4)==4 && sn_uuid_get_variant(v4)==1);
    assert(sn_uuid_get_version(v7)==7 && sn_uuid_get_variant(v7)==1);
    sn_sdk_uuid_release(v4);sn_sdk_uuid_release(v7);
    puts("SDK canonical UUID: pass");
}
