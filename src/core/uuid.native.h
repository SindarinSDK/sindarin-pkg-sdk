#ifndef SN_SDK_UUID_NATIVE_H
#define SN_SDK_UUID_NATIVE_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
typedef struct { int __rc__; long long high; long long low; } SnSdkUuidRecord;
#ifdef __cplusplus
extern "C" {
#endif
SnSdkUuidRecord *sn_sdk_uuid_create(void);
SnSdkUuidRecord *sn_sdk_uuid_retain(SnSdkUuidRecord *);
SnSdkUuidRecord *sn_sdk_uuid_copy(const SnSdkUuidRecord *);
void sn_sdk_uuid_release(SnSdkUuidRecord *);
int sn_sdk_uuid_refs(SnSdkUuidRecord *);
#ifdef __cplusplus
}
#endif
#endif
#if defined(SN_SDK_UUID_STANDALONE) && !defined(SN_SDK_UUID_OPERATIONS_DECLARED)
#define SN_SDK_UUID_OPERATIONS_DECLARED 1
#ifdef __cplusplus
extern "C" {
#endif
SnSdkUuidRecord *sn_uuid_v4(void);
SnSdkUuidRecord *sn_uuid_v5(SnSdkUuidRecord *namespace_uuid, char *name);
SnSdkUuidRecord *sn_uuid_v7(void);
SnSdkUuidRecord *sn_uuid_create(void);
long long sn_uuid_get_version(SnSdkUuidRecord *uuid);
long long sn_uuid_get_variant(SnSdkUuidRecord *uuid);
bool sn_uuid_is_nil(SnSdkUuidRecord *uuid);
long long sn_uuid_get_timestamp(SnSdkUuidRecord *uuid);
char *sn_uuid_to_string(SnSdkUuidRecord *uuid);
char *sn_uuid_to_hex(SnSdkUuidRecord *uuid);
char *sn_uuid_to_base64(SnSdkUuidRecord *uuid);
bool sn_uuid_equals(SnSdkUuidRecord *uuid, SnSdkUuidRecord *other);
long long sn_uuid_compare(SnSdkUuidRecord *uuid, SnSdkUuidRecord *other);
bool sn_uuid_is_less_than(SnSdkUuidRecord *uuid, SnSdkUuidRecord *other);
bool sn_uuid_is_greater_than(SnSdkUuidRecord *uuid, SnSdkUuidRecord *other);
SnSdkUuidRecord *sn_uuid_nil(void);
SnSdkUuidRecord *sn_uuid_max(void);
SnSdkUuidRecord *sn_uuid_namespace_dns(void);
SnSdkUuidRecord *sn_uuid_namespace_url(void);
SnSdkUuidRecord *sn_uuid_namespace_oid(void);
SnSdkUuidRecord *sn_uuid_namespace_x500(void);
SnSdkUuidRecord *sn_uuid_from_string(char *str);
SnSdkUuidRecord *sn_uuid_from_hex(char *str);
SnSdkUuidRecord *sn_uuid_from_base64(char *str);
#ifdef __cplusplus
}
#endif
#endif
