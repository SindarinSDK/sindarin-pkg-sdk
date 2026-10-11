#ifndef SN_SDK_JSON_NATIVE_H
#define SN_SDK_JSON_NATIVE_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "sn_array.h"
#include "sn_string.h"
typedef struct { int __rc__; long long obj; long long handle; int32_t is_root; } SnSdkJsonRecord;
#ifdef __cplusplus
extern "C" {
#endif
SnSdkJsonRecord *sn_sdk_json_create(void);
SnSdkJsonRecord *sn_sdk_json_retain(SnSdkJsonRecord *);
SnSdkJsonRecord *sn_sdk_json_copy(const SnSdkJsonRecord *);
void sn_sdk_json_release(SnSdkJsonRecord *);
int sn_sdk_json_refs(SnSdkJsonRecord *);
#ifdef __cplusplus
}
#endif
#endif
#if defined(SN_SDK_JSON_STANDALONE) && !defined(SN_SDK_JSON_OPERATIONS_DECLARED)
#define SN_SDK_JSON_OPERATIONS_DECLARED 1
#ifdef __cplusplus
extern "C" {
#endif
SnSdkJsonRecord *sn_json_parse(char *text);
SnSdkJsonRecord *sn_json_parse_file(char *path);
SnSdkJsonRecord *sn_json_new_object(void);
SnSdkJsonRecord *sn_json_new_array(void);
SnSdkJsonRecord *sn_json_new_null(void);
SnSdkJsonRecord *sn_json_new_bool(bool value);
SnSdkJsonRecord *sn_json_new_int(long long value);
SnSdkJsonRecord *sn_json_new_float(double value);
SnSdkJsonRecord *sn_json_new_string(char *value);
bool sn_json_is_object(SnSdkJsonRecord *j);
bool sn_json_is_array(SnSdkJsonRecord *j);
bool sn_json_is_string(SnSdkJsonRecord *j);
bool sn_json_is_number(SnSdkJsonRecord *j);
bool sn_json_is_int(SnSdkJsonRecord *j);
bool sn_json_is_float(SnSdkJsonRecord *j);
bool sn_json_is_bool(SnSdkJsonRecord *j);
bool sn_json_is_null(SnSdkJsonRecord *j);
char *sn_json_as_string(SnSdkJsonRecord *j);
long long sn_json_as_int(SnSdkJsonRecord *j);
long long sn_json_as_long(SnSdkJsonRecord *j);
double sn_json_as_float(SnSdkJsonRecord *j);
bool sn_json_as_bool(SnSdkJsonRecord *j);
SnSdkJsonRecord *sn_json_get(SnSdkJsonRecord *j, char *key);
bool sn_json_has(SnSdkJsonRecord *j, char *key);
SnArray *sn_json_keys(SnSdkJsonRecord *j);
SnSdkJsonRecord *sn_json_get_at(SnSdkJsonRecord *j, long long index);
SnSdkJsonRecord *sn_json_first(SnSdkJsonRecord *j);
SnSdkJsonRecord *sn_json_last(SnSdkJsonRecord *j);
long long sn_json_length(SnSdkJsonRecord *j);
void sn_json_set(SnSdkJsonRecord *j, char *key, SnSdkJsonRecord *value);
void sn_json_remove(SnSdkJsonRecord *j, char *key);
void sn_json_append(SnSdkJsonRecord *j, SnSdkJsonRecord *value);
void sn_json_prepend(SnSdkJsonRecord *j, SnSdkJsonRecord *value);
void sn_json_insert(SnSdkJsonRecord *j, long long index, SnSdkJsonRecord *value);
void sn_json_remove_at(SnSdkJsonRecord *j, long long index);
char *sn_json_to_string(SnSdkJsonRecord *j);
char *sn_json_to_pretty_string(SnSdkJsonRecord *j);
void sn_json_write_file(SnSdkJsonRecord *j, char *path);
void sn_json_write_file_pretty(SnSdkJsonRecord *j, char *path);
SnSdkJsonRecord *sn_json_copy(SnSdkJsonRecord *j);
char *sn_json_type_name(SnSdkJsonRecord *j);
void sn_json_dispose(SnSdkJsonRecord *j);
#ifdef __cplusplus
}
#endif
#endif
