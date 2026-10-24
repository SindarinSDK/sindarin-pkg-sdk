#ifndef SN_SDK_YAML_NATIVE_H
#define SN_SDK_YAML_NATIVE_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "sn_array.h"
#include "sn_string.h"
typedef struct { int __rc__; long long root; long long node; int32_t is_root; long long handle; } SnSdkYamlRecord;
#ifdef __cplusplus
extern "C" {
#endif
SnSdkYamlRecord *sn_sdk_yaml_create(void);
SnSdkYamlRecord *sn_sdk_yaml_retain(SnSdkYamlRecord *);
SnSdkYamlRecord *sn_sdk_yaml_copy(const SnSdkYamlRecord *);
void sn_sdk_yaml_release(SnSdkYamlRecord *);
int sn_sdk_yaml_refs(SnSdkYamlRecord *);
#ifdef __cplusplus
}
#endif
#endif
#if defined(SN_SDK_YAML_STANDALONE) && !defined(SN_SDK_YAML_OPERATIONS_DECLARED)
#define SN_SDK_YAML_OPERATIONS_DECLARED 1
#ifdef __cplusplus
extern "C" {
#endif
SnSdkYamlRecord *sn_yaml_parse(char *text);
SnSdkYamlRecord *sn_yaml_parse_file(char *path);
SnSdkYamlRecord *sn_yaml_scalar(char *value);
SnSdkYamlRecord *sn_yaml_sequence(void);
SnSdkYamlRecord *sn_yaml_mapping(void);
bool sn_yaml_is_scalar(SnSdkYamlRecord *y);
bool sn_yaml_is_sequence(SnSdkYamlRecord *y);
bool sn_yaml_is_mapping(SnSdkYamlRecord *y);
char *sn_yaml_value(SnSdkYamlRecord *y);
long long sn_yaml_as_int(SnSdkYamlRecord *y);
long long sn_yaml_as_long(SnSdkYamlRecord *y);
double sn_yaml_as_float(SnSdkYamlRecord *y);
bool sn_yaml_as_bool(SnSdkYamlRecord *y);
SnSdkYamlRecord *sn_yaml_get(SnSdkYamlRecord *y, char *key);
bool sn_yaml_has(SnSdkYamlRecord *y, char *key);
SnArray *sn_yaml_keys(SnSdkYamlRecord *y);
SnSdkYamlRecord *sn_yaml_get_at(SnSdkYamlRecord *y, long long index);
SnSdkYamlRecord *sn_yaml_first(SnSdkYamlRecord *y);
SnSdkYamlRecord *sn_yaml_last(SnSdkYamlRecord *y);
long long sn_yaml_length(SnSdkYamlRecord *y);
void sn_yaml_set(SnSdkYamlRecord *y, char *key, SnSdkYamlRecord *value);
void sn_yaml_remove(SnSdkYamlRecord *y, char *key);
void sn_yaml_append(SnSdkYamlRecord *y, SnSdkYamlRecord *value);
void sn_yaml_prepend(SnSdkYamlRecord *y, SnSdkYamlRecord *value);
void sn_yaml_remove_at(SnSdkYamlRecord *y, long long index);
char *sn_yaml_to_string(SnSdkYamlRecord *y);
void sn_yaml_write_file(SnSdkYamlRecord *y, char *path);
SnSdkYamlRecord *sn_yaml_copy(SnSdkYamlRecord *y);
char *sn_yaml_type_name(SnSdkYamlRecord *y);
void sn_yaml_dispose(SnSdkYamlRecord *y);
#ifdef __cplusplus
}
#endif
#endif
