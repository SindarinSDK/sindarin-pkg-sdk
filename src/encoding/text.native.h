#ifndef SN_SDK_TEXT_NATIVE_H
#define SN_SDK_TEXT_NATIVE_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
typedef struct { int __rc__; long long buf; long long cap; long long len; } SnSdkStringBuilderRecord;
#ifdef __cplusplus
extern "C" {
#endif
SnSdkStringBuilderRecord *sn_sdk_text_create(void);
SnSdkStringBuilderRecord *sn_sdk_text_retain(SnSdkStringBuilderRecord *);
SnSdkStringBuilderRecord *sn_sdk_text_copy(const SnSdkStringBuilderRecord *);
void sn_sdk_text_release(SnSdkStringBuilderRecord *);
int sn_sdk_text_refs(SnSdkStringBuilderRecord *);
#ifdef __cplusplus
}
#endif
#endif
#if defined(SN_SDK_TEXT_STANDALONE) && !defined(SN_SDK_TEXT_OPERATIONS_DECLARED)
#define SN_SDK_TEXT_OPERATIONS_DECLARED 1
#ifdef __cplusplus
extern "C" {
#endif
SnSdkStringBuilderRecord *sn_text_new(void);
SnSdkStringBuilderRecord *sn_text_new_with_capacity(long long initial_cap);
void sn_text_append(SnSdkStringBuilderRecord *sb, char *s);
void sn_text_append_int(SnSdkStringBuilderRecord *sb, long long n);
void sn_text_append_double(SnSdkStringBuilderRecord *sb, double v);
void sn_text_append_bool(SnSdkStringBuilderRecord *sb, bool b);
long long sn_text_length(SnSdkStringBuilderRecord *sb);
void sn_text_clear(SnSdkStringBuilderRecord *sb);
char *sn_text_to_string(SnSdkStringBuilderRecord *sb);
void sn_text_dispose(SnSdkStringBuilderRecord *sb);
#ifdef __cplusplus
}
#endif
#endif
