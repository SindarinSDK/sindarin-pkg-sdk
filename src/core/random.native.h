#ifndef SN_SDK_RANDOM_NATIVE_H
#define SN_SDK_RANDOM_NATIVE_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "sn_array.h"
typedef struct { int __rc__; int32_t is_seeded; long long state; } SnSdkRandomRecord;
#ifdef __cplusplus
extern "C" {
#endif
SnSdkRandomRecord *sn_sdk_random_create(void);
SnSdkRandomRecord *sn_sdk_random_retain(SnSdkRandomRecord *);
void sn_sdk_random_release(SnSdkRandomRecord *);
int sn_sdk_random_refs(SnSdkRandomRecord *);
#ifdef __cplusplus
}
#endif
#endif

#if defined(SN_SDK_RANDOM_STANDALONE) && !defined(SN_SDK_RANDOM_OPERATIONS_DECLARED)
#define SN_SDK_RANDOM_OPERATIONS_DECLARED 1
#ifdef __cplusplus
extern "C" {
#endif
SnSdkRandomRecord *sn_random_create(void);
SnSdkRandomRecord *sn_random_create_with_seed(long long seed);
void sn_random_free(SnSdkRandomRecord *rng);
long long sn_random_int(SnSdkRandomRecord *rng, long long min, long long max);
long long sn_random_long(SnSdkRandomRecord *rng, long long min, long long max);
double sn_random_double(SnSdkRandomRecord *rng, double min, double max);
long long sn_random_bool(SnSdkRandomRecord *rng);
unsigned char sn_random_byte(SnSdkRandomRecord *rng);
SnArray *sn_random_bytes(SnSdkRandomRecord *rng, long long count);
double sn_random_gaussian(SnSdkRandomRecord *rng, double mean, double stddev);
long long sn_random_static_int(long long min, long long max);
long long sn_random_static_long(long long min, long long max);
double sn_random_static_double(double min, double max);
long long sn_random_static_bool(void);
unsigned char sn_random_static_byte(void);
SnArray *sn_random_static_bytes(long long count);
double sn_random_static_gaussian(double mean, double stddev);
SnArray *sn_random_static_int_many(long long min, long long max, long long count);
SnArray *sn_random_static_long_many(long long min, long long max, long long count);
SnArray *sn_random_static_double_many(double min, double max, long long count);
SnArray *sn_random_static_bool_many(long long count);
SnArray *sn_random_static_gaussian_many(double mean, double stddev, long long count);
SnArray *sn_random_int_many(SnSdkRandomRecord *rng, long long min, long long max, long long count);
SnArray *sn_random_long_many(SnSdkRandomRecord *rng, long long min, long long max, long long count);
SnArray *sn_random_double_many(SnSdkRandomRecord *rng, double min, double max, long long count);
SnArray *sn_random_bool_many(SnSdkRandomRecord *rng, long long count);
SnArray *sn_random_gaussian_many(SnSdkRandomRecord *rng, double mean, double stddev, long long count);
long long sn_random_static_choice_int(SnArray *arr);
long long sn_random_static_choice_long(SnArray *arr);
double sn_random_static_choice_double(SnArray *arr);
char *sn_random_static_choice_str(SnArray *arr);
long long sn_random_static_choice_bool(SnArray *arr);
unsigned char sn_random_static_choice_byte(SnArray *arr);
long long sn_random_static_weighted_choice_int(SnArray *arr, SnArray *weights_arr);
long long sn_random_static_weighted_choice_long(SnArray *arr, SnArray *weights_arr);
double sn_random_static_weighted_choice_double(SnArray *arr, SnArray *weights_arr);
char *sn_random_static_weighted_choice_str(SnArray *arr, SnArray *weights_arr);
void sn_random_static_shuffle_int(SnArray *arr);
void sn_random_static_shuffle_long(SnArray *arr);
void sn_random_static_shuffle_double(SnArray *arr);
void sn_random_static_shuffle_str(SnArray *arr);
void sn_random_static_shuffle_bool(SnArray *arr);
void sn_random_static_shuffle_byte(SnArray *arr);
SnArray *sn_random_static_sample_int(SnArray *arr, long long count);
SnArray *sn_random_static_sample_long(SnArray *arr, long long count);
SnArray *sn_random_static_sample_double(SnArray *arr, long long count);
SnArray *sn_random_static_sample_str(SnArray *arr, long long count);
long long sn_random_choice_int(SnSdkRandomRecord *rng, SnArray *arr);
long long sn_random_choice_long(SnSdkRandomRecord *rng, SnArray *arr);
double sn_random_choice_double(SnSdkRandomRecord *rng, SnArray *arr);
char *sn_random_choice_str(SnSdkRandomRecord *rng, SnArray *arr);
long long sn_random_choice_bool(SnSdkRandomRecord *rng, SnArray *arr);
unsigned char sn_random_choice_byte(SnSdkRandomRecord *rng, SnArray *arr);
long long sn_random_weighted_choice_int(SnSdkRandomRecord *rng, SnArray *arr, SnArray *weights_arr);
long long sn_random_weighted_choice_long(SnSdkRandomRecord *rng, SnArray *arr, SnArray *weights_arr);
double sn_random_weighted_choice_double(SnSdkRandomRecord *rng, SnArray *arr, SnArray *weights_arr);
char *sn_random_weighted_choice_str(SnSdkRandomRecord *rng, SnArray *arr, SnArray *weights_arr);
void sn_random_shuffle_int(SnSdkRandomRecord *rng, SnArray *arr);
void sn_random_shuffle_long(SnSdkRandomRecord *rng, SnArray *arr);
void sn_random_shuffle_double(SnSdkRandomRecord *rng, SnArray *arr);
void sn_random_shuffle_str(SnSdkRandomRecord *rng, SnArray *arr);
void sn_random_shuffle_bool(SnSdkRandomRecord *rng, SnArray *arr);
void sn_random_shuffle_byte(SnSdkRandomRecord *rng, SnArray *arr);
SnArray *sn_random_sample_int(SnSdkRandomRecord *rng, SnArray *arr, long long count);
SnArray *sn_random_sample_long(SnSdkRandomRecord *rng, SnArray *arr, long long count);
SnArray *sn_random_sample_double(SnSdkRandomRecord *rng, SnArray *arr, long long count);
SnArray *sn_random_sample_str(SnSdkRandomRecord *rng, SnArray *arr, long long count);
#ifdef __cplusplus
}
#endif
#endif
