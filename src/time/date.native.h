#ifndef SN_SDK_DATE_NATIVE_H
#define SN_SDK_DATE_NATIVE_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
typedef struct { int __rc__; int32_t days; } SnSdkDateRecord;
#ifdef __cplusplus
extern "C" {
#endif
SnSdkDateRecord *sn_sdk_date_create(void);
SnSdkDateRecord *sn_sdk_date_retain(SnSdkDateRecord *);
void sn_sdk_date_release(SnSdkDateRecord *);
int sn_sdk_date_refs(SnSdkDateRecord *);
#ifdef __cplusplus
}
#endif
#endif

#if defined(SN_SDK_DATE_STANDALONE) && !defined(SN_SDK_DATE_OPERATIONS_DECLARED)
#define SN_SDK_DATE_OPERATIONS_DECLARED 1
#ifdef __cplusplus
extern "C" {
#endif
SnSdkDateRecord * sn_date_today(void);
SnSdkDateRecord * sn_date_from_ymd(long long year, long long month, long long day);
SnSdkDateRecord * sn_date_from_string(char * s);
SnSdkDateRecord * sn_date_from_epoch_days(long long days);
char * sn_date_format(SnSdkDateRecord * d, char * pattern);
char * sn_date_to_iso(SnSdkDateRecord * d);
char * sn_date_to_string(SnSdkDateRecord * d);
SnSdkDateRecord * sn_date_add_days(SnSdkDateRecord * d, long long days);
SnSdkDateRecord * sn_date_add_weeks(SnSdkDateRecord * d, long long weeks);
SnSdkDateRecord * sn_date_add_months(SnSdkDateRecord * d, long long months);
SnSdkDateRecord * sn_date_add_years(SnSdkDateRecord * d, long long years);
SnSdkDateRecord * sn_date_start_of_month(SnSdkDateRecord * d);
SnSdkDateRecord * sn_date_end_of_month(SnSdkDateRecord * d);
SnSdkDateRecord * sn_date_start_of_year(SnSdkDateRecord * d);
SnSdkDateRecord * sn_date_end_of_year(SnSdkDateRecord * d);
void * sn_date_to_time(SnSdkDateRecord * d);
long long sn_date_is_leap_year(long long year);
long long sn_date_days_in_month(long long year, long long month);
long long sn_date_get_year(SnSdkDateRecord *self);
long long sn_date_get_month(SnSdkDateRecord *self);
long long sn_date_get_day(SnSdkDateRecord *self);
long long sn_date_get_weekday(SnSdkDateRecord *self);
long long sn_date_get_day_of_year(SnSdkDateRecord *self);
long long sn_date_get_epoch_days(SnSdkDateRecord *self);
long long sn_date_get_days_in_month(SnSdkDateRecord *self);
bool sn_date_is_leap(SnSdkDateRecord *self);
bool sn_date_is_weekend(SnSdkDateRecord *self);
bool sn_date_is_weekday(SnSdkDateRecord *self);
bool sn_date_is_before(SnSdkDateRecord *self, SnSdkDateRecord * other);
bool sn_date_is_after(SnSdkDateRecord *self, SnSdkDateRecord * other);
bool sn_date_equals(SnSdkDateRecord *self, SnSdkDateRecord * other);
long long sn_date_diff_days(SnSdkDateRecord *self, SnSdkDateRecord * other);
#ifdef __cplusplus
}
#endif
#endif
