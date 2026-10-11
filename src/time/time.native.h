#ifndef SN_SDK_TIME_NATIVE_H
#define SN_SDK_TIME_NATIVE_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
typedef struct { int __rc__; long long milliseconds; } SnSdkTimeRecord;
#ifdef __cplusplus
extern "C" {
#endif
SnSdkTimeRecord *sn_sdk_time_create(void);
SnSdkTimeRecord *sn_sdk_time_retain(SnSdkTimeRecord *);
void sn_sdk_time_release(SnSdkTimeRecord *);
int sn_sdk_time_refs(SnSdkTimeRecord *);
#ifdef __cplusplus
}
#endif
#endif

#if defined(SN_SDK_TIME_STANDALONE) && !defined(SN_SDK_TIME_OPERATIONS_DECLARED)
#define SN_SDK_TIME_OPERATIONS_DECLARED 1
#ifdef __cplusplus
extern "C" {
#endif
SnSdkTimeRecord * sn_time_now(void);
SnSdkTimeRecord * sn_time_utc(void);
SnSdkTimeRecord * sn_time_from_millis(long long ms);
SnSdkTimeRecord * sn_time_from_seconds(long long s);
void sn_time_sleep(long long ms);
char * sn_time_format(SnSdkTimeRecord * t, char * pattern);
char * sn_time_to_iso(SnSdkTimeRecord * t);
char * sn_time_to_date(SnSdkTimeRecord * t);
char * sn_time_to_time(SnSdkTimeRecord * t);
SnSdkTimeRecord * sn_time_add(SnSdkTimeRecord * t, long long ms);
SnSdkTimeRecord * sn_time_add_seconds(SnSdkTimeRecord * t, long long seconds);
SnSdkTimeRecord * sn_time_add_minutes(SnSdkTimeRecord * t, long long minutes);
SnSdkTimeRecord * sn_time_add_hours(SnSdkTimeRecord * t, long long hours);
SnSdkTimeRecord * sn_time_add_days(SnSdkTimeRecord * t, long long days);
long long sn_time_diff(SnSdkTimeRecord * t, SnSdkTimeRecord * other);
long long sn_time_get_millis(SnSdkTimeRecord * t);
long long sn_time_get_seconds(SnSdkTimeRecord * t);
long long sn_time_get_year(SnSdkTimeRecord * t);
long long sn_time_get_month(SnSdkTimeRecord * t);
long long sn_time_get_day(SnSdkTimeRecord * t);
long long sn_time_get_hour(SnSdkTimeRecord * t);
long long sn_time_get_minute(SnSdkTimeRecord * t);
long long sn_time_get_second(SnSdkTimeRecord * t);
long long sn_time_get_weekday(SnSdkTimeRecord * t);
bool sn_time_is_before(SnSdkTimeRecord * t, SnSdkTimeRecord * other);
bool sn_time_is_after(SnSdkTimeRecord * t, SnSdkTimeRecord * other);
bool sn_time_equals(SnSdkTimeRecord * t, SnSdkTimeRecord * other);

#ifdef __cplusplus
}
#endif
#endif
