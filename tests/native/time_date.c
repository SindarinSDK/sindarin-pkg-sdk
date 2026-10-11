#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SN_SDK_TIME_STANDALONE 1
#define SN_SDK_DATE_STANDALONE 1
#include "time.native.h"
#include "date.native.h"
#include "time.native.h"
#include "date.native.h"
#include "sn_abi.h"
#include <pthread.h>
static unsigned destroyed;
static void destroy_time(void *value, uintptr_t context)
{
    assert(context == 7); destroyed++; sn_sdk_time_release(value);
}
static void *retain_time(void *value)
{
    for (int i = 0; i < 10000; i++) {
        assert(sn_sdk_time_retain(value) == value); sn_sdk_time_release(value);
    }
    return NULL;
}
int main(void)
{
    assert(sn_sdk_time_refs(NULL) == 0 && sn_sdk_time_retain(NULL) == NULL);
    assert(sn_sdk_date_refs(NULL) == 0 && sn_sdk_date_retain(NULL) == NULL);
    sn_sdk_time_release(NULL); sn_sdk_date_release(NULL);
    SnSdkTimeRecord *time = sn_time_from_millis(0);
    assert(time && sn_sdk_time_refs(time) == 1 && time->milliseconds == 0);
    pthread_t threads[4];
    for (int i = 0; i < 4; i++) assert(pthread_create(&threads[i], NULL, retain_time, time) == 0);
    for (int i = 0; i < 4; i++) assert(pthread_join(threads[i], NULL) == 0);
    assert(sn_sdk_time_refs(time) == 1);
    SnSdkTimeRecord *alias = sn_sdk_time_retain(time);
    alias->milliseconds = 86400000;
    assert(sn_time_get_day(time) == 2 && sn_time_get_year(time) == 1970);
    char *text = sn_time_to_iso(time);
    assert(!strcmp(text, "1970-01-02T00:00:00.000Z"));
    SnSdkTimeRecord *later = sn_time_add_hours(time, 1);
    assert(later != time && sn_time_diff(later, time) == 3600000);
    sn_sdk_time_release(later);
    SnAbiValue *wire = NULL;
    assert(sn_abi_v1_resource_new_typed("SindarinSDK/sindarin-pkg-sdk:time.Time@1",time,destroy_time,7,&wire) == 0);
    SnAbiValue *credit = sn_abi_v1_retain(wire); void *pointer = NULL;
    assert(sn_abi_v1_resource_data_typed(credit,"SindarinSDK/sindarin-pkg-sdk:time.Time@1",&pointer) == 0 && pointer == time);
    sn_sdk_time_release(alias); sn_abi_v1_release(wire);
    assert(destroyed == 0 && sn_time_get_day(pointer) == 2);
    sn_abi_v1_release(credit); assert(destroyed == 1);
    assert(!strcmp(text, "1970-01-02T00:00:00.000Z")); free(text);
    SnSdkDateRecord *date = sn_date_from_ymd(2024, 2, 29);
    assert(date && sn_sdk_date_refs(date) == 1 && sn_date_is_leap(date));
    SnSdkDateRecord *next = sn_date_add_years(date, 1);
    text = sn_date_to_iso(next); assert(!strcmp(text,"2025-02-28")); free(text);
    assert(sn_date_get_day(next) == 28);
    SnSdkDateRecord *date_alias = sn_sdk_date_retain(date);
    assert(date_alias == date && sn_sdk_date_refs(date) == 2);
    date_alias->days = 0; assert(sn_date_get_year(date) == 1970);
    SnSdkTimeRecord *converted = sn_date_to_time(date);
    assert(converted && converted->milliseconds == 0 && sn_sdk_time_refs(converted) == 1);
    sn_sdk_time_release(converted); sn_sdk_date_release(date_alias);
    sn_sdk_date_release(date); sn_sdk_date_release(next);
    assert(sn_date_to_time(NULL) == NULL && sn_date_add_days(NULL,1) == NULL);
    time = sn_time_add(NULL, 7); assert(time && time->milliseconds == 0); sn_sdk_time_release(time);
    sn_time_sleep(0);
    puts("SDK canonical Time/Date: pass");
    return 0;
}
