/* ============================================================================
 * sdk/time.sn.c - Self-contained Time implementation for SDK
 * ============================================================================
 * This file provides the C implementation for the SnTime SDK type.
 * All functions use the sn_time_* prefix to avoid conflicts with runtime.
 * Uses arena allocation for proper memory management.
 * ============================================================================ */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
    #if defined(__MINGW32__) || defined(__MINGW64__)
    /* MinGW is POSIX-compatible */
    #include <sys/time.h>
    #else
    #include "platform/compat_windows.h"
    #include "platform/compat_time.h"
    #endif
    #define GMTIME_R(time_ptr, tm_ptr) gmtime_s(tm_ptr, time_ptr)
#else
#include <sys/time.h>
#define GMTIME_R(time_ptr, tm_ptr) gmtime_r(time_ptr, tm_ptr)
#endif

#include "runtime/runtime_arena.h"
#include "runtime/arena/managed_arena.h"

/* ============================================================================
 * RtTime Structure (matches runtime definition)
 * ============================================================================ */

typedef struct RtTime {
    long long milliseconds;
} RtTime;

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/* Create RtTime from milliseconds using arena allocation */
static RtTime *sn_time_create(RtArena *arena, long long milliseconds)
{
    if (arena == NULL) {
        fprintf(stderr, "sn_time_create: NULL arena\n");
        exit(1);
    }
    RtTime *time = (RtTime *)rt_arena_alloc(arena, sizeof(RtTime));
    if (time == NULL) {
        fprintf(stderr, "sn_time_create: allocation failed\n");
        exit(1);
    }
    time->milliseconds = milliseconds;
    return time;
}

/* Floor division (toward negative infinity) */
static long long sn_floor_div(long long a, long long b)
{
    return a / b - (a % b != 0 && (a ^ b) < 0);
}

/* Floor modulo (result has same sign as divisor) */
static long long sn_floor_mod(long long a, long long b)
{
    return a - sn_floor_div(a, b) * b;
}

/* Convert days since Unix epoch to year/month/day
 * Based on Howard Hinnant's civil calendar algorithms */
static void sn_days_to_ymd(long long days, int *year, int *month, int *day)
{
    /* Shift epoch from 1970-01-01 to 0000-03-01 */
    days += 719468;

    /* Calculate era (400-year period) */
    long long era = (days >= 0 ? days : days - 146096) / 146097;

    /* Day of era [0, 146096] */
    long long doe = days - era * 146097;

    /* Year of era [0, 399] */
    long long yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;

    /* Year */
    long long y = yoe + era * 400;

    /* Day of year [0, 365] */
    long long doy = doe - (365*yoe + yoe/4 - yoe/100);

    /* Month [0, 11] where March = 0 */
    long long mp = (5*doy + 2) / 153;

    /* Day [1, 31] */
    *day = (int)(doy - (153*mp + 2)/5 + 1);

    /* Month [1, 12] where January = 1 */
    *month = (int)(mp < 10 ? mp + 3 : mp - 9);

    /* Adjust year for months Jan-Feb */
    *year = (int)(y + (*month <= 2));
}

/* Decompose RtTime into struct tm components */
static void sn_time_to_tm(RtTime *time, struct tm *tm_result)
{
    if (time == NULL) {
        fprintf(stderr, "sn_time_to_tm: NULL time\n");
        exit(1);
    }

    memset(tm_result, 0, sizeof(struct tm));

    long long ms = time->milliseconds;

    /* Convert to seconds using floor division */
    long long secs = sn_floor_div(ms, 1000);

    /* Extract time of day using floor modulo (always positive) */
    long long time_of_day = sn_floor_mod(secs, 86400);

    /* Convert to days since epoch using floor division */
    long long days = sn_floor_div(secs, 86400);

    /* Convert days to year/month/day */
    int year, month, day;
    sn_days_to_ymd(days, &year, &month, &day);

    /* Fill in struct tm */
    tm_result->tm_year = year - 1900;
    tm_result->tm_mon = month - 1;
    tm_result->tm_mday = day;
    tm_result->tm_hour = (int)(time_of_day / 3600);
    tm_result->tm_min = (int)((time_of_day % 3600) / 60);
    tm_result->tm_sec = (int)(time_of_day % 60);

    /* Calculate day of week (0 = Sunday) - 1970-01-01 was Thursday (day 4) */
    long long dow = sn_floor_mod(days + 4, 7);
    tm_result->tm_wday = (int)dow;

    /* Calculate day of year [0, 365] */
    static const int days_before_month[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
    int is_leap = (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0));
    int yday = days_before_month[month - 1] + day - 1;
    if (is_leap && month > 2) yday++;
    tm_result->tm_yday = yday;

    tm_result->tm_isdst = -1;
}

/* ============================================================================
 * Time Creation Functions
 * ============================================================================ */

/* Create Time from milliseconds since Unix epoch */
RtTime *sn_time_from_millis(RtArena *arena, long long ms)
{
    return sn_time_create(arena, ms);
}

/* Create Time from seconds since Unix epoch */
RtTime *sn_time_from_seconds(RtArena *arena, long long s)
{
    return sn_time_create(arena, s * 1000);
}

/* Get current local time */
RtTime *sn_time_now(RtArena *arena)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long milliseconds = (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);
    return sn_time_create(arena, milliseconds);
}

/* Get current UTC time */
RtTime *sn_time_utc(RtArena *arena)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long milliseconds = (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);
    return sn_time_create(arena, milliseconds);
}

/* Sleep for specified milliseconds */
void sn_time_sleep(long ms)
{
    if (ms <= 0) return;
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

/* ============================================================================
 * Time Getter Functions (native methods - receive self by pointer)
 * ============================================================================ */

/* Get milliseconds since Unix epoch */
long long sn_time_get_millis(RtTime *time)
{
    if (time == NULL) return 0;
    return time->milliseconds;
}

/* Get seconds since Unix epoch */
long long sn_time_get_seconds(RtTime *time)
{
    if (time == NULL) return 0;
    return time->milliseconds / 1000;
}

/* Get year component */
long sn_time_get_year(RtTime *time)
{
    if (time == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(time, &tm);
    return tm.tm_year + 1900;
}

/* Get month component (1-12) */
long sn_time_get_month(RtTime *time)
{
    if (time == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(time, &tm);
    return tm.tm_mon + 1;
}

/* Get day of month (1-31) */
long sn_time_get_day(RtTime *time)
{
    if (time == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(time, &tm);
    return tm.tm_mday;
}

/* Get hour component (0-23) */
long sn_time_get_hour(RtTime *time)
{
    if (time == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(time, &tm);
    return tm.tm_hour;
}

/* Get minute component (0-59) */
long sn_time_get_minute(RtTime *time)
{
    if (time == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(time, &tm);
    return tm.tm_min;
}

/* Get second component (0-59) */
long sn_time_get_second(RtTime *time)
{
    if (time == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(time, &tm);
    return tm.tm_sec;
}

/* Get weekday (0=Sunday, 6=Saturday) */
long sn_time_get_weekday(RtTime *time)
{
    if (time == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(time, &tm);
    return tm.tm_wday;
}

/* ============================================================================
 * Time Formatter Functions
 * ============================================================================ */

/* Format as date string (YYYY-MM-DD) */
RtHandle sn_time_to_date(RtManagedArena *arena, RtTime *time)
{
    if (arena == NULL || time == NULL) return RT_HANDLE_NULL;
    struct tm tm;
    sn_time_to_tm(time, &tm);
    char buf[16];
    sprintf(buf, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    return rt_managed_strdup(arena, RT_HANDLE_NULL, buf);
}

/* Format as time string (HH:mm:ss) */
RtHandle sn_time_to_time(RtManagedArena *arena, RtTime *time)
{
    if (arena == NULL || time == NULL) return RT_HANDLE_NULL;
    struct tm tm;
    sn_time_to_tm(time, &tm);
    char buf[16];
    sprintf(buf, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
    return rt_managed_strdup(arena, RT_HANDLE_NULL, buf);
}

/* Format as ISO 8601 string (YYYY-MM-DDTHH:mm:ss.SSSZ) */
RtHandle sn_time_to_iso(RtManagedArena *arena, RtTime *time)
{
    if (arena == NULL || time == NULL) return RT_HANDLE_NULL;
    time_t secs = time->milliseconds / 1000;
    long millis = time->milliseconds % 1000;
    struct tm tm;
    GMTIME_R(&secs, &tm);
    char buf[32];
    sprintf(buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, millis);
    return rt_managed_strdup(arena, RT_HANDLE_NULL, buf);
}

/* Format time using pattern string */
RtHandle sn_time_format(RtManagedArena *arena, RtTime *time, const char *pattern)
{
    if (arena == NULL || time == NULL || pattern == NULL) return RT_HANDLE_NULL;

    struct tm tm;
    sn_time_to_tm(time, &tm);
    long millis = time->milliseconds % 1000;

    /* 12-hour format */
    int hour12 = tm.tm_hour % 12;
    if (hour12 == 0) hour12 = 12;

    /* Allocate output buffer */
    size_t buf_size = strlen(pattern) * 3 + 1;
    char *result = (char *)malloc(buf_size);
    if (result == NULL) exit(1);

    size_t out_pos = 0;
    for (size_t i = 0; pattern[i]; ) {
        if (strncmp(&pattern[i], "YYYY", 4) == 0) {
            out_pos += sprintf(&result[out_pos], "%04d", tm.tm_year + 1900);
            i += 4;
        } else if (strncmp(&pattern[i], "YY", 2) == 0) {
            out_pos += sprintf(&result[out_pos], "%02d", (tm.tm_year + 1900) % 100);
            i += 2;
        } else if (strncmp(&pattern[i], "MM", 2) == 0) {
            out_pos += sprintf(&result[out_pos], "%02d", tm.tm_mon + 1);
            i += 2;
        } else if (strncmp(&pattern[i], "M", 1) == 0) {
            out_pos += sprintf(&result[out_pos], "%d", tm.tm_mon + 1);
            i += 1;
        } else if (strncmp(&pattern[i], "DD", 2) == 0) {
            out_pos += sprintf(&result[out_pos], "%02d", tm.tm_mday);
            i += 2;
        } else if (strncmp(&pattern[i], "D", 1) == 0) {
            out_pos += sprintf(&result[out_pos], "%d", tm.tm_mday);
            i += 1;
        } else if (strncmp(&pattern[i], "HH", 2) == 0) {
            out_pos += sprintf(&result[out_pos], "%02d", tm.tm_hour);
            i += 2;
        } else if (strncmp(&pattern[i], "H", 1) == 0) {
            out_pos += sprintf(&result[out_pos], "%d", tm.tm_hour);
            i += 1;
        } else if (strncmp(&pattern[i], "hh", 2) == 0) {
            out_pos += sprintf(&result[out_pos], "%02d", hour12);
            i += 2;
        } else if (pattern[i] == 'h') {
            out_pos += sprintf(&result[out_pos], "%d", hour12);
            i += 1;
        } else if (strncmp(&pattern[i], "mm", 2) == 0) {
            out_pos += sprintf(&result[out_pos], "%02d", tm.tm_min);
            i += 2;
        } else if (strncmp(&pattern[i], "m", 1) == 0) {
            out_pos += sprintf(&result[out_pos], "%d", tm.tm_min);
            i += 1;
        } else if (strncmp(&pattern[i], "SSS", 3) == 0) {
            out_pos += sprintf(&result[out_pos], "%03ld", millis);
            i += 3;
        } else if (strncmp(&pattern[i], "ss", 2) == 0) {
            out_pos += sprintf(&result[out_pos], "%02d", tm.tm_sec);
            i += 2;
        } else if (strncmp(&pattern[i], "s", 1) == 0) {
            out_pos += sprintf(&result[out_pos], "%d", tm.tm_sec);
            i += 1;
        } else if (pattern[i] == 'A') {
            out_pos += sprintf(&result[out_pos], "%s", tm.tm_hour < 12 ? "AM" : "PM");
            i += 1;
        } else if (pattern[i] == 'a') {
            out_pos += sprintf(&result[out_pos], "%s", tm.tm_hour < 12 ? "am" : "pm");
            i += 1;
        } else {
            result[out_pos++] = pattern[i++];
        }
    }

    result[out_pos] = '\0';
    RtHandle handle = rt_managed_strdup(arena, RT_HANDLE_NULL, result);
    free(result);
    return handle;
}

/* ============================================================================
 * Time Arithmetic Functions
 * ============================================================================ */

/* Add milliseconds to time */
RtTime *sn_time_add(RtArena *arena, RtTime *time, long long ms)
{
    if (arena == NULL || time == NULL) return NULL;
    return sn_time_create(arena, time->milliseconds + ms);
}

/* Add seconds to time */
RtTime *sn_time_add_seconds(RtArena *arena, RtTime *time, long seconds)
{
    return sn_time_add(arena, time, seconds * 1000LL);
}

/* Add minutes to time */
RtTime *sn_time_add_minutes(RtArena *arena, RtTime *time, long minutes)
{
    return sn_time_add(arena, time, minutes * 60 * 1000LL);
}

/* Add hours to time */
RtTime *sn_time_add_hours(RtArena *arena, RtTime *time, long hours)
{
    return sn_time_add(arena, time, hours * 60 * 60 * 1000LL);
}

/* Add days to time */
RtTime *sn_time_add_days(RtArena *arena, RtTime *time, long days)
{
    return sn_time_add(arena, time, days * 24 * 60 * 60 * 1000LL);
}

/* Get difference between times in milliseconds */
long long sn_time_diff(RtTime *time, RtTime *other)
{
    if (time == NULL || other == NULL) return 0;
    return time->milliseconds - other->milliseconds;
}

/* ============================================================================
 * Time Comparison Functions (native methods - receive self by pointer)
 * ============================================================================ */

/* Check if time is before other */
int sn_time_is_before(RtTime *time, RtTime *other)
{
    if (time == NULL || other == NULL) return 0;
    return (time->milliseconds < other->milliseconds) ? 1 : 0;
}

/* Check if time is after other */
int sn_time_is_after(RtTime *time, RtTime *other)
{
    if (time == NULL || other == NULL) return 0;
    return (time->milliseconds > other->milliseconds) ? 1 : 0;
}

/* Check if times are equal */
int sn_time_equals(RtTime *time, RtTime *other)
{
    if (time == NULL || other == NULL) return 0;
    return (time->milliseconds == other->milliseconds) ? 1 : 0;
}
