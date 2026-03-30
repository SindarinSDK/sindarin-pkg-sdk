/* ============================================================================
 * sdk/time.sn.c - Self-contained Time implementation for SDK
 * ============================================================================
 * This file provides the C implementation for the SnTime SDK type.
 * All functions use the sn_time_* prefix to avoid conflicts with runtime.
 * Minimal runtime version - no arena, uses malloc for allocations.
 * ============================================================================ */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #define GMTIME_R(time_ptr, tm_ptr) gmtime_s(tm_ptr, time_ptr)
#else
    #include <sys/time.h>
    #define GMTIME_R(time_ptr, tm_ptr) gmtime_r(time_ptr, tm_ptr)
#endif

/* ============================================================================
 * RtTime Structure (matches runtime definition)
 * ============================================================================ */

typedef __sn__Time RtTime;

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/* Create RtTime from milliseconds using the compiler-generated constructor.
 * __sn__Time__new() uses calloc and sets __rc__ = 1 for proper refcounting. */
static RtTime *sn_time_create(long long milliseconds)
{
    RtTime *t = __sn__Time__new();
    t->milliseconds = milliseconds;
    return t;
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
static void sn_time_to_tm(RtTime *t, struct tm *tm_result)
{
    if (t == NULL) {
        fprintf(stderr, "sn_time_to_tm: NULL time\n");
        exit(1);
    }

    memset(tm_result, 0, sizeof(struct tm));

    long long ms = t->milliseconds;

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
RtTime *sn_time_from_millis(long long ms)
{
    return sn_time_create(ms);
}

/* Create Time from seconds since Unix epoch */
RtTime *sn_time_from_seconds(long long s)
{
    return sn_time_create(s * 1000);
}

#ifdef _WIN32
/* Windows: milliseconds since Unix epoch via FILETIME */
static long long sn_time_win_millis(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    /* FILETIME is 100-nanosecond intervals since 1601-01-01 */
    ULARGE_INTEGER ul;
    ul.LowPart = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    /* Convert to Unix epoch (difference is 11644473600 seconds) */
    return (long long)(ul.QuadPart / 10000ULL - 11644473600000ULL);
}
#endif

/* Get current local time */
RtTime *sn_time_now(void)
{
#ifdef _WIN32
    return sn_time_create(sn_time_win_millis());
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long milliseconds = (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);
    return sn_time_create(milliseconds);
#endif
}

/* Get current UTC time */
RtTime *sn_time_utc(void)
{
#ifdef _WIN32
    return sn_time_create(sn_time_win_millis());
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long milliseconds = (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);
    return sn_time_create(milliseconds);
#endif
}

/* Sleep for specified milliseconds */
void sn_time_sleep(long long ms)
{
    if (ms <= 0) return;
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

/* ============================================================================
 * Time Getter Functions (native methods - receive self as RtTime*)
 * ============================================================================ */

/* Get milliseconds since Unix epoch */
long long sn_time_get_millis(RtTime *t)
{
    if (t == NULL) return 0;
    return t->milliseconds;
}

/* Get seconds since Unix epoch */
long long sn_time_get_seconds(RtTime *t)
{
    if (t == NULL) return 0;
    return t->milliseconds / 1000;
}

/* Get year component */
long long sn_time_get_year(RtTime *t)
{
    if (t == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(t, &tm);
    return tm.tm_year + 1900;
}

/* Get month component (1-12) */
long long sn_time_get_month(RtTime *t)
{
    if (t == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(t, &tm);
    return tm.tm_mon + 1;
}

/* Get day of month (1-31) */
long long sn_time_get_day(RtTime *t)
{
    if (t == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(t, &tm);
    return tm.tm_mday;
}

/* Get hour component (0-23) */
long long sn_time_get_hour(RtTime *t)
{
    if (t == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(t, &tm);
    return tm.tm_hour;
}

/* Get minute component (0-59) */
long long sn_time_get_minute(RtTime *t)
{
    if (t == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(t, &tm);
    return tm.tm_min;
}

/* Get second component (0-59) */
long long sn_time_get_second(RtTime *t)
{
    if (t == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(t, &tm);
    return tm.tm_sec;
}

/* Get weekday (0=Sunday, 6=Saturday) */
long long sn_time_get_weekday(RtTime *t)
{
    if (t == NULL) return 0;
    struct tm tm;
    sn_time_to_tm(t, &tm);
    return tm.tm_wday;
}

/* ============================================================================
 * Time Formatter Functions
 * ============================================================================ */

/* Format as date string (YYYY-MM-DD) */
char *sn_time_to_date(RtTime *t)
{
    if (t == NULL) return strdup("");
    struct tm tm;
    sn_time_to_tm(t, &tm);
    char buf[16];
    sprintf(buf, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    return strdup(buf);
}

/* Format as time string (HH:mm:ss) */
char *sn_time_to_time(RtTime *t)
{
    if (t == NULL) return strdup("");
    struct tm tm;
    sn_time_to_tm(t, &tm);
    char buf[16];
    sprintf(buf, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
    return strdup(buf);
}

/* Format as ISO 8601 string (YYYY-MM-DDTHH:mm:ss.SSSZ) */
char *sn_time_to_iso(RtTime *t)
{
    if (t == NULL) return strdup("");
    time_t secs = t->milliseconds / 1000;
    long millis = t->milliseconds % 1000;
    struct tm tm;
    GMTIME_R(&secs, &tm);
    char buf[32];
    sprintf(buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, millis);
    return strdup(buf);
}

/* Format time using pattern string */
char *sn_time_format(RtTime *t, char *pattern)
{
    if (t == NULL || pattern == NULL) return strdup("");

    struct tm tm;
    sn_time_to_tm(t, &tm);
    long millis = t->milliseconds % 1000;

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

    /* Shrink to fit */
    char *final = strdup(result);
    free(result);
    return final;
}

/* ============================================================================
 * Time Arithmetic Functions
 * ============================================================================ */

/* Add milliseconds to time */
RtTime *sn_time_add(RtTime *t, long long ms)
{
    if (t == NULL) return sn_time_create(0);
    return sn_time_create(t->milliseconds + ms);
}

/* Add seconds to time */
RtTime *sn_time_add_seconds(RtTime *t, long long seconds)
{
    return sn_time_add(t, seconds * 1000LL);
}

/* Add minutes to time */
RtTime *sn_time_add_minutes(RtTime *t, long long minutes)
{
    return sn_time_add(t, minutes * 60 * 1000LL);
}

/* Add hours to time */
RtTime *sn_time_add_hours(RtTime *t, long long hours)
{
    return sn_time_add(t, hours * 60 * 60 * 1000LL);
}

/* Add days to time */
RtTime *sn_time_add_days(RtTime *t, long long days)
{
    return sn_time_add(t, days * 24 * 60 * 60 * 1000LL);
}

/* Get difference between times in milliseconds */
long long sn_time_diff(RtTime *t, RtTime *other)
{
    if (t == NULL || other == NULL) return 0;
    return t->milliseconds - other->milliseconds;
}

/* ============================================================================
 * Time Comparison Functions (native methods - receive self as RtTime*)
 * ============================================================================ */

/* Check if time is before other */
bool sn_time_is_before(RtTime *t, RtTime *other)
{
    if (t == NULL || other == NULL) return false;
    return t->milliseconds < other->milliseconds;
}

/* Check if time is after other */
bool sn_time_is_after(RtTime *t, RtTime *other)
{
    if (t == NULL || other == NULL) return false;
    return t->milliseconds > other->milliseconds;
}

/* Check if times are equal */
bool sn_time_equals(RtTime *t, RtTime *other)
{
    if (t == NULL || other == NULL) return false;
    return t->milliseconds == other->milliseconds;
}
