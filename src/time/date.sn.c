/* ==============================================================================
 * sdk/date.sn.c - Self-contained Date Implementation for Sindarin SDK
 * ==============================================================================
 * This file provides the C implementation for the SnDate type.
 * It is compiled via #pragma source and linked with Sindarin code.
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* Include runtime arena for proper memory management */
#include "runtime/runtime_arena.h"
#include "runtime/arena/managed_arena.h"

#ifdef _WIN32
    #define LOCALTIME_R(time_ptr, tm_ptr) localtime_s(tm_ptr, time_ptr)
#else
    #define LOCALTIME_R(time_ptr, tm_ptr) localtime_r(time_ptr, tm_ptr)
#endif

/* ============================================================================
 * Date Type Definition
 * ============================================================================ */

typedef struct RtDate {
    int32_t days;     /* Days since Unix epoch (1970-01-01), can be negative */
} RtDate;

/* ============================================================================
 * Month and Weekday Name Arrays
 * ============================================================================ */

static const char *MONTH_NAMES_FULL[12] = {
    "January", "February", "March", "April",
    "May", "June", "July", "August",
    "September", "October", "November", "December"
};

static const char *MONTH_NAMES_SHORT[12] = {
    "Jan", "Feb", "Mar", "Apr",
    "May", "Jun", "Jul", "Aug",
    "Sep", "Oct", "Nov", "Dec"
};

static const char *WEEKDAY_NAMES_FULL[7] = {
    "Sunday", "Monday", "Tuesday", "Wednesday",
    "Thursday", "Friday", "Saturday"
};

static const char *WEEKDAY_NAMES_SHORT[7] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const int days_in_months[12] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

/* ============================================================================
 * Calendar Calculation Helpers
 * ============================================================================ */

int sn_date_is_leap_year(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

int sn_date_days_in_month(int year, int month)
{
    if (month < 1 || month > 12) {
        return 0;
    }
    if (month == 2 && sn_date_is_leap_year(year)) {
        return 29;
    }
    return days_in_months[month - 1];
}

int32_t sn_date_days_from_ymd(int year, int month, int day)
{
    int a = (14 - month) / 12;
    int y = year + 4800 - a;
    int m = month + 12 * a - 3;
    int32_t jdn = day + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 32045;
    return jdn - 2440588;
}

void sn_date_ymd_from_days(int32_t days, int *year, int *month, int *day)
{
    int32_t jdn = days + 2440588;
    int a = jdn + 32044;
    int b = (4 * a + 3) / 146097;
    int c = a - (146097 * b) / 4;
    int d = (4 * c + 3) / 1461;
    int e = c - (1461 * d) / 4;
    int m = (5 * e + 2) / 153;

    *day = e - (153 * m + 2) / 5 + 1;
    *month = m + 3 - 12 * (m / 10);
    *year = 100 * b + d - 4800 + m / 10;
}

int sn_date_weekday_from_days(int32_t days)
{
    int weekday = (int)((days + 4) % 7);
    if (weekday < 0) {
        weekday += 7;
    }
    return weekday;
}

int sn_date_day_of_year(int32_t days)
{
    int year, month, day;
    sn_date_ymd_from_days(days, &year, &month, &day);

    int doy = day;
    for (int m = 1; m < month; m++) {
        doy += sn_date_days_in_month(year, m);
    }
    return doy;
}

void sn_date_calculate_target_year_month(int year, int month, int months_to_add,
                                          int *out_year, int *out_month)
{
    int total_months = (year * 12) + (month - 1) + months_to_add;
    *out_year = total_months / 12;
    *out_month = (total_months % 12) + 1;
    if (*out_month < 1) {
        *out_month += 12;
        (*out_year)--;
    }
}

int sn_date_clamp_day_to_month(int day, int year, int month)
{
    int max_day = sn_date_days_in_month(year, month);
    return (day < max_day) ? day : max_day;
}

int sn_date_is_valid_ymd(int year, int month, int day)
{
    if (year < 1 || year > 9999) return 0;
    if (month < 1 || month > 12) return 0;
    if (day < 1) return 0;
    int max_day = sn_date_days_in_month(year, month);
    return day <= max_day;
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static RtDate *sn_date_create(RtArena *arena, int32_t days)
{
    RtDate *date = (RtDate *)rt_arena_alloc(arena, sizeof(RtDate));
    if (date == NULL) {
        fprintf(stderr, "sn_date_create: allocation failed\n");
        exit(1);
    }
    date->days = days;
    return date;
}

/* ============================================================================
 * Date Creation
 * ============================================================================ */

RtDate *sn_date_from_epoch_days(RtArena *arena, int32_t days)
{
    return sn_date_create(arena, days);
}

RtDate *sn_date_from_ymd(RtArena *arena, int year, int month, int day)
{
    if (!sn_date_is_valid_ymd(year, month, day)) {
        fprintf(stderr, "sn_date_from_ymd: invalid date %d-%02d-%02d\n", year, month, day);
        exit(1);
    }
    int32_t days = sn_date_days_from_ymd(year, month, day);
    return sn_date_create(arena, days);
}

RtDate *sn_date_from_string(RtArena *arena, const char *str)
{
    if (str == NULL) {
        fprintf(stderr, "sn_date_from_string: NULL string\n");
        exit(1);
    }

    size_t len = strlen(str);
    if (len != 10 || str[4] != '-' || str[7] != '-') {
        fprintf(stderr, "sn_date_from_string: invalid format '%s', expected YYYY-MM-DD\n", str);
        exit(1);
    }

    for (int i = 0; i < 10; i++) {
        if (i == 4 || i == 7) continue;
        if (str[i] < '0' || str[i] > '9') {
            fprintf(stderr, "sn_date_from_string: invalid format '%s'\n", str);
            exit(1);
        }
    }

    int year, month, day;
    sscanf(str, "%d-%d-%d", &year, &month, &day);
    return sn_date_from_ymd(arena, year, month, day);
}

RtDate *sn_date_today(RtArena *arena)
{
    time_t now = time(NULL);
    struct tm tm;
    LOCALTIME_R(&now, &tm);
    int32_t days = sn_date_days_from_ymd(tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    return sn_date_from_epoch_days(arena, days);
}

/* ============================================================================
 * Date Getters
 * ============================================================================ */

int32_t sn_date_get_epoch_days(RtDate *date)
{
    return date ? date->days : 0;
}

long sn_date_get_year(RtDate *date)
{
    if (date == NULL) return 0;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return year;
}

long sn_date_get_month(RtDate *date)
{
    if (date == NULL) return 0;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return month;
}

long sn_date_get_day(RtDate *date)
{
    if (date == NULL) return 0;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return day;
}

long sn_date_get_weekday(RtDate *date)
{
    return date ? sn_date_weekday_from_days(date->days) : 0;
}

long sn_date_get_day_of_year(RtDate *date)
{
    return date ? sn_date_day_of_year(date->days) : 0;
}

long sn_date_get_days_in_month(RtDate *date)
{
    if (date == NULL) return 0;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return sn_date_days_in_month(year, month);
}

int sn_date_is_leap(RtDate *date)
{
    if (date == NULL) return 0;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return sn_date_is_leap_year(year);
}

int sn_date_is_weekend(RtDate *date)
{
    if (date == NULL) return 0;
    int weekday = sn_date_weekday_from_days(date->days);
    return (weekday == 0 || weekday == 6) ? 1 : 0;
}

int sn_date_is_weekday(RtDate *date)
{
    if (date == NULL) return 0;
    int weekday = sn_date_weekday_from_days(date->days);
    return (weekday >= 1 && weekday <= 5) ? 1 : 0;
}

/* ============================================================================
 * Date Formatters
 * ============================================================================ */

RtHandle sn_date_format(RtManagedArena *arena, RtDate *date, const char *pattern)
{
    if (date == NULL || pattern == NULL) return RT_HANDLE_NULL;

    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);

    /* Allocate a large enough buffer on stack */
    size_t buf_size = strlen(pattern) * 4 + 64;
    char *result = (char *)malloc(buf_size);
    if (result == NULL) {
        fprintf(stderr, "sn_date_format: allocation failed\n");
        exit(1);
    }

    int out_pos = 0;
    size_t i = 0;
    while (pattern[i]) {
        const char *p = &pattern[i];

        if (strncmp(p, "YYYY", 4) == 0) {
            out_pos += sprintf(&result[out_pos], "%04d", year);
            i += 4;
        } else if (strncmp(p, "YY", 2) == 0) {
            out_pos += sprintf(&result[out_pos], "%02d", year % 100);
            i += 2;
        } else if (strncmp(p, "MMMM", 4) == 0) {
            out_pos += sprintf(&result[out_pos], "%s", MONTH_NAMES_FULL[month - 1]);
            i += 4;
        } else if (strncmp(p, "MMM", 3) == 0) {
            out_pos += sprintf(&result[out_pos], "%s", MONTH_NAMES_SHORT[month - 1]);
            i += 3;
        } else if (strncmp(p, "MM", 2) == 0) {
            out_pos += sprintf(&result[out_pos], "%02d", month);
            i += 2;
        } else if (p[0] == 'M' && !(p[1] >= 'a' && p[1] <= 'z')) {
            out_pos += sprintf(&result[out_pos], "%d", month);
            i += 1;
        } else if (strncmp(p, "dddd", 4) == 0) {
            int weekday = sn_date_weekday_from_days(date->days);
            out_pos += sprintf(&result[out_pos], "%s", WEEKDAY_NAMES_FULL[weekday]);
            i += 4;
        } else if (strncmp(p, "ddd", 3) == 0) {
            int weekday = sn_date_weekday_from_days(date->days);
            out_pos += sprintf(&result[out_pos], "%s", WEEKDAY_NAMES_SHORT[weekday]);
            i += 3;
        } else if (strncmp(p, "DD", 2) == 0) {
            out_pos += sprintf(&result[out_pos], "%02d", day);
            i += 2;
        } else if (p[0] == 'D' && !(p[1] >= 'a' && p[1] <= 'z')) {
            out_pos += sprintf(&result[out_pos], "%d", day);
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

RtHandle sn_date_to_iso(RtManagedArena *arena, RtDate *date)
{
    if (date == NULL) return RT_HANDLE_NULL;

    long year = sn_date_get_year(date);
    long month = sn_date_get_month(date);
    long day = sn_date_get_day(date);

    char buf[16];
    sprintf(buf, "%04ld-%02ld-%02ld", year, month, day);
    return rt_managed_strdup(arena, RT_HANDLE_NULL, buf);
}

RtHandle sn_date_to_string(RtManagedArena *arena, RtDate *date)
{
    if (date == NULL) return RT_HANDLE_NULL;

    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);

    char buf[32];
    sprintf(buf, "%s %d, %d", MONTH_NAMES_FULL[month - 1], day, year);
    return rt_managed_strdup(arena, RT_HANDLE_NULL, buf);
}

/* ============================================================================
 * Date Arithmetic
 * ============================================================================ */

RtDate *sn_date_add_days(RtArena *arena, RtDate *date, long days)
{
    if (date == NULL) return NULL;
    return sn_date_create(arena, date->days + (int32_t)days);
}

RtDate *sn_date_add_weeks(RtArena *arena, RtDate *date, long weeks)
{
    return sn_date_add_days(arena, date, weeks * 7);
}

RtDate *sn_date_add_months(RtArena *arena, RtDate *date, int months)
{
    if (date == NULL) return NULL;

    int year = sn_date_get_year(date);
    int month = sn_date_get_month(date);
    int day = sn_date_get_day(date);

    int target_year, target_month;
    sn_date_calculate_target_year_month(year, month, months, &target_year, &target_month);
    int target_day = sn_date_clamp_day_to_month(day, target_year, target_month);

    return sn_date_from_ymd(arena, target_year, target_month, target_day);
}

RtDate *sn_date_add_years(RtArena *arena, RtDate *date, long years)
{
    if (date == NULL) return NULL;

    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);

    int new_year = year + (int)years;
    if (month == 2 && day == 29 && !sn_date_is_leap_year(new_year)) {
        day = 28;
    }

    return sn_date_from_ymd(arena, new_year, month, day);
}

long long sn_date_diff_days(RtDate *date, RtDate *other)
{
    if (date == NULL || other == NULL) return 0;
    return (long long)date->days - (long long)other->days;
}

RtDate *sn_date_start_of_month(RtArena *arena, RtDate *date)
{
    if (date == NULL) return NULL;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return sn_date_from_ymd(arena, year, month, 1);
}

RtDate *sn_date_end_of_month(RtArena *arena, RtDate *date)
{
    if (date == NULL) return NULL;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    int last_day = sn_date_days_in_month(year, month);
    return sn_date_from_ymd(arena, year, month, last_day);
}

RtDate *sn_date_start_of_year(RtArena *arena, RtDate *date)
{
    if (date == NULL) return NULL;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return sn_date_from_ymd(arena, year, 1, 1);
}

RtDate *sn_date_end_of_year(RtArena *arena, RtDate *date)
{
    if (date == NULL) return NULL;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return sn_date_from_ymd(arena, year, 12, 31);
}

/* ============================================================================
 * Date Comparison
 * ============================================================================ */

int sn_date_is_before(RtDate *date, RtDate *other)
{
    if (date == NULL || other == NULL) return 0;
    return (date->days < other->days) ? 1 : 0;
}

int sn_date_is_after(RtDate *date, RtDate *other)
{
    if (date == NULL || other == NULL) return 0;
    return (date->days > other->days) ? 1 : 0;
}

int sn_date_equals(RtDate *date, RtDate *other)
{
    if (date == NULL || other == NULL) return 0;
    return (date->days == other->days) ? 1 : 0;
}

/* ============================================================================
 * Date/Time Conversion
 * ============================================================================ */

/* RtTime structure (must match sdk/time.sn.c definition) */
typedef struct RtTime {
    long long milliseconds;
} RtTime;

/* Convert date to time (midnight on that date in UTC) */
void *sn_date_to_time(RtArena *arena, RtDate *date)
{
    if (arena == NULL || date == NULL) return NULL;

    /* Convert days since epoch to milliseconds since epoch (midnight UTC) */
    long long ms = (long long)date->days * 24LL * 60LL * 60LL * 1000LL;

    RtTime *time = (RtTime *)rt_arena_alloc(arena, sizeof(RtTime));
    if (time == NULL) {
        fprintf(stderr, "sn_date_to_time: allocation failed\n");
        exit(1);
    }
    time->milliseconds = ms;
    return time;
}
