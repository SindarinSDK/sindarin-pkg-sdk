/* ==============================================================================
 * sdk/date.sn.c - Self-contained Date Implementation for Sindarin SDK
 * ==============================================================================
 * This file provides the C implementation for the Date type.
 * It is compiled via @source and linked with Sindarin code.
 * Minimal runtime version - no arena, uses calloc/strdup.
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
    #define LOCALTIME_R(time_ptr, tm_ptr) localtime_s(tm_ptr, time_ptr)
#else
    #define LOCALTIME_R(time_ptr, tm_ptr) localtime_r(time_ptr, tm_ptr)
#endif

/* ============================================================================
 * Date Type Definition
 * ============================================================================ */

typedef __sn__Date RtDate;

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

long long sn_date_is_leap_year(long long year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

long long sn_date_days_in_month(long long year, long long month)
{
    if (month < 1 || month > 12) {
        return 0;
    }
    if (month == 2 && sn_date_is_leap_year(year)) {
        return 29;
    }
    return days_in_months[month - 1];
}

static int32_t sn_date_days_from_ymd(int year, int month, int day)
{
    int a = (14 - month) / 12;
    int y = year + 4800 - a;
    int m = month + 12 * a - 3;
    int32_t jdn = day + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 32045;
    return jdn - 2440588;
}

static void sn_date_ymd_from_days(int32_t days, int *year, int *month, int *day)
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

static int sn_date_weekday_from_days(int32_t days)
{
    int weekday = (int)((days + 4) % 7);
    if (weekday < 0) {
        weekday += 7;
    }
    return weekday;
}

static int sn_date_day_of_year(int32_t days)
{
    int year, month, day;
    sn_date_ymd_from_days(days, &year, &month, &day);

    int doy = day;
    for (int m = 1; m < month; m++) {
        doy += (int)sn_date_days_in_month(year, m);
    }
    return doy;
}

static void sn_date_calculate_target_year_month(int year, int month, int months_to_add,
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

static int sn_date_clamp_day_to_month(int day, int year, int month)
{
    int max_day = (int)sn_date_days_in_month(year, month);
    return (day < max_day) ? day : max_day;
}

static int sn_date_is_valid_ymd(int year, int month, int day)
{
    if (year < 1 || year > 9999) return 0;
    if (month < 1 || month > 12) return 0;
    if (day < 1) return 0;
    int max_day = (int)sn_date_days_in_month(year, month);
    return day <= max_day;
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static __sn__Date *sn_date_create(int32_t days)
{
    __sn__Date *date = (__sn__Date *)calloc(1, sizeof(__sn__Date));
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

__sn__Date *sn_date_from_epoch_days(long long days)
{
    return sn_date_create((int32_t)days);
}

__sn__Date *sn_date_from_ymd(long long year, long long month, long long day)
{
    if (!sn_date_is_valid_ymd((int)year, (int)month, (int)day)) {
        fprintf(stderr, "sn_date_from_ymd: invalid date %d-%02d-%02d\n", (int)year, (int)month, (int)day);
        exit(1);
    }
    int32_t d = sn_date_days_from_ymd((int)year, (int)month, (int)day);
    return sn_date_create(d);
}

__sn__Date *sn_date_from_string(char *str)
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
    return sn_date_from_ymd(year, month, day);
}

__sn__Date *sn_date_today(void)
{
    time_t now = time(NULL);
    struct tm tm;
    LOCALTIME_R(&now, &tm);
    int32_t days = sn_date_days_from_ymd(tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    return sn_date_from_epoch_days(days);
}

/* ============================================================================
 * Date Getters
 * ============================================================================ */

long long sn_date_get_epoch_days(__sn__Date *date)
{
    if (date == NULL) return 0;
    return (long long)date->days;
}

long long sn_date_get_year(__sn__Date *date)
{
    if (date == NULL) return 0;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return year;
}

long long sn_date_get_month(__sn__Date *date)
{
    if (date == NULL) return 0;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return month;
}

long long sn_date_get_day(__sn__Date *date)
{
    if (date == NULL) return 0;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return day;
}

long long sn_date_get_weekday(__sn__Date *date)
{
    if (date == NULL) return 0;
    return sn_date_weekday_from_days(date->days);
}

long long sn_date_get_day_of_year(__sn__Date *date)
{
    if (date == NULL) return 0;
    return sn_date_day_of_year(date->days);
}

long long sn_date_get_days_in_month(__sn__Date *date)
{
    if (date == NULL) return 0;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return sn_date_days_in_month(year, month);
}

bool sn_date_is_leap(__sn__Date *date)
{
    if (date == NULL) return false;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return sn_date_is_leap_year(year) != 0;
}

bool sn_date_is_weekend(__sn__Date *date)
{
    if (date == NULL) return false;
    int weekday = sn_date_weekday_from_days(date->days);
    return (weekday == 0 || weekday == 6);
}

bool sn_date_is_weekday(__sn__Date *date)
{
    if (date == NULL) return false;
    int weekday = sn_date_weekday_from_days(date->days);
    return (weekday >= 1 && weekday <= 5);
}

/* ============================================================================
 * Date Comparison
 * ============================================================================ */

bool sn_date_is_before(__sn__Date *date, __sn__Date *other)
{
    if (date == NULL || other == NULL) return false;
    return (date->days < other->days);
}

bool sn_date_is_after(__sn__Date *date, __sn__Date *other)
{
    if (date == NULL || other == NULL) return false;
    return (date->days > other->days);
}

bool sn_date_equals(__sn__Date *date, __sn__Date *other)
{
    if (date == NULL || other == NULL) return false;
    return (date->days == other->days);
}

long long sn_date_diff_days(__sn__Date *date, __sn__Date *other)
{
    if (date == NULL || other == NULL) return 0;
    return (long long)date->days - (long long)other->days;
}

/* ============================================================================
 * Date Formatters
 * ============================================================================ */

char *sn_date_format(__sn__Date *date, char *pattern)
{
    if (date == NULL || pattern == NULL) return strdup("");

    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);

    /* Allocate a large enough buffer */
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
    char *final = strdup(result);
    free(result);
    return final;
}

char *sn_date_to_iso(__sn__Date *date)
{
    if (date == NULL) return strdup("");

    long long year = sn_date_get_year(date);
    long long month = sn_date_get_month(date);
    long long day = sn_date_get_day(date);

    char buf[16];
    sprintf(buf, "%04lld-%02lld-%02lld", year, month, day);
    return strdup(buf);
}

char *sn_date_to_string(__sn__Date *date)
{
    if (date == NULL) return strdup("");

    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);

    char buf[32];
    sprintf(buf, "%s %d, %d", MONTH_NAMES_FULL[month - 1], day, year);
    return strdup(buf);
}

/* ============================================================================
 * Date Arithmetic
 * ============================================================================ */

__sn__Date *sn_date_add_days(__sn__Date *date, long long days)
{
    if (date == NULL) return NULL;
    return sn_date_create(date->days + (int32_t)days);
}

__sn__Date *sn_date_add_weeks(__sn__Date *date, long long weeks)
{
    return sn_date_add_days(date, weeks * 7);
}

__sn__Date *sn_date_add_months(__sn__Date *date, long long months)
{
    if (date == NULL) return NULL;

    long long year = sn_date_get_year(date);
    long long month = sn_date_get_month(date);
    long long day = sn_date_get_day(date);

    int target_year, target_month;
    sn_date_calculate_target_year_month((int)year, (int)month, (int)months, &target_year, &target_month);
    int target_day = sn_date_clamp_day_to_month((int)day, target_year, target_month);

    return sn_date_from_ymd(target_year, target_month, target_day);
}

__sn__Date *sn_date_add_years(__sn__Date *date, long long years)
{
    if (date == NULL) return NULL;

    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);

    int new_year = year + (int)years;
    if (month == 2 && day == 29 && !sn_date_is_leap_year(new_year)) {
        day = 28;
    }

    return sn_date_from_ymd(new_year, month, day);
}

__sn__Date *sn_date_start_of_month(__sn__Date *date)
{
    if (date == NULL) return NULL;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return sn_date_from_ymd(year, month, 1);
}

__sn__Date *sn_date_end_of_month(__sn__Date *date)
{
    if (date == NULL) return NULL;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    int last_day = (int)sn_date_days_in_month(year, month);
    return sn_date_from_ymd(year, month, last_day);
}

__sn__Date *sn_date_start_of_year(__sn__Date *date)
{
    if (date == NULL) return NULL;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return sn_date_from_ymd(year, 1, 1);
}

__sn__Date *sn_date_end_of_year(__sn__Date *date)
{
    if (date == NULL) return NULL;
    int year, month, day;
    sn_date_ymd_from_days(date->days, &year, &month, &day);
    return sn_date_from_ymd(year, 12, 31);
}

/* ============================================================================
 * Date/Time Conversion
 * ============================================================================ */

/* RtTime structure (must match sdk/time.sn.c definition) */
typedef struct RtTime {
    long long milliseconds;
} RtTime;

/* Convert date to time (midnight on that date in UTC) */
void *sn_date_to_time(__sn__Date *date)
{
    if (date == NULL) return NULL;

    /* Convert days since epoch to milliseconds since epoch (midnight UTC) */
    long long ms = (long long)date->days * 24LL * 60LL * 60LL * 1000LL;

    RtTime *t = (RtTime *)calloc(1, sizeof(RtTime));
    if (t == NULL) {
        fprintf(stderr, "sn_date_to_time: allocation failed\n");
        exit(1);
    }
    t->milliseconds = ms;
    return t;
}
