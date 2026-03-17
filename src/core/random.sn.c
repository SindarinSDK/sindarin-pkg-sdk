/* ==============================================================================
 * sdk/random.sn.c - Self-contained Random Implementation for Sindarin SDK
 * ==============================================================================
 * This file provides the complete C implementation for the SnRandom type.
 * It is self-contained and does not depend on runtime_random_*.h headers.
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <errno.h>

/* Platform-specific includes for entropy sources */
#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <stdlib.h>  /* arc4random_buf on BSD/macOS */
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

/* ============================================================================
 * RtRandom Type Definition
 * ============================================================================ */

typedef __sn__Random RtRandom;

/* ============================================================================
 * Core Entropy Function
 * ============================================================================ */

static void sn_random_fill_entropy(uint8_t *buf, size_t len) {
    if (buf == NULL || len == 0) {
        return;
    }

#if defined(__linux__)
    size_t remaining = len;
    uint8_t *ptr = buf;

    while (remaining > 0) {
        ssize_t ret = getrandom(ptr, remaining, 0);

        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN) {
                continue;
            }
            fprintf(stderr, "sn_random_fill_entropy: getrandom() failed: %s\n",
                    strerror(errno));
            exit(1);
        }

        ptr += ret;
        remaining -= (size_t)ret;
    }

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(buf, len);

#elif defined(_WIN32)
    NTSTATUS status = BCryptGenRandom(
        NULL,
        buf,
        (ULONG)len,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "sn_random_fill_entropy: BCryptGenRandom() failed: 0x%lx\n",
                (unsigned long)status);
        exit(1);
    }

#else
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL) {
        fprintf(stderr, "sn_random_fill_entropy: failed to open /dev/urandom: %s\n",
                strerror(errno));
        exit(1);
    }

    size_t bytes_read = fread(buf, 1, len, urandom);
    if (bytes_read != len) {
        fprintf(stderr, "sn_random_fill_entropy: failed to read from /dev/urandom\n");
        fclose(urandom);
        exit(1);
    }

    fclose(urandom);
#endif
}

/* ============================================================================
 * xoshiro256** PRNG Algorithm
 * ============================================================================ */

static inline uint64_t rotl(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static uint64_t xoshiro256_next(uint64_t *state) {
    const uint64_t result = rotl(state[1] * 5, 7) * 9;

    const uint64_t t = state[1] << 17;

    state[2] ^= state[0];
    state[3] ^= state[1];
    state[1] ^= state[2];
    state[0] ^= state[3];

    state[2] ^= t;

    state[3] = rotl(state[3], 45);

    return result;
}

/* ============================================================================
 * SplitMix64 Seed Initialization
 * ============================================================================ */

static uint64_t splitmix64_next(uint64_t *x) {
    uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void xoshiro256_seed(uint64_t *state, uint64_t seed) {
    uint64_t x = seed;

    state[0] = splitmix64_next(&x);
    state[1] = splitmix64_next(&x);
    state[2] = splitmix64_next(&x);
    state[3] = splitmix64_next(&x);

    if (state[0] == 0 && state[1] == 0 && state[2] == 0 && state[3] == 0) {
        state[0] = 1;
    }
}

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

static uint64_t sn_random_next_u64(RtRandom *rng) {
    if (rng->is_seeded) {
        return xoshiro256_next((uint64_t *)(intptr_t)rng->state);
    } else {
        uint64_t result;
        sn_random_fill_entropy((uint8_t *)&result, sizeof(result));
        return result;
    }
}

static uint64_t sn_random_static_next_u64(void) {
    uint64_t result;
    sn_random_fill_entropy((uint8_t *)&result, sizeof(result));
    return result;
}

/* ============================================================================
 * Factory Functions
 * ============================================================================ */

RtRandom *sn_random_create(void)
{
    RtRandom *rng = (RtRandom *)calloc(1, sizeof(RtRandom));
    if (rng == NULL) {
        return NULL;
    }
    rng->is_seeded = 0;
    rng->state = (long long)(intptr_t)calloc(4, sizeof(uint64_t));

    sn_random_fill_entropy((uint8_t *)(intptr_t)rng->state, 4 * sizeof(uint64_t));

    return rng;
}

RtRandom *sn_random_create_with_seed(long long seed)
{
    RtRandom *rng = (RtRandom *)calloc(1, sizeof(RtRandom));
    if (rng == NULL) {
        return NULL;
    }
    rng->is_seeded = 1;
    rng->state = (long long)(intptr_t)calloc(4, sizeof(uint64_t));

    xoshiro256_seed((uint64_t *)(intptr_t)rng->state, (uint64_t)seed);

    return rng;
}

/* ============================================================================
 * Instance Value Generation (Seeded PRNG)
 * ============================================================================ */

long long sn_random_int(RtRandom *rng, long long min, long long max)
{
    if (rng == NULL) return 0;

    if (min > max) {
        long long tmp = min;
        min = max;
        max = tmp;
    }
    if (min == max) {
        return min;
    }

    uint64_t range = (uint64_t)(max - min) + 1;

    if ((range & (range - 1)) == 0) {
        uint64_t val = sn_random_next_u64(rng);
        return min + (long long)(val & (range - 1));
    }

    uint64_t threshold = (uint64_t)(-(int64_t)range) % range;
    uint64_t val;

    do {
        val = sn_random_next_u64(rng);
    } while (val < threshold);

    return min + (long long)(val % range);
}

long long sn_random_long(RtRandom *rng, long long min, long long max)
{
    if (rng == NULL) return 0;

    if (min > max) {
        long long tmp = min;
        min = max;
        max = tmp;
    }
    if (min == max) {
        return min;
    }

    uint64_t range = (uint64_t)(max - min) + 1;

    if ((range & (range - 1)) == 0) {
        uint64_t val = sn_random_next_u64(rng);
        return min + (long long)(val & (range - 1));
    }

    uint64_t threshold = (uint64_t)(-(int64_t)range) % range;
    uint64_t val;

    do {
        val = sn_random_next_u64(rng);
    } while (val < threshold);

    return min + (long long)(val % range);
}

double sn_random_double(RtRandom *rng, double min, double max)
{
    if (rng == NULL) return 0.0;

    if (min > max) {
        double tmp = min;
        min = max;
        max = tmp;
    }
    if (min == max) {
        return min;
    }

    uint64_t val = sn_random_next_u64(rng) >> 11;
    double normalized = (double)val / (double)(1ULL << 53);

    return min + normalized * (max - min);
}

long long sn_random_bool(RtRandom *rng)
{
    if (rng == NULL) return 0;
    return (sn_random_next_u64(rng) & 1) ? 1 : 0;
}

unsigned char sn_random_byte(RtRandom *rng)
{
    if (rng == NULL) return 0;
    return (unsigned char)(sn_random_next_u64(rng) & 0xFF);
}

SnArray *sn_random_bytes(RtRandom *rng, long long count)
{
    if (count <= 0) {
        SnArray *empty = sn_array_new(sizeof(unsigned char), 0);
        empty->elem_tag = SN_TAG_BYTE;
        return empty;
    }

    SnArray *result = sn_array_new(sizeof(unsigned char), (size_t)count);
    result->elem_tag = SN_TAG_BYTE;

    if (rng != NULL && rng->is_seeded) {
        for (long long i = 0; i < count; i++) {
            unsigned char b = sn_random_byte(rng);
            sn_array_push(result, &b);
        }
    } else {
        /* Fill with OS entropy directly */
        unsigned char *buf = (unsigned char *)malloc((size_t)count);
        if (buf == NULL) {
            return result;
        }
        sn_random_fill_entropy(buf, (size_t)count);
        for (long long i = 0; i < count; i++) {
            sn_array_push(result, &buf[i]);
        }
        free(buf);
    }

    return result;
}

double sn_random_gaussian(RtRandom *rng, double mean, double stddev)
{
    if (rng == NULL) return 0.0;

    double u1, u2;

    do {
        u1 = sn_random_double(rng, 0.0, 1.0);
    } while (u1 == 0.0);

    u2 = sn_random_double(rng, 0.0, 1.0);

    double mag = stddev * sqrt(-2.0 * log(u1));
    double z0 = mag * cos(2.0 * 3.14159265358979323846 * u2);

    return mean + z0;
}

/* ============================================================================
 * Static Value Generation (OS Entropy)
 * ============================================================================ */

long long sn_random_static_int(long long min, long long max)
{
    if (min > max) {
        long long tmp = min;
        min = max;
        max = tmp;
    }
    if (min == max) {
        return min;
    }

    uint64_t range = (uint64_t)(max - min) + 1;

    if ((range & (range - 1)) == 0) {
        uint64_t val = sn_random_static_next_u64();
        return min + (long long)(val & (range - 1));
    }

    uint64_t threshold = (uint64_t)(-(int64_t)range) % range;
    uint64_t val;

    do {
        val = sn_random_static_next_u64();
    } while (val < threshold);

    return min + (long long)(val % range);
}

long long sn_random_static_long(long long min, long long max)
{
    if (min > max) {
        long long tmp = min;
        min = max;
        max = tmp;
    }
    if (min == max) {
        return min;
    }

    uint64_t range = (uint64_t)(max - min) + 1;

    if ((range & (range - 1)) == 0) {
        uint64_t val = sn_random_static_next_u64();
        return min + (long long)(val & (range - 1));
    }

    uint64_t threshold = (uint64_t)(-(int64_t)range) % range;
    uint64_t val;

    do {
        val = sn_random_static_next_u64();
    } while (val < threshold);

    return min + (long long)(val % range);
}

double sn_random_static_double(double min, double max)
{
    if (min > max) {
        double tmp = min;
        min = max;
        max = tmp;
    }
    if (min == max) {
        return min;
    }

    uint64_t val = sn_random_static_next_u64() >> 11;
    double normalized = (double)val / (double)(1ULL << 53);

    return min + normalized * (max - min);
}

long long sn_random_static_bool(void)
{
    return (sn_random_static_next_u64() & 1) ? 1 : 0;
}

unsigned char sn_random_static_byte(void)
{
    unsigned char result;
    sn_random_fill_entropy(&result, 1);
    return result;
}

SnArray *sn_random_static_bytes(long long count)
{
    if (count <= 0) {
        SnArray *empty = sn_array_new(sizeof(unsigned char), 0);
        empty->elem_tag = SN_TAG_BYTE;
        return empty;
    }

    SnArray *result = sn_array_new(sizeof(unsigned char), (size_t)count);
    result->elem_tag = SN_TAG_BYTE;

    unsigned char *buf = (unsigned char *)malloc((size_t)count);
    if (buf == NULL) {
        return result;
    }

    sn_random_fill_entropy(buf, (size_t)count);
    for (long long i = 0; i < count; i++) {
        sn_array_push(result, &buf[i]);
    }

    free(buf);
    return result;
}

double sn_random_static_gaussian(double mean, double stddev)
{
    double u1, u2;

    do {
        u1 = sn_random_static_double(0.0, 1.0);
    } while (u1 == 0.0);

    u2 = sn_random_static_double(0.0, 1.0);

    double mag = stddev * sqrt(-2.0 * log(u1));
    double z0 = mag * cos(2.0 * 3.14159265358979323846 * u2);

    return mean + z0;
}

/* ============================================================================
 * Static Batch Generation (OS Entropy)
 * ============================================================================ */

SnArray *sn_random_static_int_many(long long min, long long max, long long count)
{
    if (count <= 0) {
        SnArray *empty = sn_array_new(sizeof(long long), 0);
        empty->elem_tag = SN_TAG_INT;
        return empty;
    }

    SnArray *result = sn_array_new(sizeof(long long), (size_t)count);
    result->elem_tag = SN_TAG_INT;

    for (long long i = 0; i < count; i++) {
        long long val = sn_random_static_int(min, max);
        sn_array_push(result, &val);
    }

    return result;
}

SnArray *sn_random_static_long_many(long long min, long long max, long long count)
{
    if (count <= 0) {
        SnArray *empty = sn_array_new(sizeof(long long), 0);
        empty->elem_tag = SN_TAG_INT;
        return empty;
    }

    SnArray *result = sn_array_new(sizeof(long long), (size_t)count);
    result->elem_tag = SN_TAG_INT;

    for (long long i = 0; i < count; i++) {
        long long val = sn_random_static_long(min, max);
        sn_array_push(result, &val);
    }

    return result;
}

SnArray *sn_random_static_double_many(double min, double max, long long count)
{
    if (count <= 0) {
        SnArray *empty = sn_array_new(sizeof(double), 0);
        empty->elem_tag = SN_TAG_DOUBLE;
        return empty;
    }

    SnArray *result = sn_array_new(sizeof(double), (size_t)count);
    result->elem_tag = SN_TAG_DOUBLE;

    for (long long i = 0; i < count; i++) {
        double val = sn_random_static_double(min, max);
        sn_array_push(result, &val);
    }

    return result;
}

SnArray *sn_random_static_bool_many(long long count)
{
    if (count <= 0) {
        SnArray *empty = sn_array_new(sizeof(bool), 0);
        empty->elem_tag = SN_TAG_BOOL;
        return empty;
    }

    SnArray *result = sn_array_new(sizeof(bool), (size_t)count);
    result->elem_tag = SN_TAG_BOOL;

    for (long long i = 0; i < count; i++) {
        bool val = sn_random_static_bool() != 0;
        sn_array_push(result, &val);
    }

    return result;
}

SnArray *sn_random_static_gaussian_many(double mean, double stddev, long long count)
{
    if (count <= 0) {
        SnArray *empty = sn_array_new(sizeof(double), 0);
        empty->elem_tag = SN_TAG_DOUBLE;
        return empty;
    }

    SnArray *result = sn_array_new(sizeof(double), (size_t)count);
    result->elem_tag = SN_TAG_DOUBLE;

    for (long long i = 0; i < count; i++) {
        double val = sn_random_static_gaussian(mean, stddev);
        sn_array_push(result, &val);
    }

    return result;
}

/* ============================================================================
 * Instance Batch Generation (Seeded PRNG)
 * ============================================================================ */

SnArray *sn_random_int_many(RtRandom *rng, long long min, long long max, long long count)
{
    if (count <= 0 || rng == NULL) {
        SnArray *empty = sn_array_new(sizeof(long long), 0);
        empty->elem_tag = SN_TAG_INT;
        return empty;
    }

    SnArray *result = sn_array_new(sizeof(long long), (size_t)count);
    result->elem_tag = SN_TAG_INT;

    for (long long i = 0; i < count; i++) {
        long long val = sn_random_int(rng, min, max);
        sn_array_push(result, &val);
    }

    return result;
}

SnArray *sn_random_long_many(RtRandom *rng, long long min, long long max, long long count)
{
    if (count <= 0 || rng == NULL) {
        SnArray *empty = sn_array_new(sizeof(long long), 0);
        empty->elem_tag = SN_TAG_INT;
        return empty;
    }

    SnArray *result = sn_array_new(sizeof(long long), (size_t)count);
    result->elem_tag = SN_TAG_INT;

    for (long long i = 0; i < count; i++) {
        long long val = sn_random_long(rng, min, max);
        sn_array_push(result, &val);
    }

    return result;
}

SnArray *sn_random_double_many(RtRandom *rng, double min, double max, long long count)
{
    if (count <= 0 || rng == NULL) {
        SnArray *empty = sn_array_new(sizeof(double), 0);
        empty->elem_tag = SN_TAG_DOUBLE;
        return empty;
    }

    SnArray *result = sn_array_new(sizeof(double), (size_t)count);
    result->elem_tag = SN_TAG_DOUBLE;

    for (long long i = 0; i < count; i++) {
        double val = sn_random_double(rng, min, max);
        sn_array_push(result, &val);
    }

    return result;
}

SnArray *sn_random_bool_many(RtRandom *rng, long long count)
{
    if (count <= 0 || rng == NULL) {
        SnArray *empty = sn_array_new(sizeof(bool), 0);
        empty->elem_tag = SN_TAG_BOOL;
        return empty;
    }

    SnArray *result = sn_array_new(sizeof(bool), (size_t)count);
    result->elem_tag = SN_TAG_BOOL;

    for (long long i = 0; i < count; i++) {
        bool val = sn_random_bool(rng) != 0;
        sn_array_push(result, &val);
    }

    return result;
}

SnArray *sn_random_gaussian_many(RtRandom *rng, double mean, double stddev, long long count)
{
    if (count <= 0 || rng == NULL) {
        SnArray *empty = sn_array_new(sizeof(double), 0);
        empty->elem_tag = SN_TAG_DOUBLE;
        return empty;
    }

    SnArray *result = sn_array_new(sizeof(double), (size_t)count);
    result->elem_tag = SN_TAG_DOUBLE;

    for (long long i = 0; i < count; i++) {
        double val = sn_random_gaussian(rng, mean, stddev);
        sn_array_push(result, &val);
    }

    return result;
}

/* ============================================================================
 * Static Collection Operations (OS Entropy) - Choice
 * ============================================================================ */

long long sn_random_static_choice_int(SnArray *arr)
{
    if (arr == NULL) return 0;
    long long len = (long long)sn_array_length(arr);
    if (len <= 0) return 0;

    long long *data = (long long *)arr->data;
    long long index = sn_random_static_int(0, len - 1);
    return data[index];
}

long long sn_random_static_choice_long(SnArray *arr)
{
    if (arr == NULL) return 0;
    long long len = (long long)sn_array_length(arr);
    if (len <= 0) return 0;

    long long *data = (long long *)arr->data;
    long long index = sn_random_static_int(0, len - 1);
    return data[index];
}

double sn_random_static_choice_double(SnArray *arr)
{
    if (arr == NULL) return 0.0;
    long long len = (long long)sn_array_length(arr);
    if (len <= 0) return 0.0;

    double *data = (double *)arr->data;
    long long index = sn_random_static_int(0, len - 1);
    return data[index];
}

char *sn_random_static_choice_str(SnArray *arr)
{
    if (arr == NULL) return NULL;
    long long len = (long long)sn_array_length(arr);
    if (len <= 0) return NULL;

    char **data = (char **)arr->data;
    long long index = sn_random_static_int(0, len - 1);
    return strdup(data[index]);
}

long long sn_random_static_choice_bool(SnArray *arr)
{
    if (arr == NULL) return 0;
    long long len = (long long)sn_array_length(arr);
    if (len <= 0) return 0;

    bool *data = (bool *)arr->data;
    long long index = sn_random_static_int(0, len - 1);
    return data[index] ? 1 : 0;
}

unsigned char sn_random_static_choice_byte(SnArray *arr)
{
    if (arr == NULL) return 0;
    long long len = (long long)sn_array_length(arr);
    if (len <= 0) return 0;

    unsigned char *data = (unsigned char *)arr->data;
    long long index = sn_random_static_int(0, len - 1);
    return data[index];
}

/* ============================================================================
 * Weight Validation Helper
 * ============================================================================ */

static int sn_random_validate_weights(double *weights, long long len)
{
    if (weights == NULL || len <= 0) {
        return 0;
    }

    double sum = 0.0;
    for (long long i = 0; i < len; i++) {
        if (weights[i] <= 0.0) {
            return 0;
        }
        sum += weights[i];
    }

    if (sum <= 0.0) {
        return 0;
    }

    return 1;
}

static double *sn_random_build_cumulative(double *weights, long long len)
{
    if (weights == NULL || len <= 0) {
        return NULL;
    }

    double sum = 0.0;
    for (long long i = 0; i < len; i++) {
        sum += weights[i];
    }

    if (sum <= 0.0) {
        return NULL;
    }

    double *cumulative = (double *)malloc((size_t)len * sizeof(double));
    if (cumulative == NULL) {
        return NULL;
    }

    double running_sum = 0.0;
    for (long long i = 0; i < len; i++) {
        running_sum += weights[i] / sum;
        cumulative[i] = running_sum;
    }

    cumulative[len - 1] = 1.0;

    return cumulative;
}

static long long sn_random_select_weighted_index(double random_val, double *cumulative, long long len)
{
    if (cumulative == NULL || len <= 0) {
        return 0;
    }

    if (len == 1) {
        return 0;
    }

    if (random_val >= 1.0) {
        return len - 1;
    }

    if (random_val <= 0.0) {
        return 0;
    }

    long long left = 0;
    long long right = len - 1;

    while (left < right) {
        long long mid = left + (right - left) / 2;

        if (cumulative[mid] > random_val) {
            right = mid;
        } else {
            left = mid + 1;
        }
    }

    return left;
}

/* ============================================================================
 * Static Collection Operations (OS Entropy) - Weighted Choice
 * ============================================================================ */

long long sn_random_static_weighted_choice_int(SnArray *arr, SnArray *weights_arr)
{
    if (arr == NULL || weights_arr == NULL) {
        return 0;
    }

    long long len = (long long)sn_array_length(arr);
    if (len <= 0) {
        return 0;
    }

    long long *data = (long long *)arr->data;
    double *weights = (double *)weights_arr->data;

    if (!sn_random_validate_weights(weights, len)) {
        return 0;
    }

    double *cumulative = sn_random_build_cumulative(weights, len);
    if (cumulative == NULL) {
        return 0;
    }

    double random_val = sn_random_static_double(0.0, 1.0);
    long long index = sn_random_select_weighted_index(random_val, cumulative, len);
    long long result = data[index];

    free(cumulative);

    return result;
}

long long sn_random_static_weighted_choice_long(SnArray *arr, SnArray *weights_arr)
{
    return sn_random_static_weighted_choice_int(arr, weights_arr);
}

double sn_random_static_weighted_choice_double(SnArray *arr, SnArray *weights_arr)
{
    if (arr == NULL || weights_arr == NULL) {
        return 0.0;
    }

    long long len = (long long)sn_array_length(arr);
    if (len <= 0) {
        return 0.0;
    }

    double *data = (double *)arr->data;
    double *weights = (double *)weights_arr->data;

    if (!sn_random_validate_weights(weights, len)) {
        return 0.0;
    }

    double *cumulative = sn_random_build_cumulative(weights, len);
    if (cumulative == NULL) {
        return 0.0;
    }

    double random_val = sn_random_static_double(0.0, 1.0);
    long long index = sn_random_select_weighted_index(random_val, cumulative, len);
    double result = data[index];

    free(cumulative);

    return result;
}

char *sn_random_static_weighted_choice_str(SnArray *arr, SnArray *weights_arr)
{
    if (arr == NULL || weights_arr == NULL) {
        return NULL;
    }

    long long len = (long long)sn_array_length(arr);
    if (len <= 0) {
        return NULL;
    }

    char **data = (char **)arr->data;
    double *weights = (double *)weights_arr->data;

    if (!sn_random_validate_weights(weights, len)) {
        return NULL;
    }

    double *cumulative = sn_random_build_cumulative(weights, len);
    if (cumulative == NULL) {
        return NULL;
    }

    double random_val = sn_random_static_double(0.0, 1.0);
    long long index = sn_random_select_weighted_index(random_val, cumulative, len);
    char *result = strdup(data[index]);

    free(cumulative);

    return result;
}

/* ============================================================================
 * Static Collection Operations (OS Entropy) - Shuffle
 * ============================================================================ */

void sn_random_static_shuffle_int(SnArray *arr)
{
    if (arr == NULL) {
        return;
    }

    size_t n = sn_array_length(arr);
    if (n <= 1) {
        return;
    }

    long long *data = (long long *)arr->data;
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_static_int(0, (long long)i);

        long long temp = data[i];
        data[i] = data[j];
        data[j] = temp;
    }
}

void sn_random_static_shuffle_long(SnArray *arr)
{
    sn_random_static_shuffle_int(arr);
}

void sn_random_static_shuffle_double(SnArray *arr)
{
    if (arr == NULL) {
        return;
    }

    size_t n = sn_array_length(arr);
    if (n <= 1) {
        return;
    }

    double *data = (double *)arr->data;
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_static_int(0, (long long)i);

        double temp = data[i];
        data[i] = data[j];
        data[j] = temp;
    }
}

void sn_random_static_shuffle_str(SnArray *arr)
{
    if (arr == NULL) {
        return;
    }

    size_t n = sn_array_length(arr);
    if (n <= 1) {
        return;
    }

    char **data = (char **)arr->data;
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_static_int(0, (long long)i);

        char *temp = data[i];
        data[i] = data[j];
        data[j] = temp;
    }
}

void sn_random_static_shuffle_bool(SnArray *arr)
{
    if (arr == NULL) {
        return;
    }

    size_t n = sn_array_length(arr);
    if (n <= 1) {
        return;
    }

    bool *data = (bool *)arr->data;
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_static_int(0, (long long)i);

        bool temp = data[i];
        data[i] = data[j];
        data[j] = temp;
    }
}

void sn_random_static_shuffle_byte(SnArray *arr)
{
    if (arr == NULL) {
        return;
    }

    size_t n = sn_array_length(arr);
    if (n <= 1) {
        return;
    }

    unsigned char *data = (unsigned char *)arr->data;
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_static_int(0, (long long)i);

        unsigned char temp = data[i];
        data[i] = data[j];
        data[j] = temp;
    }
}

/* ============================================================================
 * Static Collection Operations (OS Entropy) - Sample
 * ============================================================================ */

SnArray *sn_random_static_sample_int(SnArray *arr, long long count)
{
    if (arr == NULL) {
        return NULL;
    }

    if (count <= 0) {
        return NULL;
    }

    size_t n = sn_array_length(arr);

    if (count > (long long)n) {
        return NULL;
    }

    long long *src = (long long *)arr->data;

    /* Allocate temporary buffer for shuffle */
    long long *temp = (long long *)malloc(n * sizeof(long long));
    if (temp == NULL) {
        return NULL;
    }
    memcpy(temp, src, n * sizeof(long long));

    SnArray *result = sn_array_new(sizeof(long long), (size_t)count);
    result->elem_tag = SN_TAG_INT;

    for (long long i = 0; i < count; i++) {
        size_t j = (size_t)sn_random_static_int(i, (long long)(n - 1));

        long long swap = temp[i];
        temp[i] = temp[j];
        temp[j] = swap;

        sn_array_push(result, &temp[i]);
    }

    free(temp);

    return result;
}

SnArray *sn_random_static_sample_long(SnArray *arr, long long count)
{
    return sn_random_static_sample_int(arr, count);
}

SnArray *sn_random_static_sample_double(SnArray *arr, long long count)
{
    if (arr == NULL) {
        return NULL;
    }

    if (count <= 0) {
        return NULL;
    }

    size_t n = sn_array_length(arr);

    if (count > (long long)n) {
        return NULL;
    }

    double *src = (double *)arr->data;

    /* Allocate temporary buffer for shuffle */
    double *temp = (double *)malloc(n * sizeof(double));
    if (temp == NULL) {
        return NULL;
    }
    memcpy(temp, src, n * sizeof(double));

    SnArray *result = sn_array_new(sizeof(double), (size_t)count);
    result->elem_tag = SN_TAG_DOUBLE;

    for (long long i = 0; i < count; i++) {
        size_t j = (size_t)sn_random_static_int(i, (long long)(n - 1));

        double swap = temp[i];
        temp[i] = temp[j];
        temp[j] = swap;

        sn_array_push(result, &temp[i]);
    }

    free(temp);

    return result;
}

SnArray *sn_random_static_sample_str(SnArray *arr, long long count)
{
    if (arr == NULL) {
        return NULL;
    }

    if (count <= 0) {
        return NULL;
    }

    size_t n = sn_array_length(arr);

    if (count > (long long)n) {
        return NULL;
    }

    char **src = (char **)arr->data;

    /* Allocate temporary buffer for shuffle (pointers only, no strdup yet) */
    char **temp = (char **)malloc(n * sizeof(char *));
    if (temp == NULL) {
        return NULL;
    }
    memcpy(temp, src, n * sizeof(char *));

    SnArray *result = sn_array_new(sizeof(char *), (size_t)count);
    result->elem_tag = SN_TAG_STRING;
    result->elem_release = (void (*)(void *))sn_cleanup_str;
    result->elem_copy = sn_copy_str;

    for (long long i = 0; i < count; i++) {
        size_t j = (size_t)sn_random_static_int(i, (long long)(n - 1));

        char *swap = temp[i];
        temp[i] = temp[j];
        temp[j] = swap;

        char *dup = strdup(temp[i]);
        sn_array_push(result, &dup);
    }

    free(temp);

    return result;
}

/* ============================================================================
 * Instance Collection Operations (Seeded PRNG) - Choice
 * ============================================================================ */

long long sn_random_choice_int(RtRandom *rng, SnArray *arr)
{
    if (rng == NULL || arr == NULL) return 0;
    long long len = (long long)sn_array_length(arr);
    if (len <= 0) return 0;

    long long *data = (long long *)arr->data;
    long long index = sn_random_int(rng, 0, len - 1);
    return data[index];
}

long long sn_random_choice_long(RtRandom *rng, SnArray *arr)
{
    if (rng == NULL) return 0;
    return sn_random_choice_int(rng, arr);
}

double sn_random_choice_double(RtRandom *rng, SnArray *arr)
{
    if (rng == NULL || arr == NULL) return 0.0;
    long long len = (long long)sn_array_length(arr);
    if (len <= 0) return 0.0;

    double *data = (double *)arr->data;
    long long index = sn_random_int(rng, 0, len - 1);
    return data[index];
}

char *sn_random_choice_str(RtRandom *rng, SnArray *arr)
{
    if (rng == NULL || arr == NULL) return NULL;
    long long len = (long long)sn_array_length(arr);
    if (len <= 0) return NULL;

    char **data = (char **)arr->data;
    long long index = sn_random_int(rng, 0, len - 1);
    return strdup(data[index]);
}

long long sn_random_choice_bool(RtRandom *rng, SnArray *arr)
{
    if (rng == NULL || arr == NULL) return 0;
    long long len = (long long)sn_array_length(arr);
    if (len <= 0) return 0;

    bool *data = (bool *)arr->data;
    long long index = sn_random_int(rng, 0, len - 1);
    return data[index] ? 1 : 0;
}

unsigned char sn_random_choice_byte(RtRandom *rng, SnArray *arr)
{
    if (rng == NULL || arr == NULL) return 0;
    long long len = (long long)sn_array_length(arr);
    if (len <= 0) return 0;

    unsigned char *data = (unsigned char *)arr->data;
    long long index = sn_random_int(rng, 0, len - 1);
    return data[index];
}

/* ============================================================================
 * Instance Collection Operations (Seeded PRNG) - Weighted Choice
 * ============================================================================ */

long long sn_random_weighted_choice_int(RtRandom *rng, SnArray *arr, SnArray *weights_arr)
{
    if (rng == NULL || arr == NULL || weights_arr == NULL) {
        return 0;
    }

    long long len = (long long)sn_array_length(arr);
    if (len <= 0) {
        return 0;
    }

    long long *data = (long long *)arr->data;
    double *weights = (double *)weights_arr->data;

    if (!sn_random_validate_weights(weights, len)) {
        return 0;
    }

    double *cumulative = sn_random_build_cumulative(weights, len);
    if (cumulative == NULL) {
        return 0;
    }

    double random_val = sn_random_double(rng, 0.0, 1.0);
    long long index = sn_random_select_weighted_index(random_val, cumulative, len);
    long long result = data[index];

    free(cumulative);

    return result;
}

long long sn_random_weighted_choice_long(RtRandom *rng, SnArray *arr, SnArray *weights_arr)
{
    if (rng == NULL) return 0;
    return sn_random_weighted_choice_int(rng, arr, weights_arr);
}

double sn_random_weighted_choice_double(RtRandom *rng, SnArray *arr, SnArray *weights_arr)
{
    if (rng == NULL || arr == NULL || weights_arr == NULL) {
        return 0.0;
    }

    long long len = (long long)sn_array_length(arr);
    if (len <= 0) {
        return 0.0;
    }

    double *data = (double *)arr->data;
    double *weights = (double *)weights_arr->data;

    if (!sn_random_validate_weights(weights, len)) {
        return 0.0;
    }

    double *cumulative = sn_random_build_cumulative(weights, len);
    if (cumulative == NULL) {
        return 0.0;
    }

    double random_val = sn_random_double(rng, 0.0, 1.0);
    long long index = sn_random_select_weighted_index(random_val, cumulative, len);
    double result = data[index];

    free(cumulative);

    return result;
}

char *sn_random_weighted_choice_str(RtRandom *rng, SnArray *arr, SnArray *weights_arr)
{
    if (rng == NULL || arr == NULL || weights_arr == NULL) {
        return NULL;
    }

    long long len = (long long)sn_array_length(arr);
    if (len <= 0) {
        return NULL;
    }

    char **data = (char **)arr->data;
    double *weights = (double *)weights_arr->data;

    if (!sn_random_validate_weights(weights, len)) {
        return NULL;
    }

    double *cumulative = sn_random_build_cumulative(weights, len);
    if (cumulative == NULL) {
        return NULL;
    }

    double random_val = sn_random_double(rng, 0.0, 1.0);
    long long index = sn_random_select_weighted_index(random_val, cumulative, len);
    char *result = strdup(data[index]);

    free(cumulative);

    return result;
}

/* ============================================================================
 * Instance Collection Operations (Seeded PRNG) - Shuffle
 * ============================================================================ */

void sn_random_shuffle_int(RtRandom *rng, SnArray *arr)
{
    if (rng == NULL || arr == NULL) {
        return;
    }

    size_t n = sn_array_length(arr);
    if (n <= 1) {
        return;
    }

    long long *data = (long long *)arr->data;
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_int(rng, 0, (long long)i);

        long long temp = data[i];
        data[i] = data[j];
        data[j] = temp;
    }
}

void sn_random_shuffle_long(RtRandom *rng, SnArray *arr)
{
    if (rng == NULL) return;
    sn_random_shuffle_int(rng, arr);
}

void sn_random_shuffle_double(RtRandom *rng, SnArray *arr)
{
    if (rng == NULL || arr == NULL) {
        return;
    }

    size_t n = sn_array_length(arr);
    if (n <= 1) {
        return;
    }

    double *data = (double *)arr->data;
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_int(rng, 0, (long long)i);

        double temp = data[i];
        data[i] = data[j];
        data[j] = temp;
    }
}

void sn_random_shuffle_str(RtRandom *rng, SnArray *arr)
{
    if (rng == NULL || arr == NULL) {
        return;
    }

    size_t n = sn_array_length(arr);
    if (n <= 1) {
        return;
    }

    char **data = (char **)arr->data;
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_int(rng, 0, (long long)i);

        char *temp = data[i];
        data[i] = data[j];
        data[j] = temp;
    }
}

void sn_random_shuffle_bool(RtRandom *rng, SnArray *arr)
{
    if (rng == NULL || arr == NULL) {
        return;
    }

    size_t n = sn_array_length(arr);
    if (n <= 1) {
        return;
    }

    bool *data = (bool *)arr->data;
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_int(rng, 0, (long long)i);

        bool temp = data[i];
        data[i] = data[j];
        data[j] = temp;
    }
}

void sn_random_shuffle_byte(RtRandom *rng, SnArray *arr)
{
    if (rng == NULL || arr == NULL) {
        return;
    }

    size_t n = sn_array_length(arr);
    if (n <= 1) {
        return;
    }

    unsigned char *data = (unsigned char *)arr->data;
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_int(rng, 0, (long long)i);

        unsigned char temp = data[i];
        data[i] = data[j];
        data[j] = temp;
    }
}

/* ============================================================================
 * Instance Collection Operations (Seeded PRNG) - Sample
 * ============================================================================ */

SnArray *sn_random_sample_int(RtRandom *rng, SnArray *arr, long long count)
{
    if (rng == NULL || arr == NULL) {
        return NULL;
    }

    if (count <= 0) {
        return NULL;
    }

    size_t n = sn_array_length(arr);

    if (count > (long long)n) {
        return NULL;
    }

    long long *src = (long long *)arr->data;

    /* Allocate temporary buffer for shuffle */
    long long *temp = (long long *)malloc(n * sizeof(long long));
    if (temp == NULL) {
        return NULL;
    }
    memcpy(temp, src, n * sizeof(long long));

    SnArray *result = sn_array_new(sizeof(long long), (size_t)count);
    result->elem_tag = SN_TAG_INT;

    for (long long i = 0; i < count; i++) {
        size_t j = (size_t)sn_random_int(rng, i, (long long)(n - 1));

        long long swap = temp[i];
        temp[i] = temp[j];
        temp[j] = swap;

        sn_array_push(result, &temp[i]);
    }

    free(temp);

    return result;
}

SnArray *sn_random_sample_long(RtRandom *rng, SnArray *arr, long long count)
{
    if (rng == NULL) return NULL;
    return sn_random_sample_int(rng, arr, count);
}

SnArray *sn_random_sample_double(RtRandom *rng, SnArray *arr, long long count)
{
    if (rng == NULL || arr == NULL) {
        return NULL;
    }

    if (count <= 0) {
        return NULL;
    }

    size_t n = sn_array_length(arr);

    if (count > (long long)n) {
        return NULL;
    }

    double *src = (double *)arr->data;

    /* Allocate temporary buffer for shuffle */
    double *temp = (double *)malloc(n * sizeof(double));
    if (temp == NULL) {
        return NULL;
    }
    memcpy(temp, src, n * sizeof(double));

    SnArray *result = sn_array_new(sizeof(double), (size_t)count);
    result->elem_tag = SN_TAG_DOUBLE;

    for (long long i = 0; i < count; i++) {
        size_t j = (size_t)sn_random_int(rng, i, (long long)(n - 1));

        double swap = temp[i];
        temp[i] = temp[j];
        temp[j] = swap;

        sn_array_push(result, &temp[i]);
    }

    free(temp);

    return result;
}

SnArray *sn_random_sample_str(RtRandom *rng, SnArray *arr, long long count)
{
    if (rng == NULL || arr == NULL) {
        return NULL;
    }

    if (count <= 0) {
        return NULL;
    }

    size_t n = sn_array_length(arr);

    if (count > (long long)n) {
        return NULL;
    }

    char **src = (char **)arr->data;

    /* Allocate temporary buffer for shuffle (pointers only, no strdup yet) */
    char **temp = (char **)malloc(n * sizeof(char *));
    if (temp == NULL) {
        return NULL;
    }
    memcpy(temp, src, n * sizeof(char *));

    SnArray *result = sn_array_new(sizeof(char *), (size_t)count);
    result->elem_tag = SN_TAG_STRING;
    result->elem_release = (void (*)(void *))sn_cleanup_str;
    result->elem_copy = sn_copy_str;

    for (long long i = 0; i < count; i++) {
        size_t j = (size_t)sn_random_int(rng, i, (long long)(n - 1));

        char *swap = temp[i];
        temp[i] = temp[j];
        temp[j] = swap;

        char *dup = strdup(temp[i]);
        sn_array_push(result, &dup);
    }

    free(temp);

    return result;
}
