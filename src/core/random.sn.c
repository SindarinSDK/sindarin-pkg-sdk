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
#include <math.h>
#include <errno.h>

/* Include runtime headers for arena and array only */
#include "runtime/array/runtime_array_v2.h"

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

typedef struct RtRandom {
    int is_seeded;          /* 0 = OS entropy, 1 = seeded PRNG */
    uint64_t state[4];      /* PRNG state (xoshiro256** algorithm) */
} RtRandom;

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
        return xoshiro256_next(rng->state);
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

RtRandom *sn_random_create(RtArenaV2 *arena)
{
    if (arena == NULL) {
        return NULL;
    }

    RtHandleV2 *_rng_h = rt_arena_v2_alloc(arena, sizeof(RtRandom));
    RtRandom *rng = (RtRandom *)_rng_h->ptr;
    rng->is_seeded = 0;

    sn_random_fill_entropy((uint8_t *)rng->state, sizeof(rng->state));

    return rng;
}

RtRandom *sn_random_create_with_seed(RtArenaV2 *arena, long long seed)
{
    if (arena == NULL) {
        return NULL;
    }

    RtHandleV2 *_rng_h = rt_arena_v2_alloc(arena, sizeof(RtRandom));
    RtRandom *rng = (RtRandom *)_rng_h->ptr;
    rng->is_seeded = 1;

    xoshiro256_seed(rng->state, (uint64_t)seed);

    return rng;
}

/* ============================================================================
 * Instance Value Generation (Seeded PRNG)
 * ============================================================================ */

long sn_random_int(RtRandom *rng, long min, long max)
{
    if (min > max) {
        long tmp = min;
        min = max;
        max = tmp;
    }
    if (min == max) {
        return min;
    }

    uint64_t range = (uint64_t)(max - min) + 1;

    if ((range & (range - 1)) == 0) {
        uint64_t val = sn_random_next_u64(rng);
        return min + (long)(val & (range - 1));
    }

    uint64_t threshold = (uint64_t)(-(int64_t)range) % range;
    uint64_t val;

    do {
        val = sn_random_next_u64(rng);
    } while (val < threshold);

    return min + (long)(val % range);
}

long long sn_random_long(RtRandom *rng, long long min, long long max)
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

int sn_random_bool(RtRandom *rng)
{
    return (sn_random_next_u64(rng) & 1) ? 1 : 0;
}

unsigned char sn_random_byte(RtRandom *rng)
{
    return (unsigned char)(sn_random_next_u64(rng) & 0xFF);
}

RtHandleV2 *sn_random_bytes(RtArenaV2 *arena, RtRandom *rng, long count)
{
    if (arena == NULL || count <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    /* Allocate temporary buffer for byte data */
    unsigned char *buf = (unsigned char *)malloc((size_t)count);
    if (buf == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    if (rng->is_seeded) {
        for (long i = 0; i < count; i++) {
            buf[i] = sn_random_byte(rng);
        }
    } else {
        sn_random_fill_entropy(buf, (size_t)count);
    }

    /* Create handle-based array from temporary buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(unsigned char), buf);
    free(buf);
    return result;
}

double sn_random_gaussian(RtRandom *rng, double mean, double stddev)
{
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

long sn_random_static_int(long min, long max)
{
    if (min > max) {
        long tmp = min;
        min = max;
        max = tmp;
    }
    if (min == max) {
        return min;
    }

    uint64_t range = (uint64_t)(max - min) + 1;

    if ((range & (range - 1)) == 0) {
        uint64_t val = sn_random_static_next_u64();
        return min + (long)(val & (range - 1));
    }

    uint64_t threshold = (uint64_t)(-(int64_t)range) % range;
    uint64_t val;

    do {
        val = sn_random_static_next_u64();
    } while (val < threshold);

    return min + (long)(val % range);
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

int sn_random_static_bool(void)
{
    return (sn_random_static_next_u64() & 1) ? 1 : 0;
}

unsigned char sn_random_static_byte(void)
{
    unsigned char result;
    sn_random_fill_entropy(&result, 1);
    return result;
}

RtHandleV2 *sn_random_static_bytes(RtArenaV2 *arena, long count)
{
    if (arena == NULL || count <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    /* Allocate temporary buffer for byte data */
    unsigned char *buf = (unsigned char *)malloc((size_t)count);
    if (buf == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(unsigned char), NULL);
    }

    sn_random_fill_entropy(buf, (size_t)count);

    /* Create handle-based array from temporary buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(unsigned char), buf);
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

RtHandleV2 *sn_random_static_int_many(RtArenaV2 *arena, long min, long max, long count)
{
    if (arena == NULL || count <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(long long), NULL);
    }

    /* Allocate temporary buffer */
    long long *buf = (long long *)malloc((size_t)count * sizeof(long long));
    if (buf == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(long long), NULL);
    }

    for (long i = 0; i < count; i++) {
        buf[i] = sn_random_static_int(min, max);
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(long long), buf);
    free(buf);
    return result;
}

RtHandleV2 *sn_random_static_long_many(RtArenaV2 *arena, long long min, long long max, long count)
{
    if (arena == NULL || count <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(long long), NULL);
    }

    /* Allocate temporary buffer */
    long long *buf = (long long *)malloc((size_t)count * sizeof(long long));
    if (buf == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(long long), NULL);
    }

    for (long i = 0; i < count; i++) {
        buf[i] = sn_random_static_long(min, max);
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(long long), buf);
    free(buf);
    return result;
}

RtHandleV2 *sn_random_static_double_many(RtArenaV2 *arena, double min, double max, long count)
{
    if (arena == NULL || count <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(double), NULL);
    }

    /* Allocate temporary buffer */
    double *buf = (double *)malloc((size_t)count * sizeof(double));
    if (buf == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(double), NULL);
    }

    for (long i = 0; i < count; i++) {
        buf[i] = sn_random_static_double(min, max);
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(double), buf);
    free(buf);
    return result;
}

RtHandleV2 *sn_random_static_bool_many(RtArenaV2 *arena, long count)
{
    if (arena == NULL || count <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(int), NULL);
    }

    /* Allocate temporary buffer */
    int *buf = (int *)malloc((size_t)count * sizeof(int));
    if (buf == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(int), NULL);
    }

    for (long i = 0; i < count; i++) {
        buf[i] = sn_random_static_bool();
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(int), buf);
    free(buf);
    return result;
}

RtHandleV2 *sn_random_static_gaussian_many(RtArenaV2 *arena, double mean, double stddev, long count)
{
    if (arena == NULL || count <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(double), NULL);
    }

    /* Allocate temporary buffer */
    double *buf = (double *)malloc((size_t)count * sizeof(double));
    if (buf == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(double), NULL);
    }

    for (long i = 0; i < count; i++) {
        buf[i] = sn_random_static_gaussian(mean, stddev);
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(double), buf);
    free(buf);
    return result;
}

/* ============================================================================
 * Instance Batch Generation (Seeded PRNG)
 * ============================================================================ */

RtHandleV2 *sn_random_int_many(RtArenaV2 *arena, RtRandom *rng, long min, long max, long count)
{
    if (arena == NULL || count <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(long long), NULL);
    }

    /* Allocate temporary buffer */
    long long *buf = (long long *)malloc((size_t)count * sizeof(long long));
    if (buf == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(long long), NULL);
    }

    for (long i = 0; i < count; i++) {
        buf[i] = sn_random_int(rng, min, max);
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(long long), buf);
    free(buf);
    return result;
}

RtHandleV2 *sn_random_long_many(RtArenaV2 *arena, RtRandom *rng, long long min, long long max, long count)
{
    if (arena == NULL || count <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(long long), NULL);
    }

    /* Allocate temporary buffer */
    long long *buf = (long long *)malloc((size_t)count * sizeof(long long));
    if (buf == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(long long), NULL);
    }

    for (long i = 0; i < count; i++) {
        buf[i] = sn_random_long(rng, min, max);
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(long long), buf);
    free(buf);
    return result;
}

RtHandleV2 *sn_random_double_many(RtArenaV2 *arena, RtRandom *rng, double min, double max, long count)
{
    if (arena == NULL || count <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(double), NULL);
    }

    /* Allocate temporary buffer */
    double *buf = (double *)malloc((size_t)count * sizeof(double));
    if (buf == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(double), NULL);
    }

    for (long i = 0; i < count; i++) {
        buf[i] = sn_random_double(rng, min, max);
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(double), buf);
    free(buf);
    return result;
}

RtHandleV2 *sn_random_bool_many(RtArenaV2 *arena, RtRandom *rng, long count)
{
    if (arena == NULL || count <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(int), NULL);
    }

    /* Allocate temporary buffer */
    int *buf = (int *)malloc((size_t)count * sizeof(int));
    if (buf == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(int), NULL);
    }

    for (long i = 0; i < count; i++) {
        buf[i] = sn_random_bool(rng);
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(int), buf);
    free(buf);
    return result;
}

RtHandleV2 *sn_random_gaussian_many(RtArenaV2 *arena, RtRandom *rng, double mean, double stddev, long count)
{
    if (arena == NULL || count <= 0) {
        return rt_array_create_generic_v2(arena, 0, sizeof(double), NULL);
    }

    /* Allocate temporary buffer */
    double *buf = (double *)malloc((size_t)count * sizeof(double));
    if (buf == NULL) {
        return rt_array_create_generic_v2(arena, 0, sizeof(double), NULL);
    }

    for (long i = 0; i < count; i++) {
        buf[i] = sn_random_gaussian(rng, mean, stddev);
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(double), buf);
    free(buf);
    return result;
}

/* ============================================================================
 * Static Collection Operations (OS Entropy) - Choice
 * ============================================================================ */

long long sn_random_static_choice_int(long long *arr)
{
    if (arr == NULL) return 0;
    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) return 0;

    long index = sn_random_static_int(0, len - 1);
    return arr[index];
}

long long sn_random_static_choice_long(long long *arr)
{
    if (arr == NULL) return 0;
    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) return 0;

    long index = sn_random_static_int(0, len - 1);
    return arr[index];
}

double sn_random_static_choice_double(double *arr)
{
    if (arr == NULL) return 0.0;
    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) return 0.0;

    long index = sn_random_static_int(0, len - 1);
    return arr[index];
}

RtHandleV2 *sn_random_static_choice_str(RtArenaV2 *arena, char **arr)
{
    if (arr == NULL) return NULL;
    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) return NULL;

    long index = sn_random_static_int(0, len - 1);
    return rt_arena_v2_strdup(arena, arr[index]);
}

int sn_random_static_choice_bool(int *arr)
{
    if (arr == NULL) return 0;
    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) return 0;

    long index = sn_random_static_int(0, len - 1);
    return arr[index];
}

unsigned char sn_random_static_choice_byte(unsigned char *arr)
{
    if (arr == NULL) return 0;
    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) return 0;

    long index = sn_random_static_int(0, len - 1);
    return arr[index];
}

/* ============================================================================
 * Weight Validation Helper
 * ============================================================================ */

static int sn_random_validate_weights(double *weights, long len)
{
    if (weights == NULL || len <= 0) {
        return 0;
    }

    double sum = 0.0;
    for (long i = 0; i < len; i++) {
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

static double *sn_random_build_cumulative(RtArenaV2 *arena, double *weights, long len)
{
    if (arena == NULL || weights == NULL || len <= 0) {
        return NULL;
    }

    double sum = 0.0;
    for (long i = 0; i < len; i++) {
        sum += weights[i];
    }

    if (sum <= 0.0) {
        return NULL;
    }

    RtHandleV2 *_cumul_h = rt_arena_v2_alloc(arena, (size_t)len * sizeof(double));
    double *cumulative = (double *)_cumul_h->ptr;

    double running_sum = 0.0;
    for (long i = 0; i < len; i++) {
        running_sum += weights[i] / sum;
        cumulative[i] = running_sum;
    }

    cumulative[len - 1] = 1.0;

    return cumulative;
}

static long sn_random_select_weighted_index(double random_val, double *cumulative, long len)
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

    long left = 0;
    long right = len - 1;

    while (left < right) {
        long mid = left + (right - left) / 2;

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

long long sn_random_static_weighted_choice_int(long long *arr, double *weights)
{
    if (arr == NULL || weights == NULL) {
        return 0;
    }

    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) {
        return 0;
    }

    if (!sn_random_validate_weights(weights, len)) {
        return 0;
    }

    RtArenaV2 *temp_arena = rt_arena_create(NULL);
    if (temp_arena == NULL) {
        return 0;
    }

    double *cumulative = sn_random_build_cumulative(temp_arena, weights, len);
    if (cumulative == NULL) {
        rt_arena_v2_destroy(temp_arena, false);
        return 0;
    }

    double random_val = sn_random_static_double(0.0, 1.0);
    long index = sn_random_select_weighted_index(random_val, cumulative, len);
    long long result = arr[index];

    rt_arena_v2_destroy(temp_arena, false);

    return result;
}

long long sn_random_static_weighted_choice_long(long long *arr, double *weights)
{
    return sn_random_static_weighted_choice_int(arr, weights);
}

double sn_random_static_weighted_choice_double(double *arr, double *weights)
{
    if (arr == NULL || weights == NULL) {
        return 0.0;
    }

    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) {
        return 0.0;
    }

    if (!sn_random_validate_weights(weights, len)) {
        return 0.0;
    }

    RtArenaV2 *temp_arena = rt_arena_create(NULL);
    if (temp_arena == NULL) {
        return 0.0;
    }

    double *cumulative = sn_random_build_cumulative(temp_arena, weights, len);
    if (cumulative == NULL) {
        rt_arena_v2_destroy(temp_arena, false);
        return 0.0;
    }

    double random_val = sn_random_static_double(0.0, 1.0);
    long index = sn_random_select_weighted_index(random_val, cumulative, len);
    double result = arr[index];

    rt_arena_v2_destroy(temp_arena, false);

    return result;
}

RtHandleV2 *sn_random_static_weighted_choice_str(RtArenaV2 *arena, char **arr, double *weights)
{
    if (arr == NULL || weights == NULL) {
        return NULL;
    }

    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) {
        return NULL;
    }

    if (!sn_random_validate_weights(weights, len)) {
        return NULL;
    }

    RtArenaV2 *temp_arena = rt_arena_v2_create(arena, RT_ARENA_MODE_DEFAULT, NULL);
    if (temp_arena == NULL) {
        return NULL;
    }

    double *cumulative = sn_random_build_cumulative(temp_arena, weights, len);
    if (cumulative == NULL) {
        rt_arena_v2_condemn(temp_arena);
        return NULL;
    }

    double random_val = sn_random_static_double(0.0, 1.0);
    long index = sn_random_select_weighted_index(random_val, cumulative, len);
    char *str_result = arr[index];

    rt_arena_v2_condemn(temp_arena);

    return rt_arena_v2_strdup(arena, str_result);
}

/* ============================================================================
 * Static Collection Operations (OS Entropy) - Shuffle
 * ============================================================================ */

void sn_random_static_shuffle_int(long long *arr)
{
    if (arr == NULL) {
        return;
    }

    size_t n = rt_v2_data_array_length(arr);
    if (n <= 1) {
        return;
    }

    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_static_int(0, (long)i);

        long long temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

void sn_random_static_shuffle_long(long long *arr)
{
    sn_random_static_shuffle_int(arr);
}

void sn_random_static_shuffle_double(double *arr)
{
    if (arr == NULL) {
        return;
    }

    size_t n = rt_v2_data_array_length(arr);
    if (n <= 1) {
        return;
    }

    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_static_int(0, (long)i);

        double temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

void sn_random_static_shuffle_str(char **arr)
{
    if (arr == NULL) {
        return;
    }

    size_t n = rt_v2_data_array_length(arr);
    if (n <= 1) {
        return;
    }

    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_static_int(0, (long)i);

        char *temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

void sn_random_static_shuffle_bool(int *arr)
{
    if (arr == NULL) {
        return;
    }

    size_t n = rt_v2_data_array_length(arr);
    if (n <= 1) {
        return;
    }

    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_static_int(0, (long)i);

        int temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

void sn_random_static_shuffle_byte(unsigned char *arr)
{
    if (arr == NULL) {
        return;
    }

    size_t n = rt_v2_data_array_length(arr);
    if (n <= 1) {
        return;
    }

    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_static_int(0, (long)i);

        unsigned char temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

/* ============================================================================
 * Static Collection Operations (OS Entropy) - Sample
 * ============================================================================ */

RtHandleV2 *sn_random_static_sample_int(RtArenaV2 *arena, long long *arr, long count)
{
    if (arena == NULL || arr == NULL) {
        return NULL;
    }

    if (count <= 0) {
        return NULL;
    }

    size_t n = rt_v2_data_array_length(arr);

    if (count > (long)n) {
        return NULL;
    }

    /* Allocate temporary buffer for shuffle */
    long long *temp = (long long *)malloc(n * sizeof(long long));
    if (temp == NULL) {
        return NULL;
    }
    memcpy(temp, arr, n * sizeof(long long));

    /* Allocate buffer for result */
    long long *result_buf = (long long *)malloc((size_t)count * sizeof(long long));
    if (result_buf == NULL) {
        free(temp);
        return NULL;
    }

    for (long i = 0; i < count; i++) {
        size_t j = (size_t)sn_random_static_int((long)i, (long)(n - 1));

        long long swap = temp[i];
        temp[i] = temp[j];
        temp[j] = swap;

        result_buf[i] = temp[i];
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(long long), result_buf);

    free(temp);
    free(result_buf);

    return result;
}

RtHandleV2 *sn_random_static_sample_long(RtArenaV2 *arena, long long *arr, long count)
{
    return sn_random_static_sample_int(arena, arr, count);
}

RtHandleV2 *sn_random_static_sample_double(RtArenaV2 *arena, double *arr, long count)
{
    if (arena == NULL || arr == NULL) {
        return NULL;
    }

    if (count <= 0) {
        return NULL;
    }

    size_t n = rt_v2_data_array_length(arr);

    if (count > (long)n) {
        return NULL;
    }

    /* Allocate temporary buffer for shuffle */
    double *temp = (double *)malloc(n * sizeof(double));
    if (temp == NULL) {
        return NULL;
    }
    memcpy(temp, arr, n * sizeof(double));

    /* Allocate buffer for result */
    double *result_buf = (double *)malloc((size_t)count * sizeof(double));
    if (result_buf == NULL) {
        free(temp);
        return NULL;
    }

    for (long i = 0; i < count; i++) {
        size_t j = (size_t)sn_random_static_int((long)i, (long)(n - 1));

        double swap = temp[i];
        temp[i] = temp[j];
        temp[j] = swap;

        result_buf[i] = temp[i];
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(double), result_buf);

    free(temp);
    free(result_buf);

    return result;
}

RtHandleV2 *sn_random_static_sample_str(RtArenaV2 *arena, char **arr, long count)
{
    if (arena == NULL || arr == NULL) {
        return NULL;
    }

    if (count <= 0) {
        return NULL;
    }

    size_t n = rt_v2_data_array_length(arr);

    if (count > (long)n) {
        return NULL;
    }

    /* Allocate temporary buffer for shuffle */
    char **temp = (char **)malloc(n * sizeof(char *));
    if (temp == NULL) {
        return NULL;
    }
    memcpy(temp, arr, n * sizeof(char *));

    /* Allocate buffer for result string pointers */
    const char **result_buf = (const char **)malloc((size_t)count * sizeof(const char *));
    if (result_buf == NULL) {
        free(temp);
        return NULL;
    }

    for (long i = 0; i < count; i++) {
        size_t j = (size_t)sn_random_static_int((long)i, (long)(n - 1));

        char *swap = temp[i];
        temp[i] = temp[j];
        temp[j] = swap;

        result_buf[i] = temp[i];
    }

    /* Create handle-based string array from buffer */
    RtHandleV2 *result = rt_array_create_string_v2(arena, (size_t)count, result_buf);

    free(temp);
    free(result_buf);

    return result;
}

/* ============================================================================
 * Instance Collection Operations (Seeded PRNG) - Choice
 * ============================================================================ */

long long sn_random_choice_int(RtRandom *rng, long long *arr)
{
    if (rng == NULL || arr == NULL) return 0;
    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) return 0;

    long index = sn_random_int(rng, 0, len - 1);
    return arr[index];
}

long long sn_random_choice_long(RtRandom *rng, long long *arr)
{
    return sn_random_choice_int(rng, arr);
}

double sn_random_choice_double(RtRandom *rng, double *arr)
{
    if (rng == NULL || arr == NULL) return 0.0;
    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) return 0.0;

    long index = sn_random_int(rng, 0, len - 1);
    return arr[index];
}

RtHandleV2 *sn_random_choice_str(RtArenaV2 *arena, RtRandom *rng, char **arr)
{
    if (rng == NULL || arr == NULL) return NULL;
    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) return NULL;

    long index = sn_random_int(rng, 0, len - 1);
    return rt_arena_v2_strdup(arena, arr[index]);
}

int sn_random_choice_bool(RtRandom *rng, int *arr)
{
    if (rng == NULL || arr == NULL) return 0;
    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) return 0;

    long index = sn_random_int(rng, 0, len - 1);
    return arr[index];
}

unsigned char sn_random_choice_byte(RtRandom *rng, unsigned char *arr)
{
    if (rng == NULL || arr == NULL) return 0;
    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) return 0;

    long index = sn_random_int(rng, 0, len - 1);
    return arr[index];
}

/* ============================================================================
 * Instance Collection Operations (Seeded PRNG) - Weighted Choice
 * ============================================================================ */

long long sn_random_weighted_choice_int(RtRandom *rng, long long *arr, double *weights)
{
    if (rng == NULL || arr == NULL || weights == NULL) {
        return 0;
    }

    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) {
        return 0;
    }

    if (!sn_random_validate_weights(weights, len)) {
        return 0;
    }

    RtArenaV2 *temp_arena = rt_arena_create(NULL);
    if (temp_arena == NULL) {
        return 0;
    }

    double *cumulative = sn_random_build_cumulative(temp_arena, weights, len);
    if (cumulative == NULL) {
        rt_arena_v2_destroy(temp_arena, false);
        return 0;
    }

    double random_val = sn_random_double(rng, 0.0, 1.0);
    long index = sn_random_select_weighted_index(random_val, cumulative, len);
    long long result = arr[index];

    rt_arena_v2_destroy(temp_arena, false);

    return result;
}

long long sn_random_weighted_choice_long(RtRandom *rng, long long *arr, double *weights)
{
    return sn_random_weighted_choice_int(rng, arr, weights);
}

double sn_random_weighted_choice_double(RtRandom *rng, double *arr, double *weights)
{
    if (rng == NULL || arr == NULL || weights == NULL) {
        return 0.0;
    }

    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) {
        return 0.0;
    }

    if (!sn_random_validate_weights(weights, len)) {
        return 0.0;
    }

    RtArenaV2 *temp_arena = rt_arena_create(NULL);
    if (temp_arena == NULL) {
        return 0.0;
    }

    double *cumulative = sn_random_build_cumulative(temp_arena, weights, len);
    if (cumulative == NULL) {
        rt_arena_v2_destroy(temp_arena, false);
        return 0.0;
    }

    double random_val = sn_random_double(rng, 0.0, 1.0);
    long index = sn_random_select_weighted_index(random_val, cumulative, len);
    double result = arr[index];

    rt_arena_v2_destroy(temp_arena, false);

    return result;
}

RtHandleV2 *sn_random_weighted_choice_str(RtArenaV2 *arena, RtRandom *rng, char **arr, double *weights)
{
    if (rng == NULL || arr == NULL || weights == NULL) {
        return NULL;
    }

    long len = (long)rt_v2_data_array_length(arr);
    if (len <= 0) {
        return NULL;
    }

    if (!sn_random_validate_weights(weights, len)) {
        return NULL;
    }

    RtArenaV2 *temp_arena = rt_arena_v2_create(arena, RT_ARENA_MODE_DEFAULT, NULL);
    if (temp_arena == NULL) {
        return NULL;
    }

    double *cumulative = sn_random_build_cumulative(temp_arena, weights, len);
    if (cumulative == NULL) {
        rt_arena_v2_condemn(temp_arena);
        return NULL;
    }

    double random_val = sn_random_double(rng, 0.0, 1.0);
    long index = sn_random_select_weighted_index(random_val, cumulative, len);
    char *str_result = arr[index];

    rt_arena_v2_condemn(temp_arena);

    return rt_arena_v2_strdup(arena, str_result);
}

/* ============================================================================
 * Instance Collection Operations (Seeded PRNG) - Shuffle
 * ============================================================================ */

void sn_random_shuffle_int(RtRandom *rng, long long *arr)
{
    if (rng == NULL || arr == NULL) {
        return;
    }

    size_t n = rt_v2_data_array_length(arr);
    if (n <= 1) {
        return;
    }

    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_int(rng, 0, (long)i);

        long long temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

void sn_random_shuffle_long(RtRandom *rng, long long *arr)
{
    sn_random_shuffle_int(rng, arr);
}

void sn_random_shuffle_double(RtRandom *rng, double *arr)
{
    if (rng == NULL || arr == NULL) {
        return;
    }

    size_t n = rt_v2_data_array_length(arr);
    if (n <= 1) {
        return;
    }

    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_int(rng, 0, (long)i);

        double temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

void sn_random_shuffle_str(RtRandom *rng, char **arr)
{
    if (rng == NULL || arr == NULL) {
        return;
    }

    size_t n = rt_v2_data_array_length(arr);
    if (n <= 1) {
        return;
    }

    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_int(rng, 0, (long)i);

        char *temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

void sn_random_shuffle_bool(RtRandom *rng, int *arr)
{
    if (rng == NULL || arr == NULL) {
        return;
    }

    size_t n = rt_v2_data_array_length(arr);
    if (n <= 1) {
        return;
    }

    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_int(rng, 0, (long)i);

        int temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

void sn_random_shuffle_byte(RtRandom *rng, unsigned char *arr)
{
    if (rng == NULL || arr == NULL) {
        return;
    }

    size_t n = rt_v2_data_array_length(arr);
    if (n <= 1) {
        return;
    }

    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)sn_random_int(rng, 0, (long)i);

        unsigned char temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

/* ============================================================================
 * Instance Collection Operations (Seeded PRNG) - Sample
 * ============================================================================ */

RtHandleV2 *sn_random_sample_int(RtArenaV2 *arena, RtRandom *rng, long long *arr, long count)
{
    if (arena == NULL || rng == NULL || arr == NULL) {
        return NULL;
    }

    if (count <= 0) {
        return NULL;
    }

    size_t n = rt_v2_data_array_length(arr);

    if (count > (long)n) {
        return NULL;
    }

    /* Allocate temporary buffer for shuffle */
    long long *temp = (long long *)malloc(n * sizeof(long long));
    if (temp == NULL) {
        return NULL;
    }
    memcpy(temp, arr, n * sizeof(long long));

    /* Allocate buffer for result */
    long long *result_buf = (long long *)malloc((size_t)count * sizeof(long long));
    if (result_buf == NULL) {
        free(temp);
        return NULL;
    }

    for (long i = 0; i < count; i++) {
        size_t j = (size_t)sn_random_int(rng, (long)i, (long)(n - 1));

        long long swap = temp[i];
        temp[i] = temp[j];
        temp[j] = swap;

        result_buf[i] = temp[i];
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(long long), result_buf);

    free(temp);
    free(result_buf);

    return result;
}

RtHandleV2 *sn_random_sample_long(RtArenaV2 *arena, RtRandom *rng, long long *arr, long count)
{
    return sn_random_sample_int(arena, rng, arr, count);
}

RtHandleV2 *sn_random_sample_double(RtArenaV2 *arena, RtRandom *rng, double *arr, long count)
{
    if (arena == NULL || rng == NULL || arr == NULL) {
        return NULL;
    }

    if (count <= 0) {
        return NULL;
    }

    size_t n = rt_v2_data_array_length(arr);

    if (count > (long)n) {
        return NULL;
    }

    /* Allocate temporary buffer for shuffle */
    double *temp = (double *)malloc(n * sizeof(double));
    if (temp == NULL) {
        return NULL;
    }
    memcpy(temp, arr, n * sizeof(double));

    /* Allocate buffer for result */
    double *result_buf = (double *)malloc((size_t)count * sizeof(double));
    if (result_buf == NULL) {
        free(temp);
        return NULL;
    }

    for (long i = 0; i < count; i++) {
        size_t j = (size_t)sn_random_int(rng, (long)i, (long)(n - 1));

        double swap = temp[i];
        temp[i] = temp[j];
        temp[j] = swap;

        result_buf[i] = temp[i];
    }

    /* Create handle-based array from buffer */
    RtHandleV2 *result = rt_array_create_generic_v2(arena, (size_t)count, sizeof(double), result_buf);

    free(temp);
    free(result_buf);

    return result;
}

RtHandleV2 *sn_random_sample_str(RtArenaV2 *arena, RtRandom *rng, char **arr, long count)
{
    if (arena == NULL || rng == NULL || arr == NULL) {
        return NULL;
    }

    if (count <= 0) {
        return NULL;
    }

    size_t n = rt_v2_data_array_length(arr);

    if (count > (long)n) {
        return NULL;
    }

    /* Allocate temporary buffer for shuffle */
    char **temp = (char **)malloc(n * sizeof(char *));
    if (temp == NULL) {
        return NULL;
    }
    memcpy(temp, arr, n * sizeof(char *));

    /* Allocate buffer for result string pointers */
    const char **result_buf = (const char **)malloc((size_t)count * sizeof(const char *));
    if (result_buf == NULL) {
        free(temp);
        return NULL;
    }

    for (long i = 0; i < count; i++) {
        size_t j = (size_t)sn_random_int(rng, (long)i, (long)(n - 1));

        char *swap = temp[i];
        temp[i] = temp[j];
        temp[j] = swap;

        result_buf[i] = temp[i];
    }

    /* Create handle-based string array from buffer */
    RtHandleV2 *result = rt_array_create_string_v2(arena, (size_t)count, result_buf);

    free(temp);
    free(result_buf);

    return result;
}
