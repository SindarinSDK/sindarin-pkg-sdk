/* ==============================================================================
 * sdk/uuid.sn.c - Self-contained UUID Implementation for Sindarin SDK
 * ==============================================================================
 * This file provides the C implementation for the SnUUID type.
 * It is compiled via #pragma source and linked with Sindarin code.
 *
 * Supports UUID versions:
 * - v4: Random UUID (simple unique IDs)
 * - v5: SHA-1 hash of namespace + name (deterministic from input)
 * - v7: Timestamp + random (time-ordered, modern default)
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
    #if defined(__MINGW32__) || defined(__MINGW64__)
    /* MinGW has POSIX-compatible gettimeofday */
    #include <sys/time.h>
    #else
    /* MSVC needs pragma comment and custom gettimeofday */
    #pragma comment(lib, "bcrypt.lib")
    struct timeval { long tv_sec; long tv_usec; };
    static int gettimeofday(struct timeval *tv, void *tz) {
        (void)tz;
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        uint64_t time = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        time -= 116444736000000000ULL; /* Convert from Windows epoch to Unix epoch */
        time /= 10; /* Convert from 100ns to microseconds */
        tv->tv_sec = (long)(time / 1000000);
        tv->tv_usec = (long)(time % 1000000);
        return 0;
    }
    #endif
#else
#include <sys/time.h>
#endif

/* Platform-specific includes for entropy sources */
#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <stdlib.h>  /* arc4random_buf on BSD/macOS */
#endif

/* Include runtime arena for proper memory management */
#include "runtime/arena/arena_v2.h"

/* ============================================================================
 * UUID Type Definition
 * ============================================================================ */

typedef struct RtUuid {
    uint64_t high;  /* Most significant 64 bits */
    uint64_t low;   /* Least significant 64 bits */
} RtUuid;

/* ============================================================================
 * Namespace Constants (RFC 9562)
 * ============================================================================ */

/* DNS namespace: 6ba7b810-9dad-11d1-80b4-00c04fd430c8 */
static const RtUuid SN_UUID_NAMESPACE_DNS = {
    .high = 0x6ba7b8109dad11d1ULL,
    .low  = 0x80b400c04fd430c8ULL
};

/* URL namespace: 6ba7b811-9dad-11d1-80b4-00c04fd430c8 */
static const RtUuid SN_UUID_NAMESPACE_URL = {
    .high = 0x6ba7b8119dad11d1ULL,
    .low  = 0x80b400c04fd430c8ULL
};

/* OID namespace: 6ba7b812-9dad-11d1-80b4-00c04fd430c8 */
static const RtUuid SN_UUID_NAMESPACE_OID = {
    .high = 0x6ba7b8129dad11d1ULL,
    .low  = 0x80b400c04fd430c8ULL
};

/* X.500 namespace: 6ba7b814-9dad-11d1-80b4-00c04fd430c8 */
static const RtUuid SN_UUID_NAMESPACE_X500 = {
    .high = 0x6ba7b8149dad11d1ULL,
    .low  = 0x80b400c04fd430c8ULL
};

/* ============================================================================
 * Entropy Function (Platform-specific)
 * ============================================================================ */

static void sn_uuid_fill_entropy(uint8_t *buf, size_t len) {
    if (buf == NULL || len == 0) {
        return;
    }

#if defined(__linux__)
    size_t remaining = len;
    uint8_t *ptr = buf;

    while (remaining > 0) {
        ssize_t ret = getrandom(ptr, remaining, 0);

        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            fprintf(stderr, "sn_uuid_fill_entropy: getrandom() failed: %s\n",
                    strerror(errno));
            exit(1);
        }

        ptr += ret;
        remaining -= (size_t)ret;
    }

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(buf, len);

#elif defined(_WIN32)
    /* BCryptGenRandom works with both MSVC and MinGW */
    NTSTATUS status = BCryptGenRandom(
        NULL,
        buf,
        (ULONG)len,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "sn_uuid_fill_entropy: BCryptGenRandom() failed: 0x%lx\n",
                (unsigned long)status);
        exit(1);
    }

#else
    /* Fallback: Use /dev/urandom */
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL) {
        fprintf(stderr, "sn_uuid_fill_entropy: failed to open /dev/urandom: %s\n",
                strerror(errno));
        exit(1);
    }

    size_t bytes_read = fread(buf, 1, len, urandom);
    if (bytes_read != len) {
        fprintf(stderr, "sn_uuid_fill_entropy: failed to read from /dev/urandom\n");
        fclose(urandom);
        exit(1);
    }

    fclose(urandom);
#endif
}

/* ============================================================================
 * SHA-1 Implementation (for UUIDv5)
 * ============================================================================ */

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE 64

/* SHA-1 Constants */
#define SHA1_H0 0x67452301
#define SHA1_H1 0xEFCDAB89
#define SHA1_H2 0x98BADCFE
#define SHA1_H3 0x10325476
#define SHA1_H4 0xC3D2E1F0

#define SHA1_K0 0x5A827999
#define SHA1_K1 0x6ED9EBA1
#define SHA1_K2 0x8F1BBCDC
#define SHA1_K3 0xCA62C1D6

#define SHA1_ROTL(X, n) (((X) << (n)) | ((X) >> (32 - (n))))
#define SHA1_F0(B, C, D) (((B) & (C)) | ((~(B)) & (D)))
#define SHA1_F1(B, C, D) ((B) ^ (C) ^ (D))
#define SHA1_F2(B, C, D) (((B) & (C)) | ((B) & (D)) | ((C) & (D)))
#define SHA1_F3(B, C, D) ((B) ^ (C) ^ (D))

typedef struct {
    uint32_t H[5];
    uint8_t buffer[SHA1_BLOCK_SIZE];
    size_t buffer_len;
    uint64_t total_len;
} SHA1_Context;

static void sha1_process_block(uint32_t H[5], const uint8_t *block) {
    uint32_t W[80];
    uint32_t A, B, C, D, E, TEMP;
    int t;

    for (t = 0; t < 16; t++) {
        W[t] = ((uint32_t)block[t * 4] << 24) |
               ((uint32_t)block[t * 4 + 1] << 16) |
               ((uint32_t)block[t * 4 + 2] << 8) |
               ((uint32_t)block[t * 4 + 3]);
    }

    for (t = 16; t < 80; t++) {
        W[t] = SHA1_ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    A = H[0];
    B = H[1];
    C = H[2];
    D = H[3];
    E = H[4];

    for (t = 0; t < 80; t++) {
        uint32_t f, K;

        if (t < 20) {
            f = SHA1_F0(B, C, D);
            K = SHA1_K0;
        } else if (t < 40) {
            f = SHA1_F1(B, C, D);
            K = SHA1_K1;
        } else if (t < 60) {
            f = SHA1_F2(B, C, D);
            K = SHA1_K2;
        } else {
            f = SHA1_F3(B, C, D);
            K = SHA1_K3;
        }

        TEMP = SHA1_ROTL(A, 5) + f + E + W[t] + K;
        E = D;
        D = C;
        C = SHA1_ROTL(B, 30);
        B = A;
        A = TEMP;
    }

    H[0] += A;
    H[1] += B;
    H[2] += C;
    H[3] += D;
    H[4] += E;
}

static int sha1_pad_message(uint8_t *block, int *block_count,
                            const uint8_t *data, size_t data_len, uint64_t total_len) {
    if (block == NULL || block_count == NULL) {
        return -1;
    }

    if (data_len >= SHA1_BLOCK_SIZE) {
        return -1;
    }

    if (data != NULL && data_len > 0) {
        memcpy(block, data, data_len);
    }

    block[data_len] = 0x80;

    uint64_t bit_len = total_len * 8;

    if (data_len < 56) {
        memset(block + data_len + 1, 0, 55 - data_len);

        block[56] = (uint8_t)(bit_len >> 56);
        block[57] = (uint8_t)(bit_len >> 48);
        block[58] = (uint8_t)(bit_len >> 40);
        block[59] = (uint8_t)(bit_len >> 32);
        block[60] = (uint8_t)(bit_len >> 24);
        block[61] = (uint8_t)(bit_len >> 16);
        block[62] = (uint8_t)(bit_len >> 8);
        block[63] = (uint8_t)(bit_len);

        *block_count = 1;
    } else {
        memset(block + data_len + 1, 0, 63 - data_len);
        memset(block + 64, 0, 56);

        block[120] = (uint8_t)(bit_len >> 56);
        block[121] = (uint8_t)(bit_len >> 48);
        block[122] = (uint8_t)(bit_len >> 40);
        block[123] = (uint8_t)(bit_len >> 32);
        block[124] = (uint8_t)(bit_len >> 24);
        block[125] = (uint8_t)(bit_len >> 16);
        block[126] = (uint8_t)(bit_len >> 8);
        block[127] = (uint8_t)(bit_len);

        *block_count = 2;
    }

    return 0;
}

static void sha1_init(SHA1_Context *ctx) {
    if (ctx == NULL) {
        return;
    }

    ctx->H[0] = SHA1_H0;
    ctx->H[1] = SHA1_H1;
    ctx->H[2] = SHA1_H2;
    ctx->H[3] = SHA1_H3;
    ctx->H[4] = SHA1_H4;

    ctx->buffer_len = 0;
    ctx->total_len = 0;
}

static void sha1_update(SHA1_Context *ctx, const uint8_t *data, size_t len) {
    if (ctx == NULL || data == NULL || len == 0) {
        return;
    }

    ctx->total_len += len;

    if (ctx->buffer_len > 0) {
        size_t to_copy = SHA1_BLOCK_SIZE - ctx->buffer_len;
        if (to_copy > len) {
            to_copy = len;
        }

        memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
        ctx->buffer_len += to_copy;
        data += to_copy;
        len -= to_copy;

        if (ctx->buffer_len == SHA1_BLOCK_SIZE) {
            sha1_process_block(ctx->H, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }

    while (len >= SHA1_BLOCK_SIZE) {
        sha1_process_block(ctx->H, data);
        data += SHA1_BLOCK_SIZE;
        len -= SHA1_BLOCK_SIZE;
    }

    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }
}

static void sha1_final(SHA1_Context *ctx, uint8_t digest[SHA1_DIGEST_SIZE]) {
    if (ctx == NULL || digest == NULL) {
        return;
    }

    uint8_t final_blocks[128];
    int block_count;

    sha1_pad_message(final_blocks, &block_count,
                     ctx->buffer, ctx->buffer_len, ctx->total_len);

    sha1_process_block(ctx->H, final_blocks);
    if (block_count == 2) {
        sha1_process_block(ctx->H, final_blocks + 64);
    }

    for (int i = 0; i < 5; i++) {
        digest[i * 4]     = (uint8_t)(ctx->H[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->H[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->H[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->H[i]);
    }
}

/* ============================================================================
 * UUIDv4 Generation
 * ============================================================================ */

RtHandleV2 *sn_uuid_v4(RtArenaV2 *arena) {
    if (arena == NULL) {
        return NULL;
    }

    RtHandleV2 *_uuid_h = rt_arena_v2_alloc(arena, sizeof(RtUuid));
    RtUuid *uuid = (RtUuid *)_uuid_h->ptr;
    if (uuid == NULL) {
        return NULL;
    }

    uint8_t bytes[16];
    sn_uuid_fill_entropy(bytes, sizeof(bytes));

    uuid->high = ((uint64_t)bytes[0] << 56) |
                 ((uint64_t)bytes[1] << 48) |
                 ((uint64_t)bytes[2] << 40) |
                 ((uint64_t)bytes[3] << 32) |
                 ((uint64_t)bytes[4] << 24) |
                 ((uint64_t)bytes[5] << 16) |
                 ((uint64_t)bytes[6] << 8)  |
                 ((uint64_t)bytes[7]);

    uuid->low = ((uint64_t)bytes[8] << 56)  |
                ((uint64_t)bytes[9] << 48)  |
                ((uint64_t)bytes[10] << 40) |
                ((uint64_t)bytes[11] << 32) |
                ((uint64_t)bytes[12] << 24) |
                ((uint64_t)bytes[13] << 16) |
                ((uint64_t)bytes[14] << 8)  |
                ((uint64_t)bytes[15]);

    /* Set version 4 bits */
    uuid->high = (uuid->high & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;

    /* Set variant bits */
    uuid->low = (uuid->low & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;

    return _uuid_h;
}

/* ============================================================================
 * UUIDv5 Generation
 * ============================================================================ */

RtHandleV2 *sn_uuid_v5(RtArenaV2 *arena, RtUuid *namespace_uuid, const char *name) {
    if (arena == NULL || namespace_uuid == NULL || name == NULL) {
        return NULL;
    }

    RtHandleV2 *_uuid_h = rt_arena_v2_alloc(arena, sizeof(RtUuid));
    RtUuid *uuid = (RtUuid *)_uuid_h->ptr;
    if (uuid == NULL) {
        return NULL;
    }

    uint8_t namespace_bytes[16];
    namespace_bytes[0]  = (uint8_t)(namespace_uuid->high >> 56);
    namespace_bytes[1]  = (uint8_t)(namespace_uuid->high >> 48);
    namespace_bytes[2]  = (uint8_t)(namespace_uuid->high >> 40);
    namespace_bytes[3]  = (uint8_t)(namespace_uuid->high >> 32);
    namespace_bytes[4]  = (uint8_t)(namespace_uuid->high >> 24);
    namespace_bytes[5]  = (uint8_t)(namespace_uuid->high >> 16);
    namespace_bytes[6]  = (uint8_t)(namespace_uuid->high >> 8);
    namespace_bytes[7]  = (uint8_t)(namespace_uuid->high);
    namespace_bytes[8]  = (uint8_t)(namespace_uuid->low >> 56);
    namespace_bytes[9]  = (uint8_t)(namespace_uuid->low >> 48);
    namespace_bytes[10] = (uint8_t)(namespace_uuid->low >> 40);
    namespace_bytes[11] = (uint8_t)(namespace_uuid->low >> 32);
    namespace_bytes[12] = (uint8_t)(namespace_uuid->low >> 24);
    namespace_bytes[13] = (uint8_t)(namespace_uuid->low >> 16);
    namespace_bytes[14] = (uint8_t)(namespace_uuid->low >> 8);
    namespace_bytes[15] = (uint8_t)(namespace_uuid->low);

    size_t name_len = strlen(name);
    uint8_t digest[SHA1_DIGEST_SIZE];

    SHA1_Context ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, namespace_bytes, 16);
    sha1_update(&ctx, (const uint8_t *)name, name_len);
    sha1_final(&ctx, digest);

    uuid->high = ((uint64_t)digest[0] << 56) |
                 ((uint64_t)digest[1] << 48) |
                 ((uint64_t)digest[2] << 40) |
                 ((uint64_t)digest[3] << 32) |
                 ((uint64_t)digest[4] << 24) |
                 ((uint64_t)digest[5] << 16) |
                 ((uint64_t)digest[6] << 8)  |
                 ((uint64_t)digest[7]);

    uuid->low = ((uint64_t)digest[8] << 56)  |
                ((uint64_t)digest[9] << 48)  |
                ((uint64_t)digest[10] << 40) |
                ((uint64_t)digest[11] << 32) |
                ((uint64_t)digest[12] << 24) |
                ((uint64_t)digest[13] << 16) |
                ((uint64_t)digest[14] << 8)  |
                ((uint64_t)digest[15]);

    /* Set version 5 bits */
    uuid->high = (uuid->high & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000005000ULL;

    /* Set variant bits */
    uuid->low = (uuid->low & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;

    return _uuid_h;
}

/* ============================================================================
 * UUIDv7 Generation
 * ============================================================================ */

RtHandleV2 *sn_uuid_v7(RtArenaV2 *arena) {
    if (arena == NULL) {
        return NULL;
    }

    RtHandleV2 *_uuid_h = rt_arena_v2_alloc(arena, sizeof(RtUuid));
    RtUuid *uuid = (RtUuid *)_uuid_h->ptr;
    if (uuid == NULL) {
        return NULL;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t timestamp_ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;

    uint8_t random_bytes[10];
    sn_uuid_fill_entropy(random_bytes, sizeof(random_bytes));

    uuid->high = (timestamp_ms << 16) |
                 0x7000ULL |
                 ((uint64_t)(random_bytes[0] & 0x0F) << 8) |
                 (uint64_t)random_bytes[1];

    uuid->low = ((uint64_t)random_bytes[2] << 56) |
                ((uint64_t)random_bytes[3] << 48) |
                ((uint64_t)random_bytes[4] << 40) |
                ((uint64_t)random_bytes[5] << 32) |
                ((uint64_t)random_bytes[6] << 24) |
                ((uint64_t)random_bytes[7] << 16) |
                ((uint64_t)random_bytes[8] << 8)  |
                ((uint64_t)random_bytes[9]);

    /* Set variant bits */
    uuid->low = (uuid->low & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;

    return _uuid_h;
}

/* Create using recommended default (v7) */
RtHandleV2 *sn_uuid_create(RtArenaV2 *arena) {
    return sn_uuid_v7(arena);
}

/* ============================================================================
 * Property Getters
 * ============================================================================ */

long sn_uuid_get_version(RtUuid *uuid) {
    if (uuid == NULL) {
        return 0;
    }
    return (long)((uuid->high >> 12) & 0x0F);
}

long sn_uuid_get_variant(RtUuid *uuid) {
    if (uuid == NULL) {
        return 0;
    }

    uint64_t variant_bits = (uuid->low >> 62) & 0x03;

    if ((variant_bits & 0x02) == 0) {
        return 0;
    } else if ((variant_bits & 0x03) == 0x02) {
        return 1;
    } else if ((variant_bits & 0x03) == 0x03) {
        uint64_t bit61 = (uuid->low >> 61) & 0x01;
        if (bit61 == 0) {
            return 2;
        } else {
            return 3;
        }
    }

    return 1;
}

int sn_uuid_is_nil(RtUuid *uuid) {
    if (uuid == NULL) {
        return 0;
    }
    return (uuid->high == 0 && uuid->low == 0) ? 1 : 0;
}

/* ============================================================================
 * Time Extraction (v7 only)
 * ============================================================================ */

long long sn_uuid_get_timestamp(RtUuid *uuid) {
    if (uuid == NULL) {
        fprintf(stderr, "sn_uuid_get_timestamp: NULL UUID\n");
        exit(1);
    }

    long version = sn_uuid_get_version(uuid);
    if (version != 7) {
        fprintf(stderr, "sn_uuid_get_timestamp: UUID is not version 7 (version=%ld)\n", version);
        exit(1);
    }

    return (long long)(uuid->high >> 16);
}

/* ============================================================================
 * Conversion Methods
 * ============================================================================ */

RtHandleV2 *sn_uuid_to_string(RtArenaV2 *arena, RtUuid *uuid) {
    if (arena == NULL || uuid == NULL) {
        return NULL;
    }

    uint32_t time_low = (uint32_t)(uuid->high >> 32);
    uint16_t time_mid = (uint16_t)((uuid->high >> 16) & 0xFFFF);
    uint16_t time_hi_version = (uint16_t)(uuid->high & 0xFFFF);
    uint16_t clock_seq = (uint16_t)((uuid->low >> 48) & 0xFFFF);
    uint64_t node = uuid->low & 0xFFFFFFFFFFFFULL;

    char buf[37];
    snprintf(buf, 37, "%08x-%04x-%04x-%04x-%012llx",
             time_low, time_mid, time_hi_version, clock_seq,
             (unsigned long long)node);

    return rt_arena_v2_strdup(arena, buf);
}

RtHandleV2 *sn_uuid_to_hex(RtArenaV2 *arena, RtUuid *uuid) {
    if (arena == NULL || uuid == NULL) {
        return NULL;
    }

    char buf[33];
    snprintf(buf, 33, "%016llx%016llx",
             (unsigned long long)uuid->high,
             (unsigned long long)uuid->low);

    return rt_arena_v2_strdup(arena, buf);
}

/* URL-safe base64 alphabet (RFC 4648 section 5) */
static const char BASE64_URL_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

RtHandleV2 *sn_uuid_to_base64(RtArenaV2 *arena, RtUuid *uuid) {
    if (arena == NULL || uuid == NULL) {
        return NULL;
    }

    unsigned char bytes[16];
    bytes[0]  = (unsigned char)(uuid->high >> 56);
    bytes[1]  = (unsigned char)(uuid->high >> 48);
    bytes[2]  = (unsigned char)(uuid->high >> 40);
    bytes[3]  = (unsigned char)(uuid->high >> 32);
    bytes[4]  = (unsigned char)(uuid->high >> 24);
    bytes[5]  = (unsigned char)(uuid->high >> 16);
    bytes[6]  = (unsigned char)(uuid->high >> 8);
    bytes[7]  = (unsigned char)(uuid->high);
    bytes[8]  = (unsigned char)(uuid->low >> 56);
    bytes[9]  = (unsigned char)(uuid->low >> 48);
    bytes[10] = (unsigned char)(uuid->low >> 40);
    bytes[11] = (unsigned char)(uuid->low >> 32);
    bytes[12] = (unsigned char)(uuid->low >> 24);
    bytes[13] = (unsigned char)(uuid->low >> 16);
    bytes[14] = (unsigned char)(uuid->low >> 8);
    bytes[15] = (unsigned char)(uuid->low);

    char buf[23];
    int out_idx = 0;
    int i;

    for (i = 0; i < 15; i += 3) {
        uint32_t triplet = ((uint32_t)bytes[i] << 16) |
                           ((uint32_t)bytes[i + 1] << 8) |
                           ((uint32_t)bytes[i + 2]);
        buf[out_idx++] = BASE64_URL_ALPHABET[(triplet >> 18) & 0x3F];
        buf[out_idx++] = BASE64_URL_ALPHABET[(triplet >> 12) & 0x3F];
        buf[out_idx++] = BASE64_URL_ALPHABET[(triplet >> 6) & 0x3F];
        buf[out_idx++] = BASE64_URL_ALPHABET[triplet & 0x3F];
    }

    buf[out_idx++] = BASE64_URL_ALPHABET[(bytes[15] >> 2) & 0x3F];
    buf[out_idx++] = BASE64_URL_ALPHABET[(bytes[15] << 4) & 0x3F];
    buf[out_idx] = '\0';

    return rt_arena_v2_strdup(arena, buf);
}

/* ============================================================================
 * Comparison Methods
 * ============================================================================ */

int sn_uuid_equals(RtUuid *uuid, RtUuid *other) {
    if (uuid == NULL || other == NULL) {
        return (uuid == other) ? 1 : 0;
    }
    return (uuid->high == other->high && uuid->low == other->low) ? 1 : 0;
}

long long sn_uuid_compare(RtUuid *uuid, RtUuid *other) {
    if (uuid == NULL && other == NULL) return 0;
    if (uuid == NULL) return -1;
    if (other == NULL) return 1;

    if (uuid->high < other->high) return -1;
    if (uuid->high > other->high) return 1;
    if (uuid->low < other->low) return -1;
    if (uuid->low > other->low) return 1;
    return 0;
}

int sn_uuid_is_less_than(RtUuid *uuid, RtUuid *other) {
    return sn_uuid_compare(uuid, other) < 0 ? 1 : 0;
}

int sn_uuid_is_greater_than(RtUuid *uuid, RtUuid *other) {
    return sn_uuid_compare(uuid, other) > 0 ? 1 : 0;
}

/* ============================================================================
 * Special UUIDs
 * ============================================================================ */

RtHandleV2 *sn_uuid_nil(RtArenaV2 *arena) {
    if (arena == NULL) {
        return NULL;
    }

    RtHandleV2 *_uuid_h = rt_arena_v2_alloc(arena, sizeof(RtUuid));
    RtUuid *uuid = (RtUuid *)_uuid_h->ptr;
    if (uuid == NULL) {
        return NULL;
    }

    uuid->high = 0;
    uuid->low = 0;
    return _uuid_h;
}

RtHandleV2 *sn_uuid_max(RtArenaV2 *arena) {
    if (arena == NULL) {
        return NULL;
    }

    RtHandleV2 *_uuid_h = rt_arena_v2_alloc(arena, sizeof(RtUuid));
    RtUuid *uuid = (RtUuid *)_uuid_h->ptr;
    if (uuid == NULL) {
        return NULL;
    }

    uuid->high = 0xFFFFFFFFFFFFFFFFULL;
    uuid->low = 0xFFFFFFFFFFFFFFFFULL;
    return _uuid_h;
}

/* ============================================================================
 * Namespace Accessors
 * ============================================================================ */

RtHandleV2 *sn_uuid_namespace_dns(RtArenaV2 *arena) {
    if (arena == NULL) {
        return NULL;
    }

    RtHandleV2 *_uuid_h = rt_arena_v2_alloc(arena, sizeof(RtUuid));
    RtUuid *uuid = (RtUuid *)_uuid_h->ptr;
    if (uuid == NULL) {
        return NULL;
    }

    *uuid = SN_UUID_NAMESPACE_DNS;
    return _uuid_h;
}

RtHandleV2 *sn_uuid_namespace_url(RtArenaV2 *arena) {
    if (arena == NULL) {
        return NULL;
    }

    RtHandleV2 *_uuid_h = rt_arena_v2_alloc(arena, sizeof(RtUuid));
    RtUuid *uuid = (RtUuid *)_uuid_h->ptr;
    if (uuid == NULL) {
        return NULL;
    }

    *uuid = SN_UUID_NAMESPACE_URL;
    return _uuid_h;
}

RtHandleV2 *sn_uuid_namespace_oid(RtArenaV2 *arena) {
    if (arena == NULL) {
        return NULL;
    }

    RtHandleV2 *_uuid_h = rt_arena_v2_alloc(arena, sizeof(RtUuid));
    RtUuid *uuid = (RtUuid *)_uuid_h->ptr;
    if (uuid == NULL) {
        return NULL;
    }

    *uuid = SN_UUID_NAMESPACE_OID;
    return _uuid_h;
}

RtHandleV2 *sn_uuid_namespace_x500(RtArenaV2 *arena) {
    if (arena == NULL) {
        return NULL;
    }

    RtHandleV2 *_uuid_h = rt_arena_v2_alloc(arena, sizeof(RtUuid));
    RtUuid *uuid = (RtUuid *)_uuid_h->ptr;
    if (uuid == NULL) {
        return NULL;
    }

    *uuid = SN_UUID_NAMESPACE_X500;
    return _uuid_h;
}

/* ============================================================================
 * Parsing Helpers
 * ============================================================================ */

static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ============================================================================
 * Parsing Methods
 * ============================================================================ */

RtHandleV2 *sn_uuid_from_string(RtArenaV2 *arena, const char *str) {
    if (arena == NULL || str == NULL) {
        return NULL;
    }

    size_t len = strlen(str);
    if (len != 36) {
        return NULL;
    }

    if (str[8] != '-' || str[13] != '-' || str[18] != '-' || str[23] != '-') {
        return NULL;
    }

    uint8_t bytes[16];
    int hex_positions[] = {0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34};

    for (int i = 0; i < 16; i++) {
        int pos = hex_positions[i];
        int high_nibble = hex_char_to_int(str[pos]);
        int low_nibble = hex_char_to_int(str[pos + 1]);

        if (high_nibble < 0 || low_nibble < 0) {
            return NULL;
        }

        bytes[i] = (uint8_t)((high_nibble << 4) | low_nibble);
    }

    RtHandleV2 *_uuid_h = rt_arena_v2_alloc(arena, sizeof(RtUuid));
    RtUuid *uuid = (RtUuid *)_uuid_h->ptr;
    if (uuid == NULL) {
        return NULL;
    }

    uuid->high = ((uint64_t)bytes[0] << 56) |
                 ((uint64_t)bytes[1] << 48) |
                 ((uint64_t)bytes[2] << 40) |
                 ((uint64_t)bytes[3] << 32) |
                 ((uint64_t)bytes[4] << 24) |
                 ((uint64_t)bytes[5] << 16) |
                 ((uint64_t)bytes[6] << 8)  |
                 ((uint64_t)bytes[7]);

    uuid->low = ((uint64_t)bytes[8] << 56)  |
                ((uint64_t)bytes[9] << 48)  |
                ((uint64_t)bytes[10] << 40) |
                ((uint64_t)bytes[11] << 32) |
                ((uint64_t)bytes[12] << 24) |
                ((uint64_t)bytes[13] << 16) |
                ((uint64_t)bytes[14] << 8)  |
                ((uint64_t)bytes[15]);

    return _uuid_h;
}

RtHandleV2 *sn_uuid_from_hex(RtArenaV2 *arena, const char *str) {
    if (arena == NULL || str == NULL) {
        return NULL;
    }

    size_t len = strlen(str);
    if (len != 32) {
        return NULL;
    }

    uint8_t bytes[16];
    for (int i = 0; i < 16; i++) {
        int high_nibble = hex_char_to_int(str[i * 2]);
        int low_nibble = hex_char_to_int(str[i * 2 + 1]);

        if (high_nibble < 0 || low_nibble < 0) {
            return NULL;
        }

        bytes[i] = (uint8_t)((high_nibble << 4) | low_nibble);
    }

    RtHandleV2 *_uuid_h = rt_arena_v2_alloc(arena, sizeof(RtUuid));
    RtUuid *uuid = (RtUuid *)_uuid_h->ptr;
    if (uuid == NULL) {
        return NULL;
    }

    uuid->high = ((uint64_t)bytes[0] << 56) |
                 ((uint64_t)bytes[1] << 48) |
                 ((uint64_t)bytes[2] << 40) |
                 ((uint64_t)bytes[3] << 32) |
                 ((uint64_t)bytes[4] << 24) |
                 ((uint64_t)bytes[5] << 16) |
                 ((uint64_t)bytes[6] << 8)  |
                 ((uint64_t)bytes[7]);

    uuid->low = ((uint64_t)bytes[8] << 56)  |
                ((uint64_t)bytes[9] << 48)  |
                ((uint64_t)bytes[10] << 40) |
                ((uint64_t)bytes[11] << 32) |
                ((uint64_t)bytes[12] << 24) |
                ((uint64_t)bytes[13] << 16) |
                ((uint64_t)bytes[14] << 8)  |
                ((uint64_t)bytes[15]);

    return _uuid_h;
}

static int base64_url_char_to_int(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

static RtHandleV2 *sn_uuid_from_bytes(RtArenaV2 *arena, const unsigned char *bytes) {
    if (arena == NULL || bytes == NULL) {
        return NULL;
    }

    RtHandleV2 *_uuid_h = rt_arena_v2_alloc(arena, sizeof(RtUuid));
    RtUuid *uuid = (RtUuid *)_uuid_h->ptr;
    if (uuid == NULL) {
        return NULL;
    }

    uuid->high = ((uint64_t)bytes[0] << 56) |
                 ((uint64_t)bytes[1] << 48) |
                 ((uint64_t)bytes[2] << 40) |
                 ((uint64_t)bytes[3] << 32) |
                 ((uint64_t)bytes[4] << 24) |
                 ((uint64_t)bytes[5] << 16) |
                 ((uint64_t)bytes[6] << 8)  |
                 ((uint64_t)bytes[7]);

    uuid->low = ((uint64_t)bytes[8] << 56)  |
                ((uint64_t)bytes[9] << 48)  |
                ((uint64_t)bytes[10] << 40) |
                ((uint64_t)bytes[11] << 32) |
                ((uint64_t)bytes[12] << 24) |
                ((uint64_t)bytes[13] << 16) |
                ((uint64_t)bytes[14] << 8)  |
                ((uint64_t)bytes[15]);

    return _uuid_h;
}

RtHandleV2 *sn_uuid_from_base64(RtArenaV2 *arena, const char *str) {
    if (arena == NULL || str == NULL) {
        return NULL;
    }

    size_t len = strlen(str);
    if (len != 22) {
        return NULL;
    }

    uint8_t bytes[16];
    int byte_idx = 0;

    for (int i = 0; i < 20; i += 4) {
        int v0 = base64_url_char_to_int(str[i]);
        int v1 = base64_url_char_to_int(str[i + 1]);
        int v2 = base64_url_char_to_int(str[i + 2]);
        int v3 = base64_url_char_to_int(str[i + 3]);

        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
            return NULL;
        }

        uint32_t triplet = ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12) |
                           ((uint32_t)v2 << 6) | (uint32_t)v3;

        bytes[byte_idx++] = (uint8_t)((triplet >> 16) & 0xFF);
        bytes[byte_idx++] = (uint8_t)((triplet >> 8) & 0xFF);
        bytes[byte_idx++] = (uint8_t)(triplet & 0xFF);
    }

    int v0 = base64_url_char_to_int(str[20]);
    int v1 = base64_url_char_to_int(str[21]);

    if (v0 < 0 || v1 < 0) {
        return NULL;
    }

    if ((v1 & 0x0F) != 0) {
        return NULL;
    }

    bytes[byte_idx] = (uint8_t)((v0 << 2) | (v1 >> 4));

    return sn_uuid_from_bytes(arena, bytes);
}
