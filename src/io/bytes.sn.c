/* ==============================================================================
 * sdk/bytes.sn.c - Self-contained Bytes Implementation for Sindarin SDK
 * ==============================================================================
 * This file provides the C implementation for the SnBytes type.
 * It is compiled via #pragma source and linked with Sindarin code.
 * ============================================================================== */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* Include runtime arena for proper memory management */
#include "runtime/runtime_arena.h"
#include "runtime/array/runtime_array.h"
#include "runtime/arena/managed_arena.h"
#include "runtime/array/runtime_array_h.h"

/* ============================================================================
 * Bytes Type Definition (unused, just for namespace)
 * ============================================================================ */

typedef struct RtSnBytes {
    int32_t _unused;
} RtSnBytes;

/* ============================================================================
 * Base64 Decoding Table
 * ============================================================================ */

static const signed char base64_decode_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

/* ============================================================================
 * Decoding Functions
 * ============================================================================ */

/* Decode hexadecimal string to byte array */
RtHandle sn_bytes_from_hex(RtManagedArena *arena, const char *hex)
{
    if (hex == NULL) {
        return rt_array_create_byte_h(arena, 0, NULL);
    }

    size_t hex_len = strlen(hex);

    /* Hex string must have even length */
    if (hex_len % 2 != 0) {
        fprintf(stderr, "SnBytes.fromHex: hex string must have even length\n");
        exit(1);
    }

    size_t byte_len = hex_len / 2;

    /* Allocate temporary buffer for decoded bytes */
    unsigned char *temp_bytes = malloc(byte_len);
    if (temp_bytes == NULL && byte_len > 0) {
        fprintf(stderr, "SnBytes.fromHex: memory allocation failed\n");
        exit(1);
    }

    for (size_t i = 0; i < byte_len; i++) {
        unsigned char hi = hex[i * 2];
        unsigned char lo = hex[i * 2 + 1];

        int hi_val, lo_val;

        /* Parse high nibble */
        if (hi >= '0' && hi <= '9') {
            hi_val = hi - '0';
        } else if (hi >= 'a' && hi <= 'f') {
            hi_val = hi - 'a' + 10;
        } else if (hi >= 'A' && hi <= 'F') {
            hi_val = hi - 'A' + 10;
        } else {
            free(temp_bytes);
            fprintf(stderr, "SnBytes.fromHex: invalid hex character '%c'\n", hi);
            exit(1);
        }

        /* Parse low nibble */
        if (lo >= '0' && lo <= '9') {
            lo_val = lo - '0';
        } else if (lo >= 'a' && lo <= 'f') {
            lo_val = lo - 'a' + 10;
        } else if (lo >= 'A' && lo <= 'F') {
            lo_val = lo - 'A' + 10;
        } else {
            free(temp_bytes);
            fprintf(stderr, "SnBytes.fromHex: invalid hex character '%c'\n", lo);
            exit(1);
        }

        temp_bytes[i] = (unsigned char)((hi_val << 4) | lo_val);
    }

    RtHandle result = rt_array_create_byte_h(arena, byte_len, temp_bytes);
    free(temp_bytes);
    return result;
}

/* Decode Base64 string to byte array */
RtHandle sn_bytes_from_base64(RtManagedArena *arena, const char *b64)
{
    if (b64 == NULL) {
        return rt_array_create_byte_h(arena, 0, NULL);
    }

    size_t len = strlen(b64);
    if (len == 0) {
        return rt_array_create_byte_h(arena, 0, NULL);
    }

    /* Count padding characters */
    size_t padding = 0;
    if (len >= 1 && b64[len - 1] == '=') padding++;
    if (len >= 2 && b64[len - 2] == '=') padding++;

    /* Calculate output size: 3 output bytes for every 4 input chars */
    size_t out_len = (len / 4) * 3 - padding;

    /* Allocate temporary buffer for decoded bytes */
    unsigned char *temp_bytes = malloc(out_len);
    if (temp_bytes == NULL && out_len > 0) {
        fprintf(stderr, "SnBytes.fromBase64: memory allocation failed\n");
        exit(1);
    }

    size_t i = 0;
    size_t out_idx = 0;

    while (i < len) {
        /* Skip whitespace */
        while (i < len && (b64[i] == ' ' || b64[i] == '\n' || b64[i] == '\r' || b64[i] == '\t')) {
            i++;
        }
        if (i >= len) break;

        /* Read 4 characters (some may be padding) */
        unsigned int vals[4] = {0, 0, 0, 0};
        int valid_chars = 0;

        for (int j = 0; j < 4 && i < len; j++, i++) {
            if (b64[i] == '=') {
                vals[j] = 0;
            } else {
                signed char val = base64_decode_table[(unsigned char)b64[i]];
                if (val < 0) {
                    free(temp_bytes);
                    fprintf(stderr, "SnBytes.fromBase64: invalid Base64 character '%c'\n", b64[i]);
                    exit(1);
                }
                vals[j] = (unsigned int)val;
                valid_chars++;
            }
        }

        /* Decode: combine 4 6-bit values into 3 8-bit values */
        unsigned int combined = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];

        if (out_idx < out_len) {
            temp_bytes[out_idx++] = (unsigned char)((combined >> 16) & 0xFF);
        }
        if (out_idx < out_len && valid_chars >= 3) {
            temp_bytes[out_idx++] = (unsigned char)((combined >> 8) & 0xFF);
        }
        if (out_idx < out_len && valid_chars >= 4) {
            temp_bytes[out_idx++] = (unsigned char)(combined & 0xFF);
        }
    }

    RtHandle result = rt_array_create_byte_h(arena, out_len, temp_bytes);
    free(temp_bytes);
    return result;
}
