/* ==============================================================================
 * sdk/bytes.sn.c - Self-contained Bytes Implementation for Sindarin SDK
 * ==============================================================================
 * Minimal runtime version - no arena, uses SnArray for byte array returns.
 * ============================================================================== */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

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
SnArray *sn_bytes_from_hex(char *hex)
{
    SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
    arr->elem_tag = SN_TAG_BYTE;

    if (hex == NULL) return arr;

    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        fprintf(stderr, "SnBytes.fromHex: hex string must have even length\n");
        exit(1);
    }

    for (size_t i = 0; i < hex_len; i += 2) {
        unsigned char hi = hex[i];
        unsigned char lo = hex[i + 1];
        int hi_val, lo_val;

        if (hi >= '0' && hi <= '9') hi_val = hi - '0';
        else if (hi >= 'a' && hi <= 'f') hi_val = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') hi_val = hi - 'A' + 10;
        else { fprintf(stderr, "SnBytes.fromHex: invalid hex character '%c'\n", hi); exit(1); }

        if (lo >= '0' && lo <= '9') lo_val = lo - '0';
        else if (lo >= 'a' && lo <= 'f') lo_val = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') lo_val = lo - 'A' + 10;
        else { fprintf(stderr, "SnBytes.fromHex: invalid hex character '%c'\n", lo); exit(1); }

        unsigned char byte = (unsigned char)((hi_val << 4) | lo_val);
        sn_array_push(arr, &byte);
    }

    return arr;
}

/* Decode Base64 string to byte array */
SnArray *sn_bytes_from_base64(char *b64)
{
    SnArray *arr = sn_array_new(sizeof(unsigned char), 0);
    arr->elem_tag = SN_TAG_BYTE;

    if (b64 == NULL) return arr;

    size_t len = strlen(b64);
    if (len == 0) return arr;

    size_t i = 0;
    while (i < len) {
        /* Skip whitespace */
        while (i < len && (b64[i] == ' ' || b64[i] == '\n' || b64[i] == '\r' || b64[i] == '\t')) {
            i++;
        }
        if (i >= len) break;

        unsigned int vals[4] = {0, 0, 0, 0};
        int valid_chars = 0;

        for (int j = 0; j < 4 && i < len; j++, i++) {
            if (b64[i] == '=') {
                vals[j] = 0;
            } else {
                signed char val = base64_decode_table[(unsigned char)b64[i]];
                if (val < 0) {
                    fprintf(stderr, "SnBytes.fromBase64: invalid Base64 character '%c'\n", b64[i]);
                    exit(1);
                }
                vals[j] = (unsigned int)val;
                valid_chars++;
            }
        }

        unsigned int combined = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];

        unsigned char byte;
        byte = (unsigned char)((combined >> 16) & 0xFF);
        sn_array_push(arr, &byte);

        if (valid_chars >= 3) {
            byte = (unsigned char)((combined >> 8) & 0xFF);
            sn_array_push(arr, &byte);
        }
        if (valid_chars >= 4) {
            byte = (unsigned char)(combined & 0xFF);
            sn_array_push(arr, &byte);
        }
    }

    return arr;
}
