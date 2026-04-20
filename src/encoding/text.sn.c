/* ==============================================================================
 * sdk/encoding/text.sn.c - StringBuilder implementation for Sindarin SDK
 * ==============================================================================
 * Amortised O(1) append-backed string buffer. Grows capacity geometrically
 * (doubling) so N appends of total T bytes cost O(T) total.
 *
 * Fields on the Sindarin side are opaque `long` values so the auto-generated
 * __sn__StringBuilder_release does not try to free() them as if they were
 * char*. The native code manages the buffer explicitly via dispose().
 * ============================================================================== */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * Type alias
 * ============================================================================ */

typedef __sn__StringBuilder SnStringBuilder;

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

#define SB_BUF(sb) ((char *)(uintptr_t)(sb)->buf)
#define SB_SET_BUF(sb, v) ((sb)->buf = (long long)(uintptr_t)(v))

#define SB_DEFAULT_CAPACITY 256

/* Ensure the buffer has room for `need` additional bytes plus a NUL.
 * Grows capacity geometrically. Exits on allocation failure -- the same
 * fatal behaviour the rest of the SDK uses for OOM. */
static void sb_reserve(SnStringBuilder *sb, long long need)
{
    long long required = sb->len + need + 1;
    if (required <= sb->cap) {
        return;
    }

    long long new_cap = sb->cap > 0 ? sb->cap : SB_DEFAULT_CAPACITY;
    while (new_cap < required) {
        new_cap *= 2;
    }

    char *old_buf = SB_BUF(sb);
    char *new_buf = (char *)realloc(old_buf, (size_t)new_cap);
    if (new_buf == NULL) {
        fprintf(stderr, "StringBuilder: realloc failed (requested %lld bytes)\n",
                new_cap);
        exit(1);
    }
    SB_SET_BUF(sb, new_buf);
    sb->cap = new_cap;
}

/* Append `n` bytes from `src` to the builder. Maintains NUL termination. */
static void sb_append_bytes(SnStringBuilder *sb, const char *src, size_t n)
{
    if (n == 0) {
        return;
    }
    sb_reserve(sb, (long long)n);
    char *buf = SB_BUF(sb);
    memcpy(buf + sb->len, src, n);
    sb->len += (long long)n;
    buf[sb->len] = '\0';
}

/* ============================================================================
 * Construction
 * ============================================================================ */

SnStringBuilder *sn_text_new(void)
{
    SnStringBuilder *sb = __sn__StringBuilder__new();
    if (sb == NULL) {
        fprintf(stderr, "StringBuilder: struct allocation failed\n");
        exit(1);
    }
    char *buf = (char *)calloc(SB_DEFAULT_CAPACITY, 1);
    if (buf == NULL) {
        fprintf(stderr, "StringBuilder: initial buffer allocation failed\n");
        exit(1);
    }
    SB_SET_BUF(sb, buf);
    sb->cap = SB_DEFAULT_CAPACITY;
    sb->len = 0;
    return sb;
}

SnStringBuilder *sn_text_new_with_capacity(long long initial_cap)
{
    SnStringBuilder *sb = __sn__StringBuilder__new();
    if (sb == NULL) {
        fprintf(stderr, "StringBuilder: struct allocation failed\n");
        exit(1);
    }
    long long cap = initial_cap > 0 ? initial_cap : SB_DEFAULT_CAPACITY;
    char *buf = (char *)calloc((size_t)cap, 1);
    if (buf == NULL) {
        fprintf(stderr, "StringBuilder: initial buffer allocation failed (cap=%lld)\n",
                cap);
        exit(1);
    }
    SB_SET_BUF(sb, buf);
    sb->cap = cap;
    sb->len = 0;
    return sb;
}

/* ============================================================================
 * Append
 * ============================================================================ */

void sn_text_append(SnStringBuilder *sb, char *s)
{
    if (sb == NULL || s == NULL) {
        return;
    }
    sb_append_bytes(sb, s, strlen(s));
}

void sn_text_append_int(SnStringBuilder *sb, long long n)
{
    if (sb == NULL) {
        return;
    }
    char tmp[32];
    int written = snprintf(tmp, sizeof(tmp), "%lld", n);
    if (written <= 0) {
        return;
    }
    sb_append_bytes(sb, tmp, (size_t)written);
}

void sn_text_append_double(SnStringBuilder *sb, double v)
{
    if (sb == NULL) {
        return;
    }
    /* %.17g is the lossless round-trip format for IEEE 754 doubles. */
    char tmp[64];
    int written = snprintf(tmp, sizeof(tmp), "%.17g", v);
    if (written <= 0) {
        return;
    }
    sb_append_bytes(sb, tmp, (size_t)written);
}

void sn_text_append_bool(SnStringBuilder *sb, bool b)
{
    if (sb == NULL) {
        return;
    }
    if (b) {
        sb_append_bytes(sb, "true", 4);
    } else {
        sb_append_bytes(sb, "false", 5);
    }
}

/* ============================================================================
 * Size / Reset
 * ============================================================================ */

long long sn_text_length(SnStringBuilder *sb)
{
    if (sb == NULL) {
        return 0;
    }
    return sb->len;
}

void sn_text_clear(SnStringBuilder *sb)
{
    if (sb == NULL) {
        return;
    }
    char *buf = SB_BUF(sb);
    if (buf != NULL && sb->cap > 0) {
        buf[0] = '\0';
    }
    sb->len = 0;
}

/* ============================================================================
 * Extract / Dispose
 * ============================================================================ */

char *sn_text_to_string(SnStringBuilder *sb)
{
    if (sb == NULL) {
        return strdup("");
    }
    char *buf = SB_BUF(sb);
    if (buf == NULL) {
        return strdup("");
    }
    /* strdup over the NUL-terminated prefix -- caller owns the returned
     * string. The builder retains its own buffer and can keep appending
     * or be disposed independently. */
    return strdup(buf);
}

void sn_text_dispose(SnStringBuilder *sb)
{
    if (sb == NULL) {
        return;
    }
    char *buf = SB_BUF(sb);
    if (buf != NULL) {
        free(buf);
        SB_SET_BUF(sb, NULL);
    }
    sb->cap = 0;
    sb->len = 0;
}
