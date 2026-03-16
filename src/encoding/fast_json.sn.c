/*
 * sdk/encoding/fast/json.sn.c — Fast JSON Encoder/Decoder
 *
 * Encoder: builds JSON string directly with a growable buffer (no library).
 * Decoder: recursive-descent parser into a lightweight node tree, then
 *          vtable methods do key/index lookups.
 *
 * Zero external dependencies. All memory is managed explicitly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

/* ===== Growable buffer ===== */

typedef struct {
    char *data;
    size_t len, cap;
} FJBuf;

static FJBuf *fjbuf_new(size_t initial) {
    FJBuf *b = (FJBuf *)calloc(1, sizeof(FJBuf));
    b->cap = initial > 64 ? initial : 64;
    b->data = (char *)malloc(b->cap);
    b->data[0] = '\0';
    return b;
}

static void fjbuf_ensure(FJBuf *b, size_t need) {
    if (b->len + need >= b->cap) {
        b->cap = (b->cap + need) * 2;
        b->data = (char *)realloc(b->data, b->cap);
    }
}

static void fjbuf_char(FJBuf *b, char c) {
    fjbuf_ensure(b, 1);
    b->data[b->len++] = c;
    b->data[b->len] = '\0';
}

static void fjbuf_raw(FJBuf *b, const char *s, size_t n) {
    fjbuf_ensure(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void fjbuf_str(FJBuf *b, const char *s) {
    fjbuf_raw(b, s, strlen(s));
}

/* Append a JSON-escaped string (without surrounding quotes) */
static void fjbuf_escaped(FJBuf *b, const char *s) {
    if (!s) return;
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '"':  fjbuf_raw(b, "\\\"", 2); break;
            case '\\': fjbuf_raw(b, "\\\\", 2); break;
            case '\n': fjbuf_raw(b, "\\n", 2);  break;
            case '\r': fjbuf_raw(b, "\\r", 2);  break;
            case '\t': fjbuf_raw(b, "\\t", 2);  break;
            case '\b': fjbuf_raw(b, "\\b", 2);  break;
            case '\f': fjbuf_raw(b, "\\f", 2);  break;
            default:
                if ((unsigned char)*p < 0x20) {
                    char esc[8];
                    int n = snprintf(esc, sizeof(esc), "\\u%04x", (unsigned char)*p);
                    fjbuf_raw(b, esc, n);
                } else {
                    fjbuf_char(b, *p);
                }
                break;
        }
    }
}

static void fjbuf_free(FJBuf *b) {
    if (b) { free(b->data); free(b); }
}

/* ===== JSON Encoder ===== */

typedef struct {
    FJBuf *buf;       /* shared across all sub-encoders */
    int first;        /* comma tracking for this level */
    int is_array;
} FJEnc;

static void fje_comma(FJEnc *j) {
    if (!j->first) fjbuf_char(j->buf, ',');
    j->first = 0;
}

static __sn__Encoder *fje_make_sub(FJBuf *buf, int is_array);

static void fje_write_str(__sn__Encoder *self, const char *key, const char *val) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fje_comma(j);
    fjbuf_char(j->buf, '"');
    fjbuf_str(j->buf, key);
    fjbuf_raw(j->buf, "\":\"", 3);
    fjbuf_escaped(j->buf, val);
    fjbuf_char(j->buf, '"');
}

static void fje_write_int(__sn__Encoder *self, const char *key, long long val) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fje_comma(j);
    char tmp[96];
    int n = snprintf(tmp, sizeof(tmp), "\"%s\":%lld", key, val);
    fjbuf_raw(j->buf, tmp, n);
}

static void fje_write_double(__sn__Encoder *self, const char *key, double val) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fje_comma(j);
    char tmp[96];
    int n;
    if (val == (long long)val && fabs(val) < 1e15) {
        n = snprintf(tmp, sizeof(tmp), "\"%s\":%g", key, val);
    } else {
        n = snprintf(tmp, sizeof(tmp), "\"%s\":%.17g", key, val);
    }
    fjbuf_raw(j->buf, tmp, n);
}

static void fje_write_bool(__sn__Encoder *self, const char *key, long long val) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fje_comma(j);
    char tmp[96];
    int n = snprintf(tmp, sizeof(tmp), "\"%s\":%s", key, val ? "true" : "false");
    fjbuf_raw(j->buf, tmp, n);
}

static void fje_write_null(__sn__Encoder *self, const char *key) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fje_comma(j);
    char tmp[96];
    int n = snprintf(tmp, sizeof(tmp), "\"%s\":null", key);
    fjbuf_raw(j->buf, tmp, n);
}

static __sn__Encoder *fje_begin_object(__sn__Encoder *self, const char *key) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fje_comma(j);
    fjbuf_char(j->buf, '"');
    fjbuf_str(j->buf, key);
    fjbuf_raw(j->buf, "\":{", 3);
    return fje_make_sub(j->buf, 0);
}

static __sn__Encoder *fje_begin_array(__sn__Encoder *self, const char *key) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fje_comma(j);
    fjbuf_char(j->buf, '"');
    fjbuf_str(j->buf, key);
    fjbuf_raw(j->buf, "\":[", 3);
    return fje_make_sub(j->buf, 1);
}

static void fje_end(__sn__Encoder *self) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fjbuf_char(j->buf, j->is_array ? ']' : '}');
    free(j);
    free(self);
}

static void fje_append_str(__sn__Encoder *self, const char *val) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fje_comma(j);
    fjbuf_char(j->buf, '"');
    fjbuf_escaped(j->buf, val);
    fjbuf_char(j->buf, '"');
}

static void fje_append_int(__sn__Encoder *self, long long val) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fje_comma(j);
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%lld", val);
    fjbuf_raw(j->buf, tmp, n);
}

static void fje_append_double(__sn__Encoder *self, double val) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fje_comma(j);
    char tmp[32];
    int n;
    if (val == (long long)val && fabs(val) < 1e15) {
        n = snprintf(tmp, sizeof(tmp), "%g", val);
    } else {
        n = snprintf(tmp, sizeof(tmp), "%.17g", val);
    }
    fjbuf_raw(j->buf, tmp, n);
}

static void fje_append_bool(__sn__Encoder *self, long long val) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fje_comma(j);
    fjbuf_str(j->buf, val ? "true" : "false");
}

static __sn__Encoder *fje_append_object(__sn__Encoder *self) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fje_comma(j);
    fjbuf_char(j->buf, '{');
    return fje_make_sub(j->buf, 0);
}

static char *fje_result(__sn__Encoder *self) {
    FJEnc *j = (FJEnc *)self->__sn__ctx;
    fjbuf_char(j->buf, j->is_array ? ']' : '}');
    char *result = strdup(j->buf->data);
    fjbuf_free(j->buf);
    free(j);
    self->__sn__ctx = NULL;
    /* Don't free self — sn_auto_Encoder cleanup handles that */
    return result;
}

static __sn__EncoderVTable fje_vt = {
    .writeStr    = fje_write_str,
    .writeInt    = fje_write_int,
    .writeDouble = fje_write_double,
    .writeBool   = fje_write_bool,
    .writeNull   = fje_write_null,
    .beginObject = fje_begin_object,
    .beginArray  = fje_begin_array,
    .end         = fje_end,
    .appendStr   = fje_append_str,
    .appendInt   = fje_append_int,
    .appendDouble= fje_append_double,
    .appendBool  = fje_append_bool,
    .appendObject= fje_append_object,
    .result      = fje_result,
};

static __sn__Encoder *fje_make_sub(FJBuf *buf, int is_array) {
    __sn__Encoder *enc = (__sn__Encoder *)calloc(1, sizeof(__sn__Encoder));
    FJEnc *j = (FJEnc *)calloc(1, sizeof(FJEnc));
    j->buf = buf;
    j->first = 1;
    j->is_array = is_array;
    enc->__sn__vt = &fje_vt;
    enc->__sn__ctx = j;
    return enc;
}

__sn__Encoder *sn_fast_json_encoder(void) {
    FJBuf *buf = fjbuf_new(256);
    fjbuf_char(buf, '{');
    __sn__Encoder *enc = (__sn__Encoder *)calloc(1, sizeof(__sn__Encoder));
    FJEnc *j = (FJEnc *)calloc(1, sizeof(FJEnc));
    j->buf = buf;
    j->first = 1;
    j->is_array = 0;
    enc->__sn__vt = &fje_vt;
    enc->__sn__ctx = j;
    return enc;
}

__sn__Encoder *sn_fast_json_array_encoder(void) {
    FJBuf *buf = fjbuf_new(256);
    fjbuf_char(buf, '[');
    __sn__Encoder *enc = (__sn__Encoder *)calloc(1, sizeof(__sn__Encoder));
    FJEnc *j = (FJEnc *)calloc(1, sizeof(FJEnc));
    j->buf = buf;
    j->first = 1;
    j->is_array = 1;
    enc->__sn__vt = &fje_vt;
    enc->__sn__ctx = j;
    return enc;
}

/* ===== JSON Decoder ===== */

/*
 * Recursive-descent parser → lightweight node tree.
 * Nodes are allocated individually. The tree is NOT freed automatically;
 * for a test/SDK context this is acceptable. A production version could
 * use an arena allocator for zero-overhead cleanup.
 */

typedef enum { FJN_OBJ, FJN_ARR, FJN_STR, FJN_INT, FJN_DOUBLE, FJN_BOOL, FJN_NULL } FJNType;

typedef struct FJNode FJNode;
typedef struct { char *key; FJNode *val; } FJKV;

struct FJNode {
    FJNType type;
    union {
        struct { FJKV *items; int count; int cap; } obj;
        struct { FJNode **items; int count; int cap; } arr;
        char *str;
        long long ival;
        double dval;
        int bval;
    };
};

static const char *fj_skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static char *fj_parse_string(const char **pp) {
    const char *p = *pp;
    if (*p != '"') return NULL;
    p++;
    FJBuf *b = fjbuf_new(64);
    while (*p && *p != '"') {
        if (*p == '\\') {
            p++;
            switch (*p) {
                case '"':  fjbuf_char(b, '"'); break;
                case '\\': fjbuf_char(b, '\\'); break;
                case '/':  fjbuf_char(b, '/'); break;
                case 'n':  fjbuf_char(b, '\n'); break;
                case 'r':  fjbuf_char(b, '\r'); break;
                case 't':  fjbuf_char(b, '\t'); break;
                case 'b':  fjbuf_char(b, '\b'); break;
                case 'f':  fjbuf_char(b, '\f'); break;
                case 'u': {
                    /* Basic \uXXXX — decode as ASCII if possible, skip otherwise */
                    unsigned cp = 0;
                    for (int i = 0; i < 4 && p[1]; i++) {
                        p++;
                        char c = *p;
                        cp <<= 4;
                        if (c >= '0' && c <= '9') cp |= c - '0';
                        else if (c >= 'a' && c <= 'f') cp |= 10 + c - 'a';
                        else if (c >= 'A' && c <= 'F') cp |= 10 + c - 'A';
                    }
                    if (cp < 128) fjbuf_char(b, (char)cp);
                    else fjbuf_char(b, '?');
                    break;
                }
                default: fjbuf_char(b, *p); break;
            }
        } else {
            fjbuf_char(b, *p);
        }
        p++;
    }
    if (*p == '"') p++;
    *pp = p;
    char *result = strdup(b->data);
    fjbuf_free(b);
    return result;
}

static FJNode *fj_parse(const char **pp);

static FJNode *fj_parse(const char **pp) {
    const char *p = fj_skip_ws(*pp);
    FJNode *n = (FJNode *)calloc(1, sizeof(FJNode));

    if (*p == '{') {
        n->type = FJN_OBJ;
        p++;
        n->obj.cap = 8;
        n->obj.items = (FJKV *)malloc(sizeof(FJKV) * n->obj.cap);
        p = fj_skip_ws(p);
        while (*p && *p != '}') {
            if (n->obj.count >= n->obj.cap) {
                n->obj.cap *= 2;
                n->obj.items = (FJKV *)realloc(n->obj.items, sizeof(FJKV) * n->obj.cap);
            }
            p = fj_skip_ws(p);
            char *key = fj_parse_string(&p);
            p = fj_skip_ws(p);
            if (*p == ':') p++;
            FJNode *val = fj_parse(&p);
            n->obj.items[n->obj.count++] = (FJKV){ key, val };
            p = fj_skip_ws(p);
            if (*p == ',') p++;
        }
        if (*p == '}') p++;
    } else if (*p == '[') {
        n->type = FJN_ARR;
        p++;
        n->arr.cap = 8;
        n->arr.items = (FJNode **)malloc(sizeof(FJNode *) * n->arr.cap);
        p = fj_skip_ws(p);
        while (*p && *p != ']') {
            if (n->arr.count >= n->arr.cap) {
                n->arr.cap *= 2;
                n->arr.items = (FJNode **)realloc(n->arr.items, sizeof(FJNode *) * n->arr.cap);
            }
            n->arr.items[n->arr.count++] = fj_parse(&p);
            p = fj_skip_ws(p);
            if (*p == ',') p++;
        }
        if (*p == ']') p++;
    } else if (*p == '"') {
        n->type = FJN_STR;
        n->str = fj_parse_string(&p);
    } else if (*p == 't') {
        n->type = FJN_BOOL; n->bval = 1; p += 4;
    } else if (*p == 'f') {
        n->type = FJN_BOOL; n->bval = 0; p += 5;
    } else if (*p == 'n') {
        n->type = FJN_NULL; p += 4;
    } else {
        /* Number */
        char *end;
        double d = strtod(p, &end);
        int is_int = 1;
        for (const char *c = p; c < end; c++) {
            if (*c == '.' || *c == 'e' || *c == 'E') { is_int = 0; break; }
        }
        if (is_int) { n->type = FJN_INT; n->ival = (long long)d; }
        else { n->type = FJN_DOUBLE; n->dval = d; }
        p = end;
    }
    *pp = p;
    return n;
}

static void fj_node_free(FJNode *n) {
    if (!n) return;
    switch (n->type) {
        case FJN_OBJ:
            for (int i = 0; i < n->obj.count; i++) {
                free(n->obj.items[i].key);
                fj_node_free(n->obj.items[i].val);
            }
            free(n->obj.items);
            break;
        case FJN_ARR:
            for (int i = 0; i < n->arr.count; i++) {
                fj_node_free(n->arr.items[i]);
            }
            free(n->arr.items);
            break;
        case FJN_STR:
            free(n->str);
            break;
        default:
            break;
    }
    free(n);
}

static FJNode *fj_get(FJNode *n, const char *key) {
    if (!n || n->type != FJN_OBJ) return NULL;
    for (int i = 0; i < n->obj.count; i++) {
        if (strcmp(n->obj.items[i].key, key) == 0) return n->obj.items[i].val;
    }
    return NULL;
}

/* Decoder context */
typedef struct {
    FJNode *node;    /* borrowed reference into the parse tree */
    FJNode *root;    /* root node — only non-NULL for the root decoder (owns the tree) */
} FJDec;

static __sn__Decoder *fjd_make(FJNode *node, FJNode *root);

static char *fjd_read_str(__sn__Decoder *self, const char *key) {
    FJDec *d = (FJDec *)self->__sn__ctx;
    FJNode *v = fj_get(d->node, key);
    return (v && v->type == FJN_STR) ? strdup(v->str) : strdup("");
}

static long long fjd_read_int(__sn__Decoder *self, const char *key) {
    FJDec *d = (FJDec *)self->__sn__ctx;
    FJNode *v = fj_get(d->node, key);
    return (v && v->type == FJN_INT) ? v->ival : 0;
}

static double fjd_read_double(__sn__Decoder *self, const char *key) {
    FJDec *d = (FJDec *)self->__sn__ctx;
    FJNode *v = fj_get(d->node, key);
    if (v && v->type == FJN_DOUBLE) return v->dval;
    if (v && v->type == FJN_INT) return (double)v->ival;
    return 0.0;
}

static long long fjd_read_bool(__sn__Decoder *self, const char *key) {
    FJDec *d = (FJDec *)self->__sn__ctx;
    FJNode *v = fj_get(d->node, key);
    return (v && v->type == FJN_BOOL) ? v->bval : 0;
}

static long long fjd_has_key(__sn__Decoder *self, const char *key) {
    FJDec *d = (FJDec *)self->__sn__ctx;
    return fj_get(d->node, key) != NULL;
}

static __sn__Decoder *fjd_read_object(__sn__Decoder *self, const char *key) {
    FJDec *d = (FJDec *)self->__sn__ctx;
    return fjd_make(fj_get(d->node, key), NULL);
}

static __sn__Decoder *fjd_read_array(__sn__Decoder *self, const char *key) {
    FJDec *d = (FJDec *)self->__sn__ctx;
    return fjd_make(fj_get(d->node, key), NULL);
}

static long long fjd_length(__sn__Decoder *self) {
    FJDec *d = (FJDec *)self->__sn__ctx;
    if (d->node && d->node->type == FJN_ARR) return d->node->arr.count;
    return 0;
}

static __sn__Decoder *fjd_at(__sn__Decoder *self, long long index) {
    FJDec *d = (FJDec *)self->__sn__ctx;
    if (d->node && d->node->type == FJN_ARR && index < d->node->arr.count)
        return fjd_make(d->node->arr.items[index], NULL);
    return fjd_make(NULL, NULL);
}

static char *fjd_at_str(__sn__Decoder *self, long long index) {
    FJDec *d = (FJDec *)self->__sn__ctx;
    if (d->node && d->node->type == FJN_ARR && index < d->node->arr.count) {
        FJNode *v = d->node->arr.items[index];
        if (v->type == FJN_STR) return strdup(v->str);
    }
    return strdup("");
}

static long long fjd_at_int(__sn__Decoder *self, long long index) {
    FJDec *d = (FJDec *)self->__sn__ctx;
    if (d->node && d->node->type == FJN_ARR && index < d->node->arr.count) {
        FJNode *v = d->node->arr.items[index];
        if (v->type == FJN_INT) return v->ival;
    }
    return 0;
}

static double fjd_at_double(__sn__Decoder *self, long long index) {
    FJDec *d = (FJDec *)self->__sn__ctx;
    if (d->node && d->node->type == FJN_ARR && index < d->node->arr.count) {
        FJNode *v = d->node->arr.items[index];
        if (v->type == FJN_DOUBLE) return v->dval;
        if (v->type == FJN_INT) return (double)v->ival;
    }
    return 0.0;
}

static long long fjd_at_bool(__sn__Decoder *self, long long index) {
    FJDec *d = (FJDec *)self->__sn__ctx;
    if (d->node && d->node->type == FJN_ARR && index < d->node->arr.count) {
        FJNode *v = d->node->arr.items[index];
        if (v->type == FJN_BOOL) return v->bval;
    }
    return 0;
}

static __sn__DecoderVTable fjd_vt = {
    .readStr    = fjd_read_str,
    .readInt    = fjd_read_int,
    .readDouble = fjd_read_double,
    .readBool   = fjd_read_bool,
    .hasKey     = fjd_has_key,
    .readObject = fjd_read_object,
    .readArray  = fjd_read_array,
    .length     = fjd_length,
    .at         = fjd_at,
    .atStr      = fjd_at_str,
    .atInt      = fjd_at_int,
    .atDouble   = fjd_at_double,
    .atBool     = fjd_at_bool,
};

static __sn__Decoder *fjd_make(FJNode *node, FJNode *root) {
    __sn__Decoder *dec = (__sn__Decoder *)calloc(1, sizeof(__sn__Decoder));
    FJDec *d = (FJDec *)calloc(1, sizeof(FJDec));
    d->node = node;
    d->root = root;
    dec->__sn__vt = &fjd_vt;
    dec->__sn__ctx = d;
    return dec;
}

__sn__Decoder *sn_fast_json_decoder(const char *input) {
    const char *p = input;
    FJNode *root = fj_parse(&p);
    return fjd_make(root, root);
}
