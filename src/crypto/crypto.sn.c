/* ==============================================================================
 * sdk/crypto.sn.c - Self-contained Crypto Implementation for Sindarin SDK
 * ==============================================================================
 * Provides cryptographic operations using OpenSSL's libcrypto (EVP API).
 * Minimal runtime version - no arena, uses SnArray for byte array returns.
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

/* ============================================================================
 * RtCrypto Type Definition (Static-only, never instantiated)
 * ============================================================================ */

typedef struct RtCrypto {
    int _unused;
} RtCrypto;

/* ============================================================================
 * Internal Helper: Create SnArray from raw byte buffer
 * ============================================================================ */

static SnArray *sn_crypto_make_byte_array(unsigned char *buf, size_t len)
{
    SnArray *arr = sn_array_new(sizeof(unsigned char), (long long)len);
    arr->elem_tag = SN_TAG_BYTE;
    for (size_t i = 0; i < len; i++) {
        sn_array_push(arr, &buf[i]);
    }
    return arr;
}

/* ============================================================================
 * Internal Helper: Generic EVP Digest
 * ============================================================================
 * Returns heap-allocated buffer that caller must free.
 * Returns NULL on error, sets *out_len to digest length on success.
 * ============================================================================ */

static unsigned char *sn_crypto_digest_internal(const unsigned char *data,
                                                 size_t data_len, const EVP_MD *md,
                                                 unsigned int *out_len)
{
    if (md == NULL) {
        return NULL;
    }

    unsigned int digest_len = (unsigned int)EVP_MD_size(md);
    unsigned char *result = (unsigned char *)malloc(digest_len);
    if (result == NULL) {
        return NULL;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        free(result);
        return NULL;
    }

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, data_len) != 1 ||
        EVP_DigestFinal_ex(ctx, result, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        free(result);
        return NULL;
    }

    EVP_MD_CTX_free(ctx);
    *out_len = digest_len;
    return result;
}

/* ============================================================================
 * Hashing (byte[] input)
 * ============================================================================ */

SnArray *sn_crypto_sha256(SnArray *data)
{
    size_t len = data ? (size_t)sn_array_length(data) : 0;
    unsigned char *raw = data ? (unsigned char *)data->data : NULL;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal(raw, len, EVP_sha256(), &digest_len);
    if (buf == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }
    SnArray *result = sn_crypto_make_byte_array(buf, digest_len);
    free(buf);
    return result;
}

SnArray *sn_crypto_sha384(SnArray *data)
{
    size_t len = data ? (size_t)sn_array_length(data) : 0;
    unsigned char *raw = data ? (unsigned char *)data->data : NULL;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal(raw, len, EVP_sha384(), &digest_len);
    if (buf == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }
    SnArray *result = sn_crypto_make_byte_array(buf, digest_len);
    free(buf);
    return result;
}

SnArray *sn_crypto_sha512(SnArray *data)
{
    size_t len = data ? (size_t)sn_array_length(data) : 0;
    unsigned char *raw = data ? (unsigned char *)data->data : NULL;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal(raw, len, EVP_sha512(), &digest_len);
    if (buf == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }
    SnArray *result = sn_crypto_make_byte_array(buf, digest_len);
    free(buf);
    return result;
}

SnArray *sn_crypto_sha1(SnArray *data)
{
    size_t len = data ? (size_t)sn_array_length(data) : 0;
    unsigned char *raw = data ? (unsigned char *)data->data : NULL;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal(raw, len, EVP_sha1(), &digest_len);
    if (buf == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }
    SnArray *result = sn_crypto_make_byte_array(buf, digest_len);
    free(buf);
    return result;
}

SnArray *sn_crypto_md5(SnArray *data)
{
    size_t len = data ? (size_t)sn_array_length(data) : 0;
    unsigned char *raw = data ? (unsigned char *)data->data : NULL;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal(raw, len, EVP_md5(), &digest_len);
    if (buf == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }
    SnArray *result = sn_crypto_make_byte_array(buf, digest_len);
    free(buf);
    return result;
}

/* ============================================================================
 * Hashing (str input)
 * ============================================================================ */

SnArray *sn_crypto_sha256_str(char *text)
{
    size_t len = text ? strlen(text) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal((const unsigned char *)text, len, EVP_sha256(), &digest_len);
    if (buf == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }
    SnArray *result = sn_crypto_make_byte_array(buf, digest_len);
    free(buf);
    return result;
}

SnArray *sn_crypto_sha384_str(char *text)
{
    size_t len = text ? strlen(text) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal((const unsigned char *)text, len, EVP_sha384(), &digest_len);
    if (buf == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }
    SnArray *result = sn_crypto_make_byte_array(buf, digest_len);
    free(buf);
    return result;
}

SnArray *sn_crypto_sha512_str(char *text)
{
    size_t len = text ? strlen(text) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal((const unsigned char *)text, len, EVP_sha512(), &digest_len);
    if (buf == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }
    SnArray *result = sn_crypto_make_byte_array(buf, digest_len);
    free(buf);
    return result;
}

SnArray *sn_crypto_sha1_str(char *text)
{
    size_t len = text ? strlen(text) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal((const unsigned char *)text, len, EVP_sha1(), &digest_len);
    if (buf == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }
    SnArray *result = sn_crypto_make_byte_array(buf, digest_len);
    free(buf);
    return result;
}

SnArray *sn_crypto_md5_str(char *text)
{
    size_t len = text ? strlen(text) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal((const unsigned char *)text, len, EVP_md5(), &digest_len);
    if (buf == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }
    SnArray *result = sn_crypto_make_byte_array(buf, digest_len);
    free(buf);
    return result;
}

/* ============================================================================
 * HMAC
 * ============================================================================ */

SnArray *sn_crypto_hmac_sha256(SnArray *key, SnArray *data)
{
    size_t key_len = key ? (size_t)sn_array_length(key) : 0;
    unsigned char *key_raw = key ? (unsigned char *)key->data : NULL;
    size_t data_len = data ? (size_t)sn_array_length(data) : 0;
    unsigned char *data_raw = data ? (unsigned char *)data->data : NULL;

    unsigned int result_len = (unsigned int)EVP_MD_size(EVP_sha256());
    unsigned char *buf = (unsigned char *)malloc(result_len);
    if (buf == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    unsigned char *ret = HMAC(EVP_sha256(),
                              key_raw, (int)key_len,
                              data_raw, data_len,
                              buf, &result_len);

    if (ret == NULL) {
        free(buf);
        return sn_crypto_make_byte_array(NULL, 0);
    }

    SnArray *result = sn_crypto_make_byte_array(buf, result_len);
    free(buf);
    return result;
}

SnArray *sn_crypto_hmac_sha512(SnArray *key, SnArray *data)
{
    size_t key_len = key ? (size_t)sn_array_length(key) : 0;
    unsigned char *key_raw = key ? (unsigned char *)key->data : NULL;
    size_t data_len = data ? (size_t)sn_array_length(data) : 0;
    unsigned char *data_raw = data ? (unsigned char *)data->data : NULL;

    unsigned int result_len = (unsigned int)EVP_MD_size(EVP_sha512());
    unsigned char *buf = (unsigned char *)malloc(result_len);
    if (buf == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    unsigned char *ret = HMAC(EVP_sha512(),
                              key_raw, (int)key_len,
                              data_raw, data_len,
                              buf, &result_len);

    if (ret == NULL) {
        free(buf);
        return sn_crypto_make_byte_array(NULL, 0);
    }

    SnArray *result = sn_crypto_make_byte_array(buf, result_len);
    free(buf);
    return result;
}

/* ============================================================================
 * AES-256-GCM Encryption
 * ============================================================================ */

#define AES_GCM_IV_LEN  12
#define AES_GCM_TAG_LEN 16
#define AES_256_KEY_LEN 32

SnArray *sn_crypto_encrypt(SnArray *key, SnArray *plaintext)
{
    if (key == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    size_t key_len = (size_t)sn_array_length(key);
    unsigned char *key_raw = (unsigned char *)key->data;
    if (key_len != AES_256_KEY_LEN) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    size_t pt_len = plaintext ? (size_t)sn_array_length(plaintext) : 0;
    unsigned char *pt_raw = plaintext ? (unsigned char *)plaintext->data : NULL;

    /* Output: [IV(12)][ciphertext][tag(16)] */
    size_t out_len = AES_GCM_IV_LEN + pt_len + AES_GCM_TAG_LEN;
    unsigned char *output = (unsigned char *)malloc(out_len);
    if (output == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    /* Generate random IV */
    if (RAND_bytes(output, AES_GCM_IV_LEN) != 1) {
        free(output);
        return sn_crypto_make_byte_array(NULL, 0);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(output);
        return sn_crypto_make_byte_array(NULL, 0);
    }

    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto encrypt_fail;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1) {
        goto encrypt_fail;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key_raw, output) != 1) {
        goto encrypt_fail;
    }

    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, output + AES_GCM_IV_LEN, &len, pt_raw, (int)pt_len) != 1) {
            goto encrypt_fail;
        }
        ciphertext_len = len;
    }

    if (EVP_EncryptFinal_ex(ctx, output + AES_GCM_IV_LEN + ciphertext_len, &len) != 1) {
        goto encrypt_fail;
    }
    ciphertext_len += len;

    /* Get the tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN,
                             output + AES_GCM_IV_LEN + ciphertext_len) != 1) {
        goto encrypt_fail;
    }

    EVP_CIPHER_CTX_free(ctx);
    {
        SnArray *result = sn_crypto_make_byte_array(output, out_len);
        free(output);
        return result;
    }

encrypt_fail:
    EVP_CIPHER_CTX_free(ctx);
    free(output);
    return sn_crypto_make_byte_array(NULL, 0);
}

SnArray *sn_crypto_decrypt(SnArray *key, SnArray *ciphertext)
{
    if (key == NULL || ciphertext == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    size_t key_len = (size_t)sn_array_length(key);
    unsigned char *key_raw = (unsigned char *)key->data;
    if (key_len != AES_256_KEY_LEN) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    size_t ct_total_len = (size_t)sn_array_length(ciphertext);
    unsigned char *ct_raw = (unsigned char *)ciphertext->data;
    if (ct_total_len < AES_GCM_IV_LEN + AES_GCM_TAG_LEN) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    /* Input layout: [IV(12)][ciphertext][tag(16)] */
    unsigned char *iv = ct_raw;
    size_t ct_len = ct_total_len - AES_GCM_IV_LEN - AES_GCM_TAG_LEN;
    unsigned char *ct_data = ct_raw + AES_GCM_IV_LEN;
    unsigned char *tag = ct_raw + AES_GCM_IV_LEN + ct_len;

    unsigned char *plaintext = (unsigned char *)malloc(ct_len > 0 ? ct_len : 1);
    if (plaintext == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(plaintext);
        return sn_crypto_make_byte_array(NULL, 0);
    }

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto decrypt_fail;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1) {
        goto decrypt_fail;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key_raw, iv) != 1) {
        goto decrypt_fail;
    }

    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ct_data, (int)ct_len) != 1) {
            goto decrypt_fail;
        }
        plaintext_len = len;
    }

    /* Set expected tag before final */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, (void *)tag) != 1) {
        goto decrypt_fail;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len) != 1) {
        goto decrypt_fail;
    }

    EVP_CIPHER_CTX_free(ctx);
    {
        SnArray *result = sn_crypto_make_byte_array(plaintext, ct_len);
        free(plaintext);
        return result;
    }

decrypt_fail:
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return sn_crypto_make_byte_array(NULL, 0);
}

SnArray *sn_crypto_encrypt_with_iv(SnArray *key, SnArray *iv, SnArray *plaintext)
{
    if (key == NULL || iv == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    size_t key_len = (size_t)sn_array_length(key);
    unsigned char *key_raw = (unsigned char *)key->data;
    if (key_len != AES_256_KEY_LEN) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    size_t iv_len = (size_t)sn_array_length(iv);
    unsigned char *iv_raw = (unsigned char *)iv->data;
    if (iv_len != AES_GCM_IV_LEN) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    size_t pt_len = plaintext ? (size_t)sn_array_length(plaintext) : 0;
    unsigned char *pt_raw = plaintext ? (unsigned char *)plaintext->data : NULL;

    /* Output: [ciphertext][tag(16)] */
    size_t out_len = pt_len + AES_GCM_TAG_LEN;
    unsigned char *output = (unsigned char *)malloc(out_len > 0 ? out_len : 1);
    if (output == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(output);
        return sn_crypto_make_byte_array(NULL, 0);
    }

    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto encrypt_iv_fail;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1) {
        goto encrypt_iv_fail;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key_raw, iv_raw) != 1) {
        goto encrypt_iv_fail;
    }

    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, output, &len, pt_raw, (int)pt_len) != 1) {
            goto encrypt_iv_fail;
        }
        ciphertext_len = len;
    }

    if (EVP_EncryptFinal_ex(ctx, output + ciphertext_len, &len) != 1) {
        goto encrypt_iv_fail;
    }
    ciphertext_len += len;

    /* Get the tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN,
                             output + ciphertext_len) != 1) {
        goto encrypt_iv_fail;
    }

    EVP_CIPHER_CTX_free(ctx);
    {
        SnArray *result = sn_crypto_make_byte_array(output, out_len);
        free(output);
        return result;
    }

encrypt_iv_fail:
    EVP_CIPHER_CTX_free(ctx);
    free(output);
    return sn_crypto_make_byte_array(NULL, 0);
}

SnArray *sn_crypto_decrypt_with_iv(SnArray *key, SnArray *iv, SnArray *ciphertext)
{
    if (key == NULL || iv == NULL || ciphertext == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    size_t key_len = (size_t)sn_array_length(key);
    unsigned char *key_raw = (unsigned char *)key->data;
    if (key_len != AES_256_KEY_LEN) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    size_t iv_len = (size_t)sn_array_length(iv);
    unsigned char *iv_raw = (unsigned char *)iv->data;
    if (iv_len != AES_GCM_IV_LEN) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    size_t ct_total_len = (size_t)sn_array_length(ciphertext);
    unsigned char *ct_raw = (unsigned char *)ciphertext->data;
    if (ct_total_len < AES_GCM_TAG_LEN) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    /* Input layout: [ciphertext][tag(16)] */
    size_t ct_len = ct_total_len - AES_GCM_TAG_LEN;
    unsigned char *tag = ct_raw + ct_len;

    unsigned char *plaintext = (unsigned char *)malloc(ct_len > 0 ? ct_len : 1);
    if (plaintext == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(plaintext);
        return sn_crypto_make_byte_array(NULL, 0);
    }

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto decrypt_iv_fail;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1) {
        goto decrypt_iv_fail;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key_raw, iv_raw) != 1) {
        goto decrypt_iv_fail;
    }

    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ct_raw, (int)ct_len) != 1) {
            goto decrypt_iv_fail;
        }
        plaintext_len = len;
    }

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, (void *)tag) != 1) {
        goto decrypt_iv_fail;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len) != 1) {
        goto decrypt_iv_fail;
    }

    EVP_CIPHER_CTX_free(ctx);
    {
        SnArray *result = sn_crypto_make_byte_array(plaintext, ct_len);
        free(plaintext);
        return result;
    }

decrypt_iv_fail:
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return sn_crypto_make_byte_array(NULL, 0);
}

/* ============================================================================
 * Key Derivation (PBKDF2)
 * ============================================================================ */

SnArray *sn_crypto_pbkdf2(char *password, SnArray *salt,
                          long long iterations, long long key_len)
{
    if (password == NULL || key_len <= 0 || iterations <= 0) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    size_t salt_len = salt ? (size_t)sn_array_length(salt) : 0;
    unsigned char *salt_raw = salt ? (unsigned char *)salt->data : NULL;
    unsigned char *result = (unsigned char *)malloc((size_t)key_len);
    if (result == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                            salt_raw, (int)salt_len,
                            (int)iterations,
                            EVP_sha256(),
                            (int)key_len, result) != 1) {
        free(result);
        return sn_crypto_make_byte_array(NULL, 0);
    }

    SnArray *h = sn_crypto_make_byte_array(result, (size_t)key_len);
    free(result);
    return h;
}

SnArray *sn_crypto_pbkdf2_sha512(char *password, SnArray *salt,
                                 long long iterations, long long key_len)
{
    if (password == NULL || key_len <= 0 || iterations <= 0) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    size_t salt_len = salt ? (size_t)sn_array_length(salt) : 0;
    unsigned char *salt_raw = salt ? (unsigned char *)salt->data : NULL;
    unsigned char *result = (unsigned char *)malloc((size_t)key_len);
    if (result == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                            salt_raw, (int)salt_len,
                            (int)iterations,
                            EVP_sha512(),
                            (int)key_len, result) != 1) {
        free(result);
        return sn_crypto_make_byte_array(NULL, 0);
    }

    SnArray *h = sn_crypto_make_byte_array(result, (size_t)key_len);
    free(result);
    return h;
}

/* ============================================================================
 * Secure Random
 * ============================================================================ */

SnArray *sn_crypto_random_bytes(long long count)
{
    if (count <= 0) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    unsigned char *result = (unsigned char *)malloc((size_t)count);
    if (result == NULL) {
        return sn_crypto_make_byte_array(NULL, 0);
    }

    if (RAND_bytes(result, (int)count) != 1) {
        free(result);
        return sn_crypto_make_byte_array(NULL, 0);
    }

    SnArray *h = sn_crypto_make_byte_array(result, (size_t)count);
    free(result);
    return h;
}

/* ============================================================================
 * Utility
 * ============================================================================ */

long long sn_crypto_constant_time_equal(SnArray *a, SnArray *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }

    size_t a_len = (size_t)sn_array_length(a);
    size_t b_len = (size_t)sn_array_length(b);

    if (a_len != b_len) {
        return 0;
    }

    return CRYPTO_memcmp(a->data, b->data, a_len) == 0 ? 1 : 0;
}
