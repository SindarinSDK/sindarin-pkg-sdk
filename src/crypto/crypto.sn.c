/* ==============================================================================
 * sdk/crypto.sn.c - Self-contained Crypto Implementation for Sindarin SDK
 * ==============================================================================
 * Provides cryptographic operations using OpenSSL's libcrypto (EVP API).
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "runtime/runtime_arena.h"
#include "runtime/runtime_array.h"
#include "runtime/arena/managed_arena.h"
#include "runtime/runtime_array_h.h"

/* ============================================================================
 * RtCrypto Type Definition (Static-only, never instantiated)
 * ============================================================================ */

typedef struct RtCrypto {
    int _unused;
} RtCrypto;

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

RtHandle sn_crypto_sha256(RtManagedArena *arena, unsigned char *data)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }
    size_t len = data ? rt_array_length(data) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal(data, len, EVP_sha256(), &digest_len);
    if (buf == NULL) {
        return RT_HANDLE_NULL;
    }
    RtHandle result = rt_array_create_byte_h(arena, digest_len, buf);
    free(buf);
    return result;
}

RtHandle sn_crypto_sha384(RtManagedArena *arena, unsigned char *data)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }
    size_t len = data ? rt_array_length(data) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal(data, len, EVP_sha384(), &digest_len);
    if (buf == NULL) {
        return RT_HANDLE_NULL;
    }
    RtHandle result = rt_array_create_byte_h(arena, digest_len, buf);
    free(buf);
    return result;
}

RtHandle sn_crypto_sha512(RtManagedArena *arena, unsigned char *data)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }
    size_t len = data ? rt_array_length(data) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal(data, len, EVP_sha512(), &digest_len);
    if (buf == NULL) {
        return RT_HANDLE_NULL;
    }
    RtHandle result = rt_array_create_byte_h(arena, digest_len, buf);
    free(buf);
    return result;
}

RtHandle sn_crypto_sha1(RtManagedArena *arena, unsigned char *data)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }
    size_t len = data ? rt_array_length(data) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal(data, len, EVP_sha1(), &digest_len);
    if (buf == NULL) {
        return RT_HANDLE_NULL;
    }
    RtHandle result = rt_array_create_byte_h(arena, digest_len, buf);
    free(buf);
    return result;
}

RtHandle sn_crypto_md5(RtManagedArena *arena, unsigned char *data)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }
    size_t len = data ? rt_array_length(data) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal(data, len, EVP_md5(), &digest_len);
    if (buf == NULL) {
        return RT_HANDLE_NULL;
    }
    RtHandle result = rt_array_create_byte_h(arena, digest_len, buf);
    free(buf);
    return result;
}

/* ============================================================================
 * Hashing (str input)
 * ============================================================================ */

RtHandle sn_crypto_sha256_str(RtManagedArena *arena, const char *text)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }
    size_t len = text ? strlen(text) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal((const unsigned char *)text, len, EVP_sha256(), &digest_len);
    if (buf == NULL) {
        return RT_HANDLE_NULL;
    }
    RtHandle result = rt_array_create_byte_h(arena, digest_len, buf);
    free(buf);
    return result;
}

RtHandle sn_crypto_sha384_str(RtManagedArena *arena, const char *text)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }
    size_t len = text ? strlen(text) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal((const unsigned char *)text, len, EVP_sha384(), &digest_len);
    if (buf == NULL) {
        return RT_HANDLE_NULL;
    }
    RtHandle result = rt_array_create_byte_h(arena, digest_len, buf);
    free(buf);
    return result;
}

RtHandle sn_crypto_sha512_str(RtManagedArena *arena, const char *text)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }
    size_t len = text ? strlen(text) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal((const unsigned char *)text, len, EVP_sha512(), &digest_len);
    if (buf == NULL) {
        return RT_HANDLE_NULL;
    }
    RtHandle result = rt_array_create_byte_h(arena, digest_len, buf);
    free(buf);
    return result;
}

RtHandle sn_crypto_sha1_str(RtManagedArena *arena, const char *text)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }
    size_t len = text ? strlen(text) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal((const unsigned char *)text, len, EVP_sha1(), &digest_len);
    if (buf == NULL) {
        return RT_HANDLE_NULL;
    }
    RtHandle result = rt_array_create_byte_h(arena, digest_len, buf);
    free(buf);
    return result;
}

RtHandle sn_crypto_md5_str(RtManagedArena *arena, const char *text)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }
    size_t len = text ? strlen(text) : 0;
    unsigned int digest_len = 0;
    unsigned char *buf = sn_crypto_digest_internal((const unsigned char *)text, len, EVP_md5(), &digest_len);
    if (buf == NULL) {
        return RT_HANDLE_NULL;
    }
    RtHandle result = rt_array_create_byte_h(arena, digest_len, buf);
    free(buf);
    return result;
}

/* ============================================================================
 * HMAC
 * ============================================================================ */

RtHandle sn_crypto_hmac_sha256(RtManagedArena *arena, unsigned char *key,
                                unsigned char *data)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }

    size_t key_len = key ? rt_array_length(key) : 0;
    size_t data_len = data ? rt_array_length(data) : 0;

    unsigned int result_len = (unsigned int)EVP_MD_size(EVP_sha256());
    unsigned char *buf = (unsigned char *)malloc(result_len);
    if (buf == NULL) {
        return RT_HANDLE_NULL;
    }

    unsigned char *ret = HMAC(EVP_sha256(),
                              key, (int)key_len,
                              data, data_len,
                              buf, &result_len);

    if (ret == NULL) {
        free(buf);
        return RT_HANDLE_NULL;
    }

    RtHandle result = rt_array_create_byte_h(arena, result_len, buf);
    free(buf);
    return result;
}

RtHandle sn_crypto_hmac_sha512(RtManagedArena *arena, unsigned char *key,
                                unsigned char *data)
{
    if (arena == NULL) {
        return RT_HANDLE_NULL;
    }

    size_t key_len = key ? rt_array_length(key) : 0;
    size_t data_len = data ? rt_array_length(data) : 0;

    unsigned int result_len = (unsigned int)EVP_MD_size(EVP_sha512());
    unsigned char *buf = (unsigned char *)malloc(result_len);
    if (buf == NULL) {
        return RT_HANDLE_NULL;
    }

    unsigned char *ret = HMAC(EVP_sha512(),
                              key, (int)key_len,
                              data, data_len,
                              buf, &result_len);

    if (ret == NULL) {
        free(buf);
        return RT_HANDLE_NULL;
    }

    RtHandle result = rt_array_create_byte_h(arena, result_len, buf);
    free(buf);
    return result;
}

/* ============================================================================
 * AES-256-GCM Encryption
 * ============================================================================ */

#define AES_GCM_IV_LEN  12
#define AES_GCM_TAG_LEN 16
#define AES_256_KEY_LEN 32

RtHandle sn_crypto_encrypt(RtManagedArena *arena, unsigned char *key,
                            unsigned char *plaintext)
{
    if (arena == NULL || key == NULL) {
        return RT_HANDLE_NULL;
    }

    size_t key_len = rt_array_length(key);
    if (key_len != AES_256_KEY_LEN) {
        return RT_HANDLE_NULL;
    }

    size_t pt_len = plaintext ? rt_array_length(plaintext) : 0;

    /* Output: [IV(12)][ciphertext][tag(16)] */
    size_t out_len = AES_GCM_IV_LEN + pt_len + AES_GCM_TAG_LEN;
    unsigned char *output = (unsigned char *)malloc(out_len);
    if (output == NULL) {
        return RT_HANDLE_NULL;
    }

    /* Generate random IV */
    if (RAND_bytes(output, AES_GCM_IV_LEN) != 1) {
        free(output);
        return RT_HANDLE_NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(output);
        return RT_HANDLE_NULL;
    }

    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto encrypt_fail;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1) {
        goto encrypt_fail;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, output) != 1) {
        goto encrypt_fail;
    }

    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, output + AES_GCM_IV_LEN, &len, plaintext, (int)pt_len) != 1) {
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
        RtHandle result = rt_array_create_byte_h(arena, out_len, output);
        free(output);
        return result;
    }

encrypt_fail:
    EVP_CIPHER_CTX_free(ctx);
    free(output);
    return RT_HANDLE_NULL;
}

RtHandle sn_crypto_decrypt(RtManagedArena *arena, unsigned char *key,
                            unsigned char *ciphertext)
{
    if (arena == NULL || key == NULL || ciphertext == NULL) {
        return RT_HANDLE_NULL;
    }

    size_t key_len = rt_array_length(key);
    if (key_len != AES_256_KEY_LEN) {
        return RT_HANDLE_NULL;
    }

    size_t ct_total_len = rt_array_length(ciphertext);
    if (ct_total_len < AES_GCM_IV_LEN + AES_GCM_TAG_LEN) {
        return RT_HANDLE_NULL;
    }

    /* Input layout: [IV(12)][ciphertext][tag(16)] */
    unsigned char *iv = ciphertext;
    size_t ct_len = ct_total_len - AES_GCM_IV_LEN - AES_GCM_TAG_LEN;
    unsigned char *ct_data = ciphertext + AES_GCM_IV_LEN;
    unsigned char *tag = ciphertext + AES_GCM_IV_LEN + ct_len;

    unsigned char *plaintext = (unsigned char *)malloc(ct_len > 0 ? ct_len : 1);
    if (plaintext == NULL) {
        return RT_HANDLE_NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(plaintext);
        return RT_HANDLE_NULL;
    }

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto decrypt_fail;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1) {
        goto decrypt_fail;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
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
        RtHandle result = rt_array_create_byte_h(arena, ct_len, plaintext);
        free(plaintext);
        return result;
    }

decrypt_fail:
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return RT_HANDLE_NULL;
}

RtHandle sn_crypto_encrypt_with_iv(RtManagedArena *arena, unsigned char *key,
                                    unsigned char *iv, unsigned char *plaintext)
{
    if (arena == NULL || key == NULL || iv == NULL) {
        return RT_HANDLE_NULL;
    }

    size_t key_len = rt_array_length(key);
    if (key_len != AES_256_KEY_LEN) {
        return RT_HANDLE_NULL;
    }

    size_t iv_len = rt_array_length(iv);
    if (iv_len != AES_GCM_IV_LEN) {
        return RT_HANDLE_NULL;
    }

    size_t pt_len = plaintext ? rt_array_length(plaintext) : 0;

    /* Output: [ciphertext][tag(16)] */
    size_t out_len = pt_len + AES_GCM_TAG_LEN;
    unsigned char *output = (unsigned char *)malloc(out_len > 0 ? out_len : 1);
    if (output == NULL) {
        return RT_HANDLE_NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(output);
        return RT_HANDLE_NULL;
    }

    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto encrypt_iv_fail;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1) {
        goto encrypt_iv_fail;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        goto encrypt_iv_fail;
    }

    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, output, &len, plaintext, (int)pt_len) != 1) {
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
        RtHandle result = rt_array_create_byte_h(arena, out_len, output);
        free(output);
        return result;
    }

encrypt_iv_fail:
    EVP_CIPHER_CTX_free(ctx);
    free(output);
    return RT_HANDLE_NULL;
}

RtHandle sn_crypto_decrypt_with_iv(RtManagedArena *arena, unsigned char *key,
                                    unsigned char *iv, unsigned char *ciphertext)
{
    if (arena == NULL || key == NULL || iv == NULL || ciphertext == NULL) {
        return RT_HANDLE_NULL;
    }

    size_t key_len = rt_array_length(key);
    if (key_len != AES_256_KEY_LEN) {
        return RT_HANDLE_NULL;
    }

    size_t iv_len = rt_array_length(iv);
    if (iv_len != AES_GCM_IV_LEN) {
        return RT_HANDLE_NULL;
    }

    size_t ct_total_len = rt_array_length(ciphertext);
    if (ct_total_len < AES_GCM_TAG_LEN) {
        return RT_HANDLE_NULL;
    }

    /* Input layout: [ciphertext][tag(16)] */
    size_t ct_len = ct_total_len - AES_GCM_TAG_LEN;
    unsigned char *tag = ciphertext + ct_len;

    unsigned char *plaintext = (unsigned char *)malloc(ct_len > 0 ? ct_len : 1);
    if (plaintext == NULL) {
        return RT_HANDLE_NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(plaintext);
        return RT_HANDLE_NULL;
    }

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto decrypt_iv_fail;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1) {
        goto decrypt_iv_fail;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        goto decrypt_iv_fail;
    }

    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ct_len) != 1) {
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
        RtHandle result = rt_array_create_byte_h(arena, ct_len, plaintext);
        free(plaintext);
        return result;
    }

decrypt_iv_fail:
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return RT_HANDLE_NULL;
}

/* ============================================================================
 * Key Derivation (PBKDF2)
 * ============================================================================ */

RtHandle sn_crypto_pbkdf2(RtManagedArena *arena, const char *password,
                           unsigned char *salt, long iterations, long key_len)
{
    if (arena == NULL || password == NULL || key_len <= 0 || iterations <= 0) {
        return RT_HANDLE_NULL;
    }

    size_t salt_len = salt ? rt_array_length(salt) : 0;
    unsigned char *result = (unsigned char *)malloc((size_t)key_len);
    if (result == NULL) {
        return RT_HANDLE_NULL;
    }

    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                            salt, (int)salt_len,
                            (int)iterations,
                            EVP_sha256(),
                            (int)key_len, result) != 1) {
        free(result);
        return RT_HANDLE_NULL;
    }

    RtHandle h = rt_array_create_byte_h(arena, (size_t)key_len, result);
    free(result);
    return h;
}

RtHandle sn_crypto_pbkdf2_sha512(RtManagedArena *arena, const char *password,
                                  unsigned char *salt, long iterations, long key_len)
{
    if (arena == NULL || password == NULL || key_len <= 0 || iterations <= 0) {
        return RT_HANDLE_NULL;
    }

    size_t salt_len = salt ? rt_array_length(salt) : 0;
    unsigned char *result = (unsigned char *)malloc((size_t)key_len);
    if (result == NULL) {
        return RT_HANDLE_NULL;
    }

    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                            salt, (int)salt_len,
                            (int)iterations,
                            EVP_sha512(),
                            (int)key_len, result) != 1) {
        free(result);
        return RT_HANDLE_NULL;
    }

    RtHandle h = rt_array_create_byte_h(arena, (size_t)key_len, result);
    free(result);
    return h;
}

/* ============================================================================
 * Secure Random
 * ============================================================================ */

RtHandle sn_crypto_random_bytes(RtManagedArena *arena, long count)
{
    if (arena == NULL || count <= 0) {
        return RT_HANDLE_NULL;
    }

    unsigned char *result = (unsigned char *)malloc((size_t)count);
    if (result == NULL) {
        return RT_HANDLE_NULL;
    }

    if (RAND_bytes(result, (int)count) != 1) {
        free(result);
        return RT_HANDLE_NULL;
    }

    RtHandle h = rt_array_create_byte_h(arena, (size_t)count, result);
    free(result);
    return h;
}

/* ============================================================================
 * Utility
 * ============================================================================ */

long sn_crypto_constant_time_equal(unsigned char *a, unsigned char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }

    size_t a_len = rt_array_length(a);
    size_t b_len = rt_array_length(b);

    if (a_len != b_len) {
        return 0;
    }

    return CRYPTO_memcmp(a, b, a_len) == 0 ? 1 : 0;
}
