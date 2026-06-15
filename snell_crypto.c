/*
 * snell_crypto.c — see snell_crypto.h.
 *
 * Argon2id via libsodium (crypto_pwhash); AES-128-GCM via OpenSSL EVP. The AEAD
 * keeps the EVP context per direction so the AES key schedule is built once and
 * only the nonce changes per record.
 */
#include "snell_crypto.h"

#include <sodium.h>
#include <openssl/evp.h>

#include <string.h>
#include <stdio.h>

/* Argon2id cost parameters, fixed by Snell v6 b2. */
#define SN_ARGON2ID_OPS  3ULL           /* time cost (passes)            */
#define SN_ARGON2ID_MEM  (8u * 1024u)   /* memory cost in bytes (8 KiB)  */
#define SN_GCM_IV_LEN    12             /* AES-GCM nonce length          */

/* 12-byte GCM nonce = little-endian record counter, high 4 bytes zero. */
static void make_nonce(uint64_t counter, uint8_t nonce[SN_GCM_IV_LEN]) {
    for (int i = 0; i < 8; i++) nonce[i] = (uint8_t)(counter >> (i * 8));
    nonce[8] = nonce[9] = nonce[10] = nonce[11] = 0;
}

int sn_derive_key(const char *psk, const uint8_t salt[SN_SALT_LEN], uint8_t key[SN_KEY_LEN]) {
    /* crypto_pwhash wants exactly crypto_pwhash_SALTBYTES (16) = SN_SALT_LEN. */
    if (crypto_pwhash(key, SN_KEY_LEN, psk, strlen(psk), salt,
                      SN_ARGON2ID_OPS, SN_ARGON2ID_MEM,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        fprintf(stderr, "[crypto] crypto_pwhash failed (mem too low / oom?)\n");
        return -1;
    }
    return 0;
}

/* Lazily build the per-direction GCM context (binds the cipher + key once). */
static EVP_CIPHER_CTX *gcm_ctx(void **ctxp, const uint8_t *key, int encrypt) {
    EVP_CIPHER_CTX *c = (EVP_CIPHER_CTX *)*ctxp;
    if (c) return c;
    c = EVP_CIPHER_CTX_new();
    if (!c) return NULL;
    int ok = encrypt
        ? (EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
           EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, SN_GCM_IV_LEN, NULL) == 1 &&
           EVP_EncryptInit_ex(c, NULL, NULL, key, NULL) == 1)
        : (EVP_DecryptInit_ex(c, EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
           EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, SN_GCM_IV_LEN, NULL) == 1 &&
           EVP_DecryptInit_ex(c, NULL, NULL, key, NULL) == 1);
    if (!ok) { EVP_CIPHER_CTX_free(c); return NULL; }
    *ctxp = c;
    return c;
}

int sn_aead_seal(void **ctxp, const uint8_t *key, uint64_t counter,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *plain, size_t plain_len, uint8_t *out) {
    EVP_CIPHER_CTX *c = gcm_ctx(ctxp, key, 1);
    if (!c) return -1;
    uint8_t nonce[SN_GCM_IV_LEN]; make_nonce(counter, nonce);
    int l = 0, tot = 0;
    if (EVP_EncryptInit_ex(c, NULL, NULL, NULL, nonce) != 1) return -1;          /* new message: IV only */
    if (aad_len && EVP_EncryptUpdate(c, NULL, &l, aad, aad_len) != 1) return -1;
    if (EVP_EncryptUpdate(c, out, &l, plain, plain_len) != 1) return -1; tot = l;
    if (EVP_EncryptFinal_ex(c, out + tot, &l) != 1) return -1; tot += l;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, SN_TAG_LEN, out + tot) != 1) return -1;
    return 0;
}

int sn_aead_open(void **ctxp, const uint8_t *key, uint64_t counter,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    if (in_len < SN_TAG_LEN) return -1;
    EVP_CIPHER_CTX *c = gcm_ctx(ctxp, key, 0);
    if (!c) return -1;
    uint8_t nonce[SN_GCM_IV_LEN]; make_nonce(counter, nonce);
    size_t body = in_len - SN_TAG_LEN;
    int l = 0, tot = 0;
    if (EVP_DecryptInit_ex(c, NULL, NULL, NULL, nonce) != 1) return -1;
    if (aad_len && EVP_DecryptUpdate(c, NULL, &l, aad, aad_len) != 1) return -1;
    if (EVP_DecryptUpdate(c, out, &l, in, body) != 1) return -1; tot = l;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, SN_TAG_LEN, (void *)(in + body)) != 1) return -1;
    if (EVP_DecryptFinal_ex(c, out + tot, &l) != 1) return -1; tot += l;         /* verifies the tag */
    *out_len = tot;
    return 0;
}

void sn_aead_ctx_free(void *ctx) {
    if (ctx) EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)ctx);
}
