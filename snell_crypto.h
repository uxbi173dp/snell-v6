/*
 * snell_crypto.h — Snell v6 (b3) crypto: Argon2id key derivation + AES-128-GCM
 * AEAD.
 *
 * Thin wrappers over libsodium (Argon2id KDF) and OpenSSL (AES-GCM); no bespoke
 * crypto. The cipher (AES-128-GCM), KDF (Argon2id) and their parameters are
 * fixed by the protocol — there is nothing to negotiate.
 */
#ifndef SNELL_CRYPTO_H
#define SNELL_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SN_TAG_LEN  16   /* AES-GCM authentication tag length            */
#define SN_SALT_LEN 16   /* per-session random salt that feeds the KDF   */
#define SN_KEY_LEN  32   /* Argon2id output; AES-128-GCM uses the first 16 bytes */

/*
 * Derive a per-direction key from psk + the session salt (Argon2id). Writes
 * SN_KEY_LEN bytes into key. Returns 0 on success, -1 on failure.
 */
int sn_derive_key(const char *psk, const uint8_t salt[SN_SALT_LEN], uint8_t key[SN_KEY_LEN]);

/*
 * One AES-128-GCM record with optional AAD. A cached EVP context (pass a void*
 * initialised to NULL; reused across calls, freed with sn_aead_ctx_free) builds
 * the AES key schedule once per direction; later calls only reset the 12-byte
 * nonce, which is the little-endian `counter`.
 *
 *   seal: out receives [ciphertext || tag]  (plain_len + SN_TAG_LEN bytes)
 *   open: in is [ciphertext || tag] (in_len bytes); out receives the plaintext,
 *         *out_len its length. The tag is verified (open fails on mismatch).
 *
 * `out` may alias `in`/`plain` (AES-GCM is a CTR-mode stream, so in-place
 * seal/open is safe — the tunnel decrypts in place). Return 0 on success, -1 on
 * failure.
 */
int sn_aead_seal(void **ctx, const uint8_t *key, uint64_t counter,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *plain, size_t plain_len, uint8_t *out);
int sn_aead_open(void **ctx, const uint8_t *key, uint64_t counter,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
void sn_aead_ctx_free(void *ctx);

#ifdef __cplusplus
}
#endif
#endif
