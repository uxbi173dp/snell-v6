/*
 * snell_crypto.h — Snell v6 (b2) AEAD + KDF + record framing.
 *
 * Self-contained (libsodium + OpenSSL). NO dependency on src/server.
 * Every protocol parameter that we are still reverse-engineering is a
 * field of snell_params_t, so the production client and the probe share
 * ONE implementation and we only flip constants once the binary RE
 * pins the real values down.
 */
#ifndef SNELL_CRYPTO_H
#define SNELL_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SN_TAG_LEN 16
#define SN_MAX_PAYLOAD 0x3FFF   /* shadowsocks AEAD max chunk */

typedef enum { SN_KDF_ARGON2ID, SN_KDF_SS_HKDF_SHA1 } sn_kdf_t;
typedef enum { SN_CIPHER_CHACHA20, SN_CIPHER_AES256GCM, SN_CIPHER_AES128GCM } sn_cipher_t;
typedef enum { SN_FRAME_ENC_LEN, SN_FRAME_PLAIN_LEN } sn_frame_t;

/* The full set of currently-uncertain protocol parameters. */
typedef struct {
    sn_kdf_t    kdf;
    sn_cipher_t cipher;
    sn_frame_t  frame;
    int         salt_len;      /* bytes on the wire before the first record */
    int         key_len;       /* AEAD key length                           */
    unsigned long long argon_ops;
    size_t      argon_mem;     /* bytes (libsodium crypto_pwhash memlimit)   */
    uint8_t     version;       /* request header version byte                */
    uint8_t     command;       /* request header command byte (connect)      */
} sn_params_t;

/* A directional AEAD stream: key + monotonic record counter. */
typedef struct {
    const sn_params_t *p;
    uint8_t  key[32];
    uint64_t counter;
} sn_stream_t;

const char *sn_kdf_name(sn_kdf_t);
const char *sn_cipher_name(sn_cipher_t);
const char *sn_frame_name(sn_frame_t);

/* Derive the session key from psk + salt into key[p->key_len]. 0 on success. */
int sn_derive_key(const sn_params_t *p, const char *psk,
                  const uint8_t *salt, int salt_len, uint8_t *key);

/* Initialise a stream from an already-derived key. */
void sn_stream_init(sn_stream_t *st, const sn_params_t *p, const uint8_t *key);

/* Encrypt one logical payload into a wire record. Returns bytes written
 * to out (which must hold payload_len + framing overhead). */
size_t sn_seal_record(sn_stream_t *st, const uint8_t *payload, size_t payload_len,
                      uint8_t *out);

/* Try to open ONE record from the front of buf[0..buf_len).
 * On success: writes plaintext to out, *out_len, sets *consumed to the wire
 * bytes used, advances the stream counter, returns 1.
 * Returns 0 if more bytes are needed (no counter advance).
 * Returns -1 on authentication failure (caller should treat as fatal). */
int sn_open_record(sn_stream_t *st, const uint8_t *buf, size_t buf_len,
                   uint8_t *out, size_t *out_len, size_t *consumed);

/* Max wire overhead a single sealed record adds over its payload. */
size_t sn_frame_overhead(const sn_params_t *p);

/* ---- Low-level single AEAD blob with optional AAD (for shaped framing) ---- */
/* Seal: out (= plain_len + 16) gets [ciphertext || tag]. counter = nonce counter. */
int sn_aead_seal(const sn_params_t *p, const uint8_t *key, uint64_t counter,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *plain, size_t plain_len, uint8_t *out);
/* Open: in (= ct||tag, in_len bytes) → out, *out_len. Returns 0 on success. */
int sn_aead_open(const sn_params_t *p, const uint8_t *key, uint64_t counter,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

/* Reusable-context variants for the per-chunk hot path (AES-GCM): the EVP cipher
 * context is created on first use and cached at *ctx (opaque void*, init to NULL),
 * so the AES key schedule is built ONCE per direction; later calls reset only the
 * 12-byte nonce. Output is byte-identical to sn_aead_seal/open. (ChaCha20 has no
 * persistent state and transparently falls back to the one-shot path.) Free the
 * cached context with sn_aead_ctx_free when the stream ends. */
int sn_aead_seal_r(const sn_params_t *p, void **ctx, const uint8_t *key, uint64_t counter,
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *plain, size_t plain_len, uint8_t *out);
int sn_aead_open_r(const sn_params_t *p, void **ctx, const uint8_t *key, uint64_t counter,
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
void sn_aead_ctx_free(void *ctx);

/* AES-GCM only: decrypt plaintext WITHOUT verifying the tag (diagnostic — the
 * GCM plaintext doesn't depend on the AAD, only the tag does). */
int sn_aead_open_noverify(const sn_params_t *p, const uint8_t *key, uint64_t counter,
                          const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif
#endif
