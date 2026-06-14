/*
 * snell_crypto.c — see snell_crypto.h
 */
#include "snell_crypto.h"

#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/md5.h>

#include <string.h>
#include <stdio.h>

const char *sn_kdf_name(sn_kdf_t k){return k==SN_KDF_ARGON2ID?"argon2id":"ss-hkdf-sha1";}
const char *sn_cipher_name(sn_cipher_t c){return c==SN_CIPHER_CHACHA20?"chacha20-ietf-poly1305":c==SN_CIPHER_AES256GCM?"aes-256-gcm":"aes-128-gcm";}
const char *sn_frame_name(sn_frame_t f){return f==SN_FRAME_ENC_LEN?"enc-len(ss)":"plain-len";}

static void make_nonce(uint64_t counter, uint8_t nonce[12]) {
    for (int i = 0; i < 8; i++) nonce[i] = (uint8_t)(counter >> (i*8));
    nonce[8]=nonce[9]=nonce[10]=nonce[11]=0;
}

/* shadowsocks master key: MD5-chain (EVP_BytesToKey with no salt, 1 iter) */
static void ss_master_key(const char *psk, uint8_t *key, int key_len) {
    uint8_t md[16]; int have = 0; uint8_t buf[16 + 256];
    size_t pl = strlen(psk);
    while (have < key_len) {
        MD5_CTX c; MD5_Init(&c);
        size_t off = 0;
        if (have > 0) { memcpy(buf, md, 16); off = 16; }
        memcpy(buf + off, psk, pl);
        MD5_Update(&c, buf, off + pl);
        MD5_Final(md, &c);
        int take = (key_len - have < 16) ? key_len - have : 16;
        memcpy(key + have, md, take);
        have += take;
    }
}

int sn_derive_key(const sn_params_t *p, const char *psk,
                  const uint8_t *salt, int salt_len, uint8_t *key) {
    if (p->kdf == SN_KDF_ARGON2ID) {
        uint8_t s16[16];
        if (salt_len >= 16) memcpy(s16, salt, 16);
        else { memset(s16,0,16); memcpy(s16, salt, salt_len); }
        if (crypto_pwhash(key, p->key_len, psk, strlen(psk), s16,
                          p->argon_ops, p->argon_mem,
                          crypto_pwhash_ALG_ARGON2ID13) != 0) {
            fprintf(stderr, "[crypto] crypto_pwhash failed (mem too low / oom?)\n");
            return -1;
        }
        return 0;
    }
    /* shadowsocks: subkey = HKDF-SHA1(EVP_BytesToKey(psk), salt, "ss-subkey") */
    uint8_t master[32];
    ss_master_key(psk, master, p->key_len);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;
    int rc = -1;
    do {
        if (EVP_PKEY_derive_init(pctx) != 1) break;
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha1()) != 1) break;
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, master, p->key_len) != 1) break;
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) != 1) break;
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, (const uint8_t*)"ss-subkey", 9) != 1) break;
        size_t outlen = p->key_len;
        rc = (EVP_PKEY_derive(pctx, key, &outlen) == 1) ? 0 : -1;
    } while (0);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

void sn_stream_init(sn_stream_t *st, const sn_params_t *p, const uint8_t *key) {
    st->p = p; st->counter = 0;
    memcpy(st->key, key, p->key_len);
}

/* one AEAD blob with optional AAD: pt[ptlen] -> out[ptlen+16] */
static int aead_enc_aad(const sn_params_t *p, const uint8_t *key, uint64_t ctr,
                        const uint8_t *aad, size_t aadlen,
                        const uint8_t *pt, size_t ptlen, uint8_t *out) {
    uint8_t nonce[12]; make_nonce(ctr, nonce);
    if (p->cipher == SN_CIPHER_CHACHA20) {
        unsigned long long clen;
        return crypto_aead_chacha20poly1305_ietf_encrypt(
            out, &clen, pt, ptlen, aad, aadlen, NULL, nonce, key) == 0 ? 0 : -1;
    }
    const EVP_CIPHER *ev = p->cipher==SN_CIPHER_AES256GCM?EVP_aes_256_gcm():EVP_aes_128_gcm();
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); if(!c) return -1;
    int l=0,tot=0,ok=0;
    do {
        if (EVP_EncryptInit_ex(c, ev, NULL, NULL, NULL)!=1) break;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)!=1) break;
        if (EVP_EncryptInit_ex(c, NULL, NULL, key, nonce)!=1) break;
        if (aadlen) { if (EVP_EncryptUpdate(c, NULL, &l, aad, aadlen)!=1) break; }
        if (EVP_EncryptUpdate(c, out, &l, pt, ptlen)!=1) break; tot=l;
        if (EVP_EncryptFinal_ex(c, out+tot, &l)!=1) break; tot+=l;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, SN_TAG_LEN, out+tot)!=1) break;
        ok=1;
    } while(0);
    EVP_CIPHER_CTX_free(c);
    return ok?0:-1;
}
static int aead_enc(const sn_params_t *p, const uint8_t *key, uint64_t ctr,
                    const uint8_t *pt, size_t ptlen, uint8_t *out) {
    return aead_enc_aad(p, key, ctr, NULL, 0, pt, ptlen, out);
}

static int aead_dec_aad(const sn_params_t *p, const uint8_t *key, uint64_t ctr,
                        const uint8_t *aad, size_t aadlen,
                        const uint8_t *ct, size_t ctlen /*ct+tag*/,
                        uint8_t *out, size_t *outlen) {
    if (ctlen < SN_TAG_LEN) return -1;
    uint8_t nonce[12]; make_nonce(ctr, nonce);
    if (p->cipher == SN_CIPHER_CHACHA20) {
        unsigned long long pl;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
            out, &pl, NULL, ct, ctlen, aad, aadlen, nonce, key) != 0) return -1;
        *outlen = pl; return 0;
    }
    const EVP_CIPHER *ev = p->cipher==SN_CIPHER_AES256GCM?EVP_aes_256_gcm():EVP_aes_128_gcm();
    size_t bodylen = ctlen - SN_TAG_LEN;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); if(!c) return -1;
    int l=0,tot=0,ok=0;
    do {
        if (EVP_DecryptInit_ex(c, ev, NULL, NULL, NULL)!=1) break;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)!=1) break;
        if (EVP_DecryptInit_ex(c, NULL, NULL, key, nonce)!=1) break;
        if (aadlen) { if (EVP_DecryptUpdate(c, NULL, &l, aad, aadlen)!=1) break; }
        if (EVP_DecryptUpdate(c, out, &l, ct, bodylen)!=1) break; tot=l;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, SN_TAG_LEN, (void*)(ct+bodylen))!=1) break;
        if (EVP_DecryptFinal_ex(c, out+tot, &l)!=1) break; tot+=l;
        ok=1;
    } while(0);
    EVP_CIPHER_CTX_free(c);
    if(!ok) return -1; *outlen=tot; return 0;
}
static int aead_dec(const sn_params_t *p, const uint8_t *key, uint64_t ctr,
                    const uint8_t *ct, size_t ctlen, uint8_t *out, size_t *outlen) {
    return aead_dec_aad(p, key, ctr, NULL, 0, ct, ctlen, out, outlen);
}

int sn_aead_seal(const sn_params_t *p, const uint8_t *key, uint64_t counter,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *plain, size_t plain_len, uint8_t *out) {
    return aead_enc_aad(p, key, counter, aad, aad_len, plain, plain_len, out);
}
int sn_aead_open(const sn_params_t *p, const uint8_t *key, uint64_t counter,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    return aead_dec_aad(p, key, counter, aad, aad_len, in, in_len, out, out_len);
}

/* ---- reusable-context AES-GCM: key schedule built once, nonce reset per op ---- */
int sn_aead_seal_r(const sn_params_t *p, void **ctxp, const uint8_t *key, uint64_t counter,
                   const uint8_t *aad, size_t aadlen,
                   const uint8_t *pt, size_t ptlen, uint8_t *out) {
    if (p->cipher == SN_CIPHER_CHACHA20)        /* libsodium: no persistent ctx */
        return aead_enc_aad(p, key, counter, aad, aadlen, pt, ptlen, out);
    uint8_t nonce[12]; make_nonce(counter, nonce);
    EVP_CIPHER_CTX *c = (EVP_CIPHER_CTX*)*ctxp;
    if (!c) {   /* first use: bind cipher + key (the expensive AES key schedule) */
        const EVP_CIPHER *ev = p->cipher==SN_CIPHER_AES256GCM?EVP_aes_256_gcm():EVP_aes_128_gcm();
        c = EVP_CIPHER_CTX_new(); if (!c) return -1;
        if (EVP_EncryptInit_ex(c, ev, NULL, NULL, NULL)!=1 ||
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)!=1 ||
            EVP_EncryptInit_ex(c, NULL, NULL, key, NULL)!=1) { EVP_CIPHER_CTX_free(c); return -1; }
        *ctxp = c;
    }
    int l=0, tot=0;
    if (EVP_EncryptInit_ex(c, NULL, NULL, NULL, nonce)!=1) return -1;   /* new message: IV only */
    if (aadlen && EVP_EncryptUpdate(c, NULL, &l, aad, aadlen)!=1) return -1;
    if (EVP_EncryptUpdate(c, out, &l, pt, ptlen)!=1) return -1; tot=l;
    if (EVP_EncryptFinal_ex(c, out+tot, &l)!=1) return -1; tot+=l;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, SN_TAG_LEN, out+tot)!=1) return -1;
    return 0;
}
int sn_aead_open_r(const sn_params_t *p, void **ctxp, const uint8_t *key, uint64_t counter,
                   const uint8_t *aad, size_t aadlen,
                   const uint8_t *ct, size_t ctlen, uint8_t *out, size_t *outlen) {
    if (p->cipher == SN_CIPHER_CHACHA20)
        return aead_dec_aad(p, key, counter, aad, aadlen, ct, ctlen, out, outlen);
    if (ctlen < SN_TAG_LEN) return -1;
    uint8_t nonce[12]; make_nonce(counter, nonce);
    EVP_CIPHER_CTX *c = (EVP_CIPHER_CTX*)*ctxp;
    if (!c) {
        const EVP_CIPHER *ev = p->cipher==SN_CIPHER_AES256GCM?EVP_aes_256_gcm():EVP_aes_128_gcm();
        c = EVP_CIPHER_CTX_new(); if (!c) return -1;
        if (EVP_DecryptInit_ex(c, ev, NULL, NULL, NULL)!=1 ||
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)!=1 ||
            EVP_DecryptInit_ex(c, NULL, NULL, key, NULL)!=1) { EVP_CIPHER_CTX_free(c); return -1; }
        *ctxp = c;
    }
    size_t bodylen = ctlen - SN_TAG_LEN;
    int l=0, tot=0;
    if (EVP_DecryptInit_ex(c, NULL, NULL, NULL, nonce)!=1) return -1;
    if (aadlen && EVP_DecryptUpdate(c, NULL, &l, aad, aadlen)!=1) return -1;
    if (EVP_DecryptUpdate(c, out, &l, ct, bodylen)!=1) return -1; tot=l;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, SN_TAG_LEN, (void*)(ct+bodylen))!=1) return -1;
    if (EVP_DecryptFinal_ex(c, out+tot, &l)!=1) return -1; tot+=l;   /* tag verify */
    *outlen = tot; return 0;
}
void sn_aead_ctx_free(void *ctx){ if (ctx) EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)ctx); }

int sn_aead_open_noverify(const sn_params_t *p, const uint8_t *key, uint64_t counter,
                          const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    if (in_len < SN_TAG_LEN) return -1;
    uint8_t nonce[12]; make_nonce(counter, nonce);
    const EVP_CIPHER *ev = p->cipher==SN_CIPHER_AES256GCM?EVP_aes_256_gcm():EVP_aes_128_gcm();
    size_t bodylen = in_len - SN_TAG_LEN;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); if(!c) return -1;
    int l=0,tot=0,ok=0;
    do {
        if (EVP_DecryptInit_ex(c, ev, NULL, NULL, NULL)!=1) break;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)!=1) break;
        if (EVP_DecryptInit_ex(c, NULL, NULL, key, nonce)!=1) break;
        if (EVP_DecryptUpdate(c, out, &l, in, bodylen)!=1) break; tot=l;
        ok=1;   /* skip tag verification */
    } while(0);
    EVP_CIPHER_CTX_free(c);
    if(!ok) return -1; *out_len=tot; return 0;
}

size_t sn_frame_overhead(const sn_params_t *p) {
    return p->frame==SN_FRAME_ENC_LEN ? (2+SN_TAG_LEN+SN_TAG_LEN) : (2+SN_TAG_LEN);
}

size_t sn_seal_record(sn_stream_t *st, const uint8_t *pt, size_t ptlen, uint8_t *out) {
    const sn_params_t *p = st->p;
    size_t off = 0;
    if (p->frame == SN_FRAME_ENC_LEN) {
        uint8_t lenbuf[2] = { (uint8_t)(ptlen>>8), (uint8_t)(ptlen&0xff) };
        aead_enc(p, st->key, st->counter++, lenbuf, 2, out+off); off += 2 + SN_TAG_LEN;
        aead_enc(p, st->key, st->counter++, pt, ptlen, out+off); off += ptlen + SN_TAG_LEN;
    } else {
        out[off++] = (uint8_t)(ptlen>>8); out[off++] = (uint8_t)(ptlen&0xff);
        aead_enc(p, st->key, st->counter++, pt, ptlen, out+off); off += ptlen + SN_TAG_LEN;
    }
    return off;
}

int sn_open_record(sn_stream_t *st, const uint8_t *buf, size_t buf_len,
                   uint8_t *out, size_t *out_len, size_t *consumed) {
    const sn_params_t *p = st->p;
    if (p->frame == SN_FRAME_ENC_LEN) {
        if (buf_len < 2 + SN_TAG_LEN) return 0;
        uint8_t lb[2]; size_t ll;
        if (aead_dec(p, st->key, st->counter, buf, 2+SN_TAG_LEN, lb, &ll) != 0 || ll != 2)
            return -1;
        size_t rec = (lb[0]<<8)|lb[1];
        if (buf_len < 2+SN_TAG_LEN + rec+SN_TAG_LEN) return 0; /* need more */
        size_t pl;
        if (aead_dec(p, st->key, st->counter+1, buf+2+SN_TAG_LEN, rec+SN_TAG_LEN, out, &pl) != 0)
            return -1;
        st->counter += 2;
        *out_len = pl;
        *consumed = 2+SN_TAG_LEN + rec+SN_TAG_LEN;
        return 1;
    } else {
        if (buf_len < 2 + SN_TAG_LEN) return 0;
        size_t rec = (buf[0]<<8)|buf[1];
        if (buf_len < 2 + rec+SN_TAG_LEN) return 0;
        size_t pl;
        if (aead_dec(p, st->key, st->counter, buf+2, rec+SN_TAG_LEN, out, &pl) != 0)
            return -1;
        st->counter += 1;
        *out_len = pl;
        *consumed = 2 + rec+SN_TAG_LEN;
        return 1;
    }
}
