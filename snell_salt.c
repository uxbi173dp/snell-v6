/*
 * snell_salt.c — Snell v6 (b3) salt-block obfuscation.
 *
 * The 16-byte AEAD salt is not sent in the clear: it is scattered across the
 * first `block_len` wire bytes of a session, the rest being profile-shaped
 * filler. The receiver recovers it with
 *
 *     real_salt[i] = wire_block[ S[i] ] ^ PRF[i]            (i = 0..15)
 *
 * where the carrier length `block_len`, the 16 scatter indices `S[]` (the first
 * 16 entries of a keyed Fisher-Yates permutation) and the XOR keystream `PRF[]`
 * are all PSK-derived through the shared shaping PRNG (snell_prng.c). Everything
 * here is a deterministic function of the PSK, byte-exact against the reference
 * server.
 *
 * Reversed from:
 *   fcn.0x3aae0  block-length   = 0x10 + range_map(prng(0x21,seq0,0x7053), lo, hi)
 *   fcn.0x3ab70  Fisher-Yates permutation (first 16 entries -> S[])
 *   fcn.0x3ab10  KSA inner PRF
 *   fcn.0x38e50  keystream PRF  -> PRF[]
 *   fcn.0x39d90  init (block-length bounds, KSA round count, keystream multiplier)
 * The PRNG sub-state the salt path draws from is prng->s_ctxE8 (server ctx+0xe8).
 */
#include "snell_salt.h"
#include "snell_prng.h"
#include <stdint.h>
#include <string.h>

/*
 * Salt-path scalar parameters, derived once at init (server fcn.0x39d90). The
 * selector reads pass fixed seeds 0x7053 / 0x51a7 (the server's constants).
 */
typedef struct {
    const sn_prng_t *prng;
    uint16_t blk_lo, blk_hi;   /* block-length variable-part bounds (ctx+0xcc / +0x130) */
    uint8_t  ksa_rounds;       /* Fisher-Yates round count (ctx+0x112), in [1,4]        */
    uint8_t  multiplier;       /* keystream byte multiplier (ctx+0x142), in [0x11,0xfb] */
} sn_salt_t;

/* The server's init-time "fixed" PRNG is the shaping PRNG evaluated at seq 0. */
static uint32_t salt_prng(const sn_prng_t *p, uint32_t sel, uint32_t arg) {
    return sn_prng(p, sel, 0u, arg);
}

static void salt_init(sn_salt_t *s, const sn_prng_t *prng) {
    s->prng = prng;
    s->blk_lo = (uint16_t)sn_range_map(salt_prng(prng, 0x0e, 0x7053), 0x10, 0x60);
    s->blk_hi = (uint16_t)(s->blk_lo + sn_range_map(salt_prng(prng, 0x0f, 0x7053), 0x10, 0xa0));
    if (s->blk_hi > 0x80) s->blk_hi = 0x80;              /* clamp (init @0x3a535) */
    if (s->blk_lo > s->blk_hi) s->blk_lo = s->blk_hi;
    s->ksa_rounds = (uint8_t)sn_range_map(salt_prng(prng, 0x11, 0x51a7), 1, 4);
    s->multiplier = (uint8_t)sn_range_map(salt_prng(prng, 0x12, 0x51a7), 0x11, 0xfb);
}

/* (a) Carrier block length (fcn.0x3aae0). */
static uint32_t salt_block_len(const sn_salt_t *s) {
    return 0x10u + sn_range_map(salt_prng(s->prng, 0x21, 0x7053), s->blk_lo, s->blk_hi);
}

/*
 * (b) KSA inner PRF (fcn.0x3ab10): note this is NOT the shaping wymix — it has
 * its own constants, no golden-ratio term, and the state is pre-XORed.
 */
static uint32_t ksa_prf(uint64_t state, uint32_t salt, uint32_t idx) {
    uint64_t rdx = (uint64_t)idx  * 0x589965cc75374cc3ULL + 0x33a213ec50ffe2e9ULL;
    rdx ^= (state ^ 0xdaa66d2c7ddf743fULL);
    uint64_t rsi = (uint64_t)salt * 0xe7037ed1a0b428dbULL + 0x8f3907f7b2b80c35ULL;
    uint64_t v = sn_splitmix64(rsi ^ rdx);
    return (uint32_t)(v ^ (v >> 32));
}

/* Keyed Fisher-Yates permutation (fcn.0x3ab70); S[i] = perm[i] for i < 16. */
static void salt_permutation(const sn_salt_t *s, uint32_t block_len, uint8_t *perm) {
    uint64_t state = s->prng->s_ctxE8;                   /* salt sub-state (ctx+0xe8) */
    uint32_t n = block_len;
    for (uint32_t i = 0; i < n; i++) perm[i] = (uint8_t)i;       /* identity */
    uint32_t rounds = s->ksa_rounds ? s->ksa_rounds : 1;
    for (uint32_t r = 0; r < rounds; r++) {
        uint32_t salt = 0x51a7u + r;
        for (uint32_t j = 0; j < n; j++) {
            uint32_t pick = j + (ksa_prf(state, salt, j) % (n - j));
            uint8_t t = perm[j]; perm[j] = perm[pick]; perm[pick] = t;
        }
    }
}

/* (c) Keystream byte PRF[k] (fcn.0x38e50); only the low 8 bits are used. */
static uint8_t keystream_byte(const sn_salt_t *s, uint32_t k) {
    uint32_t wmix = sn_wymix(s->prng->s_ctxE8, 2u, 0x51a7u, k);
    uint16_t mul  = (uint16_t)((uint16_t)(k & 0xff) * (uint16_t)s->multiplier);
    return (uint8_t)((mul ^ wmix) & 0xff);
}

void sn_salt_derive(const sn_prng_t *prng, uint32_t *block_len,
                    uint8_t S[16], uint8_t PRF[16]) {
    sn_salt_t s;
    salt_init(&s, prng);
    uint32_t bl = salt_block_len(&s);
    if (block_len) *block_len = bl;
    uint8_t perm[256];
    salt_permutation(&s, bl, perm);
    for (int i = 0; i < 16; i++) S[i] = perm[i];
    for (uint32_t i = 0; i < 16; i++) PRF[i] = keystream_byte(&s, i);
}

/* ----------------------------------------------------------------------- */
#ifdef SALT_SELFTEST
#include <stdio.h>
/* PSK-agnostic self-test: derive the salt params for a user-supplied PSK and
 * verify the obfuscate/de-obfuscate round-trip. No PSK or PSK-derived ground
 * truth is embedded here (test PSKs live in project memory). */
static void hexd(const char *t, const uint8_t *p, int n) {
    printf("%s", t); for (int i = 0; i < n; i++) printf("%02x ", p[i]); printf("\n");
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <psk>\n", argv[0]); return 2; }
    sn_prng_t prng; sn_prng_init(&prng, argv[1]);

    uint32_t bl; uint8_t S[16], PRF[16];
    sn_salt_derive(&prng, &bl, S, PRF);
    sn_salt_t s; salt_init(&s, &prng);

    printf("seed = "); for (int i = 0; i < 32; i++) printf("%02x", prng.seed[i]); printf("\n");
    printf("salt_state=%016llx ksa_rounds=%u mult=0x%02x blk_lo=%u blk_hi=%u\n",
        (unsigned long long)prng.s_ctxE8, s.ksa_rounds, s.multiplier, s.blk_lo, s.blk_hi);
    printf("block_len = %u\n", bl);
    hexd("S   = ", S, 16);
    hexd("PRF = ", PRF, 16);

    /* round-trip: build a wire block from a known salt via the inverse mapping
       (wire[S[i]] = salt[i] ^ PRF[i]), then gather it back and confirm. */
    uint8_t known[16]; for (int i = 0; i < 16; i++) known[i] = (uint8_t)(0xA0 + i);
    uint8_t wire[256]; for (uint32_t i = 0; i < bl; i++) wire[i] = (uint8_t)(i * 7 + 3);
    for (int i = 0; i < 16; i++) wire[S[i]] = (uint8_t)(known[i] ^ PRF[i]);
    uint8_t got[16]; for (int i = 0; i < 16; i++) got[i] = (uint8_t)(wire[S[i]] ^ PRF[i]);
    int ok = !memcmp(got, known, 16);
    printf("de-obfuscation round-trip:  %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
#endif
