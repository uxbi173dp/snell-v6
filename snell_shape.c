/*
 * snell_shape.c — Snell v6 (b2) per-PSK profile & traffic shaping.
 *
 * Builds the deployment profile from the PSK and implements the shaping the wire
 * format needs: salt obfuscation, prefix-pad length, pad content (4 modes),
 * chunk-size selection, and the inter_pad/payload de-interleave (3 modes).
 * The underlying PRNG lives in snell_prng.c; the inter-pad length pipeline in
 * snell_inter_pad.c. Stand-alone PRNG reference + self-test: snell_shape_prng.c.
 */
#include "snell_shape.h"
#include "snell_prng.h"
#include "snell_salt.h"
#include <string.h>

int sn_profile_init(sn_profile_t *pf, const char *psk) {
    memset(pf, 0, sizeof(*pf));
    strncpy(pf->psk, psk, sizeof(pf->psk)-1);
    pf->psk_len = strlen(pf->psk);

    sn_prng_init(&pf->prng, psk);   /* seed (BLAKE2b) + sub-states, in snell_prng.c */

    pf->pad_lo = (uint16_t)sn_range_map(sn_prng(&pf->prng,0x0e,0,0), 8, 0x50);
    pf->pad_hi = (uint16_t)(pf->pad_lo + sn_range_map(sn_prng(&pf->prng,0x0f,0,0), 0x10, 0xa0));
    if (pf->pad_hi > 0x80) pf->pad_hi = 0x80;
    if (pf->pad_lo > pf->pad_hi) pf->pad_lo = pf->pad_hi;

    pf->deint_mode   = (int)(sn_prng(&pf->prng,0x10,0,0) % 3u);
    pf->deint_rounds = (int)sn_range_map(sn_prng(&pf->prng,0x11,0,0), 1, 3);
    pf->stride_base  = (int)sn_range_map(sn_prng(&pf->prng,0x12,0,0), 2, 0x0d);
    pf->phase_seed   = (int)sn_range_map(sn_prng(&pf->prng,0x13,0,0), 0, 0x0f);
    pf->deint_block_len      = (int)sn_range_map(sn_prng(&pf->prng,0x14,0,0), 8, 0x40);  /* mode 1 */

    /* pad-content shaping params (sel 0x06 rounds 0..6, plus 0x0c/0x0d for mode 0) */
    pf->pad_mode   = (int)(sn_prng(&pf->prng,0x06,0,0) & 3u);
    pf->pad_m1_wA  = (int)sn_range_map(sn_prng(&pf->prng,0x06,0,1), 0x18, 0x80);
    pf->pad_m1_wB  = (int)sn_range_map(sn_prng(&pf->prng,0x06,0,2), 0x10, 0x60);
    pf->pad_m1_wC  = (int)sn_range_map(sn_prng(&pf->prng,0x06,0,3), 0x10, 0x60);
    pf->pad_m2_off = (int)sn_range_map(sn_prng(&pf->prng,0x06,0,4), 0, 9);
    pf->pad_m3_base   = (int)sn_range_map(sn_prng(&pf->prng,0x06,0,5), 1, 8);     /* round 5 -> base */
    pf->pad_m3_period = (int)sn_range_map(sn_prng(&pf->prng,0x06,0,6), 7, 0x17);  /* round 6 -> period */
    pf->pad_m0_step = (int)sn_range_map(sn_prng(&pf->prng,0x0c,0,0), 0x18, 0x29);
    pf->pad_m0_span = (int)sn_range_map(sn_prng(&pf->prng,0x0d,0,0), 0x3a, 0x4c);

    /* chunk-size selection (sel 0x15-0x1a) and inter-pad cadence (sel 0x09/0x0a/0x0b) */
    pf->chunk_mode   = (int)(sn_prng(&pf->prng,0x15,0,0) % 3u);
    pf->chunk_max    = (int)sn_range_map(sn_prng(&pf->prng,0x17,0,0), 0x2000, 0x3fff);
    pf->chunk_min    = (int)sn_range_map(sn_prng(&pf->prng,0x16,0,0), 0x200, 0x5b4);
    pf->chunk_jitter = (int)sn_range_map(sn_prng(&pf->prng,0x19,0,0), 0x10, 0xc0);
    if (pf->chunk_jitter > 0xb6) pf->chunk_jitter = 0xb6;
    for (int i = 0; i < 8; i++) {
        int v = (int)sn_range_map(sn_prng(&pf->prng,0x1a,0,(uint32_t)i), 0x1000, (uint16_t)pf->chunk_max);
        if (v < 0x400) v = 0x1000;
        pf->chunk_hist[i] = v;
    }
    pf->chunk_grow = (int)sn_range_map(sn_prng(&pf->prng,0x18,0,0), 0x400, 0x1000);  /* ramp step */
    if (pf->chunk_grow > 0xb68) pf->chunk_grow = 0xb68;                    /* clamp 0x3a615 */
    pf->cadence_period    = (int)sn_range_map(sn_prng(&pf->prng,0x0a,0,0), 2, 0x0b);
    pf->cadence_payload_max = (int)sn_range_map(sn_prng(&pf->prng,0x0b,0,0), 0x60, 0x300);

    /* inter-pad length pipeline (pad-to-target-size) params */
    int s07 = (int)sn_range_map(sn_prng(&pf->prng,0x07,0,0), 0x18, 0xa0);
    pf->inter_hi = s07 + (int)sn_range_map(sn_prng(&pf->prng,0x08,0,0), 0xa0, 0x3c0);
    if (pf->inter_hi > 0x2da) pf->inter_hi = 0x2da;
    pf->inter_lo = s07 < pf->inter_hi ? s07 : pf->inter_hi;
    for (int i = 0; i < 8; i++) pf->inter_sz_rand[i] = (int)sn_range_map(sn_prng(&pf->prng,0x1e,0,(uint32_t)i), 0x140, 0x5b4);
    for (int i = 0; i < 8; i++) pf->inter_sz_seq[i] = (int)sn_range_map(sn_prng(&pf->prng,0x1f,0,(uint32_t)i), 0x168, 0x5b4);
    pf->inter_jitter_mode  = (int)(sn_prng(&pf->prng,0x1c,0,0) % 3u);
    pf->inter_warmup_seqs  = (int)sn_range_map(sn_prng(&pf->prng,0x1d,0,0), 4, 8);
    pf->inter_jitter_span  = (int)sn_range_map(sn_prng(&pf->prng,0x20,0,0), 8, 0x60);
    pf->inter_target_pct  = (int)sn_range_map(sn_prng(&pf->prng,0x1c,0,0x504c), 8, 0x30);
    /* chunk-ramp idle-reset gap, in SECONDS (server init 0x3a3dd-0x3a407 -> ctx+0x144).
     * Used by the tunnel: a write-pass starting >idle_gap_s wall-seconds after the prior
     * one resets the running chunk target to chunk_min (server RVA 0x3bb40-0x3bb5b). */
    pf->idle_gap_s = (int)sn_range_map(sn_prng(&pf->prng,0x1b,0,0), 0xc, 0x5a);

    /* salt-obfuscation params from the shared PRNG (snell_salt.c) */
    uint32_t bl = 0;
    sn_salt_derive(&pf->prng, &bl, pf->salt_S, pf->salt_PRF);
    pf->salt_block_len = (int)bl;
    return 0;
}

void sn_salt_obfuscate(const sn_profile_t *pf, const uint8_t real_salt[16], uint8_t *block) {
    /* filler is profile-shaped like the server's salt carrier (it fills the block
     * via fill_pad with seq=0xffffffff), then the 16 real-salt bytes are scattered. */
    sn_fill_pad(pf, SN_DIR_C2S, 0xffffffffu, block, pf->salt_block_len);
    for (int i = 0; i < 16; i++) block[pf->salt_S[i]] = real_salt[i] ^ pf->salt_PRF[i];
}
void sn_salt_deobfuscate(const sn_profile_t *pf, const uint8_t *block, uint8_t real_salt[16]) {
    for (int i = 0; i < 16; i++) real_salt[i] = block[pf->salt_S[i]] ^ pf->salt_PRF[i];
}

int sn_shape_prefix_len(const sn_profile_t *pf, int dir, uint32_t seq) {
    (void)dir;   /* both directions share the profile; caller keeps per-dir seq */
    return (int)sn_range_map(sn_prng(&pf->prng, 0x21, seq, 0), pf->pad_lo, pf->pad_hi);
}

/* Inter-pad length = the server's EXACT pad-to-target-size pipeline, implemented
 * byte-for-byte in snell_inter_pad.c (two independent reconstructions agree across
 * 2880 differential inputs + 2117 live records). This is a thin alias for the
 * existing call sites. Handles cadence internally (may return 0). */
int sn_shape_inter_len(const sn_profile_t *pf, uint32_t seq, int payload, int prior) {
    return inter_pad_len(pf, seq, payload, prior);
}

/* choose_chunk @ 0x39610 — exact per-record size cap from the running target.
 * mode 0: size IS the ramp target; mode 1: histogram pick indexed by
 * prng(0x26,seq,target); mode 2: target + signed jitter via prng(0x27,seq,target).
 * Common tail: min(picked, chunk_max) then floor 0x40. */
int sn_shape_chunk_len(const sn_profile_t *pf, uint32_t seq, int remaining, uint16_t *target) {
    (void)remaining;                                       /* ignored by the size pick */
    uint32_t tgt = *target ? *target : (uint16_t)pf->chunk_min;   /* 0x39611 seed-from-min */
    int picked;
    switch (pf->chunk_mode) {
    case 1:  picked = pf->chunk_hist[sn_prng(&pf->prng,0x26,seq,tgt) % 8u]; break;   /* 0x39680 */
    case 2:  { int span = 2*pf->chunk_jitter + 1;                             /* 0x396dd */
               int off = (int)(sn_prng(&pf->prng,0x27,seq,tgt) % (uint32_t)span) - pf->chunk_jitter;
               int val = (int)tgt + off;                                      /* 0x396e7 */
               picked = (val >= 0x40) ? val : 0x40; break; }                  /* 0x396f0 */
    default: picked = (int)tgt; break;                                        /* mode 0 ramp */
    }
    int sz = (picked < pf->chunk_max) ? picked : pf->chunk_max;  /* min(picked,max) 0x3963c */
    if (sz <= 0x3f) sz = 0x40;                                   /* floor 0x40 */
    return sz;
}

/* update_chunk_state @ 0x39700 — call once AFTER each emitted record. */
void sn_shape_chunk_advance(const sn_profile_t *pf, uint16_t *target) {
    if (*target == 0) { *target = (uint16_t)pf->chunk_min; return; }
    int t = (int)*target + pf->chunk_grow;
    *target = (uint16_t)((t < pf->chunk_max) ? t : pf->chunk_max);   /* saturate at max */
}

/* Seed a fresh stream's running target (server RVA 0x3b9cb). */
void sn_shape_chunk_reset(const sn_profile_t *pf, uint16_t *target) {
    *target = (uint16_t)pf->chunk_min;
}

/* map_byte: lo + (b % (hi-lo+1)) — the server's pad-content range mapper (8-bit). */
static uint8_t map_byte(uint8_t b, int lo, int hi) {
    if (hi <= lo) return (uint8_t)lo;
    return (uint8_t)(lo + (b % (hi - lo + 1)));
}

/* mode-0 GF table (rodata 0x1f5f80): row K = bytes with K set bits. */
static const uint8_t SN_GF_TBL[128] = {
 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,
 0x03,0x05,0x09,0x11,0x21,0x41,0x81,0x06,0x0a,0x12,0x22,0x42,0x82,0x0c,0x18,0x24,
 0x07,0x0b,0x13,0x23,0x43,0x83,0x0d,0x19,0x31,0x61,0xc1,0x0e,0x1c,0x38,0x70,0xe0,
 0x0f,0x17,0x27,0x47,0x87,0x1b,0x33,0x63,0xc3,0x1d,0x39,0x71,0xe1,0x3c,0x78,0xf0,
 0xf8,0xf4,0xec,0xdc,0xbc,0x7c,0xf2,0xe6,0xce,0x9e,0x3e,0xf1,0xe3,0xc7,0x8f,0x1f,
 0xfc,0xfa,0xf6,0xee,0xde,0xbe,0x7e,0xf9,0xf5,0xed,0xdd,0xbd,0x7d,0xf3,0xe7,0xdb,
 0xfe,0xfd,0xfb,0xf7,0xef,0xdf,0xbf,0x7f,0xfe,0xfd,0xfb,0xf7,0xef,0xdf,0xbf,0x7f};

/* stream_fill (RVA 0x38d20): deterministic keystream, len baked into the seed.
 * sel=0 draws from the pad-base sub-state (s_ctxA8); sel=2 from the mode-3
 * scratch sub-state (s_ctx120). */
static void stream_fill(const sn_profile_t *pf, uint32_t sel, uint32_t seq, uint8_t *dest, int len) {
    uint64_t g = (sel == 2) ? pf->prng.s_ctx120 : pf->prng.s_ctxA8;
    uint64_t S = (0xb57de1f3f82cb33fULL + (uint64_t)seq * 0xd6e8feb86659fd93ULL)
               ^ ((uint64_t)sel * 0xa24baed4963ee407ULL)
               ^ ((uint64_t)(uint32_t)len * 0x165667b19e3779f9ULL + 0x0d4cd3e7b14a36d7ULL)
               ^ g;
    for (int off = 0; off < len; ) {
        S += 0x9e3779b97f4a7c15ULL;
        uint64_t w = sn_splitmix64(S);
        for (int b = 0; b < 8 && off < len; b++, off++) dest[off] = (uint8_t)(w >> (8*b));
    }
}

/* Byte-EXACT pad content: deterministic per (PSK,seq,len) base + the mode transform,
 * reproducing the server's pad bit-for-bit (so c->s pad == a real client's). */
void sn_fill_pad(const sn_profile_t *pf, int dir, uint32_t seq, uint8_t *dest, int len) {
    (void)dir;
    if (len <= 0) return;
    stream_fill(pf, 0, seq, dest, len);          /* deterministic base keystream */
    switch (pf->pad_mode) {
    case 2: {  /* nibble-mix decimal: low nibble is a decimal digit 0..9 */
        int o = pf->pad_m2_off;
        for (int i = 0; i < len; i++) {
            uint8_t a = dest[i];
            int low  = ((a & 0x0f) + (i & 1) + o) % 10;
            int high = ((a >> 4)   + (i & 3) + 3) & 0x0f;
            dest[i] = (uint8_t)((high << 4) | low);
        }
        break; }
    case 1: {  /* 3-class byte histogram: printable / high1 / high2 */
        int W = pf->pad_m1_wA + pf->pad_m1_wB + pf->pad_m1_wC; if (W <= 0) W = 1;
        for (int i = 0; i < len; i++) {
            uint8_t b = dest[i]; int rem = b % W;
            if (rem < pf->pad_m1_wA)                       dest[i] = map_byte((uint8_t)(b + i),   0x20, 0x7e);
            else if (rem < pf->pad_m1_wA + pf->pad_m1_wB)  dest[i] = map_byte((uint8_t)(b ^ i),   0x80, 0xbf);
            else                                           dest[i] = map_byte((uint8_t)(b + i*7), 0xc0, 0xff);
        }
        break; }
    case 0: {  /* GF-table byte-walk */
        int v = (int)sn_range_map(sn_prng(&pf->prng,1,seq,0), pf->pad_m0_step, pf->pad_m0_span);
        int e = (v & 0xff) << 3;
        int k = (e <= 0x31) ? 1 : (e > 0x2ed) ? 7 : (e + 0x32)/100;
        if (k < 1) k = 1; if (k > 7) k = 7;
        for (int i = 0; i < len; i++) {
            uint8_t a = dest[i];
            int ed = (i + a) & 0xff;
            uint8_t tv = SN_GF_TBL[k*16 + ((ed ^ a) & 0x0f)];
            int c = ((a >> 4) ^ ed) & 7;
            dest[i] = c ? (uint8_t)((tv << c) | (tv >> (8 - c))) : tv;   /* rol8 */
        }
        break; }
    case 3: {  /* periodic alphabet */
        int P = pf->pad_m3_period < 5 ? 5 : pf->pad_m3_period;
        int A = pf->pad_m3_base;
        int G = (A*4 < 0x20) ? A*4 : 0x20; if (G < 1) G = 1;
        uint8_t scratch[32]; stream_fill(pf, 2, seq, scratch, 32);
        for (int i = 0; i < len; i++) {
            int m = i % P;
            if (m < P-3)        dest[i] = (uint8_t)(((A+3)*i) ^ scratch[i % G]);
            else if (m == P-1)  { /* keep base[i] */ }
            else                dest[i] = (uint8_t)(0x30 + (dest[i] % 10));
        }
        break; }
    }
}

void sn_deinterleave(const sn_profile_t *pf, int dir, uint32_t seq,
                     uint8_t *A, int lenA, uint8_t *B, int lenB) {
    (void)dir;
    if (lenA <= 0 || lenB <= 0) return;
    int L = lenA < lenB ? lenA : lenB;

    if (pf->deint_mode == 1) {
        /* block-swap: each round k swaps P-byte blocks at indices with
         * parity (k&1) between A and B. Composed of commuting involutions,
         * so replaying the same rounds both permutes (send) & de-permutes. */
        int P = pf->deint_block_len; if (P <= 0) P = 1;
        int nblk = L / P;
        for (int k = 0; k < pf->deint_rounds; k++) {
            int parity = k & 1;
            for (int i = parity; i < nblk; i += 2) {
                uint8_t *a = A + (long)i * P, *b = B + (long)i * P;
                for (int j = 0; j < P; j++) { uint8_t t=a[j]; a[j]=b[j]; b[j]=t; }
            }
        }
        return;
    }

    /* modes 0 and 2: stride-swap. Mode 2 derives the phase per round from
     * the data PRNG (sel 3); mode 0 uses a constant phase (phase_seed). */
    for (int r = 0; r < pf->deint_rounds; r++) {
        int stride = pf->stride_base + (r % 3); if (stride <= 0) stride = 1;
        int phase;
        if (pf->deint_mode == 2) {
            uint32_t pv = sn_prng(&pf->prng, 3, seq, (uint32_t)r);
            phase = (int)(((uint64_t)pv + (uint32_t)pf->phase_seed) % (uint32_t)stride);
        } else { /* mode 0 */
            phase = (int)((uint32_t)pf->phase_seed % (uint32_t)stride);
        }
        for (int j = phase; j < L; j += stride) { uint8_t t=A[j]; A[j]=B[j]; B[j]=t; }
    }
}
