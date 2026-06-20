/*
 * snell_shape.h — Snell v6 (b3) per-PSK profile & traffic shaping.
 *
 * Derives the deployment profile from the PSK and provides the shaping
 * operations the wire format needs:
 *   - salt obfuscation/deobfuscation (16 real bytes scattered in a per-PSK block_len block, e.g. 87)
 *   - per-chunk prefix-pad length (the bytes preceding each control record)
 *   - mode-2 de-interleave (involution) of the inter_pad+payload region
 *
 * The values are PRNG-derived (wyhash/splitmix seeded from BLAKE2b(PREFIX24||PSK)),
 * deterministic per PSK. See PROTOCOL.md.
 */
#ifndef SNELL_SHAPE_H
#define SNELL_SHAPE_H

#include <stdint.h>
#include <stddef.h>
#include "snell_prng.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SN_DIR_C2S 0   /* client -> server framing state */
#define SN_DIR_S2C 1   /* server -> client framing state */

typedef struct {
    /* salt obfuscation (per PSK) */
    uint8_t  salt_S[16];     /* scatter indices into the salt block */
    uint8_t  salt_PRF[16];   /* salt keystream */
    int      salt_block_len; /* total obfuscated salt block length (e.g. 87) */

    /* de-interleave + shaping params (PRNG-derived from PSK) */
    int      deint_mode;     /* 0=stride/const-phase, 1=block-swap, 2=stride/PRNG-phase */
    int      stride_base;    /* modes 0/2: stride = stride_base + round%3 */
    int      phase_seed;     /* modes 0/2: phase offset */
    int      deint_block_len;        /* mode 1: block size for block-swap (sel 0x14, [8,64]) */
    int      deint_rounds;   /* R */
    uint16_t pad_lo, pad_hi; /* prefix-pad bounds (clamped) */

    /* pad-CONTENT shaping (per-byte transform of generated padding, for DPI
     * resistance). The server fills pad via a base keystream + one of 4 modes
     * selected by (prng(0x06,0,0)&3); we reproduce the mode's distribution. */
    int      pad_mode;                          /* 0..3 */
    int      pad_m0_step, pad_m0_span;          /* mode 0 (byte-walk) */
    int      pad_m1_wA, pad_m1_wB, pad_m1_wC;   /* mode 1 (3-class histogram) */
    int      pad_m2_off;                        /* mode 2 (nibble-mix decimal) */
    int      pad_m3_period, pad_m3_base;        /* mode 3 (periodic alphabet) */

    /* chunk-size selection (how c->s payload is split into records) */
    int      chunk_mode;                        /* 0=ramp, 1=histogram, 2=ramp+jitter */
    int      chunk_max, chunk_min, chunk_jitter;
    int      chunk_grow;                         /* per-record ramp step (sel 0x18, [0x400,0x1000] clamp 0xb68) */
    int      chunk_hist[8];                      /* mode 1 size pool */
    /* inter-pad cadence: whether a chunk carries an inter-pad region */
    int      cadence_period;       /* pad every cadence_period-th chunk (ctx+0xf6, sel 0x0a) */
    int      cadence_payload_max;  /* also pad any chunk with payload <= this (ctx+0x12c, sel 0x0b) */
    /* inter-pad LENGTH pipeline (pad each record toward a profile target size) */
    int      inter_lo, inter_hi;   /* stage1 base bounds (sel 0x07/0x08) */
    int      inter_sz_rand[8];     /* stage2 size table, PRNG-indexed     (ctx+0x68, sel 0x1e) */
    int      inter_sz_seq[8];      /* stage2 size table, seq-indexed (warmup) (ctx+0xd6, sel 0x1f) */
    int      inter_jitter_mode;    /* stage2 jitter mode 0/1/2; mode 2 jitters r10 (ctx+0xb4, sel 0x1c) */
    int      inter_warmup_seqs;    /* first N seqs index inter_sz_seq directly (ctx+0x149, sel 0x1d) */
    int      inter_jitter_span;    /* stage2 jitter half-span (ctx+0x114, sel 0x20) */
    int      inter_target_pct;     /* stage2 target = pct*total/100, capped at 0x2da (ctx+0x11e, sel 0x1c/0x504c) */
    int      idle_gap_s;             /* s2c/c2s chunk-ramp idle-reset threshold, SECONDS
                                      * (server ctx+0x144 = range_map(prng(0x1b,0,0),0xc,0x5a)).
                                      * If wall-clock seconds since the previous write-pass
                                      * exceed this, the running chunk target resets to chunk_min. */

    /* shaping-PRNG core (seed + sub-states), shared by inter-pad & salt */
    sn_prng_t prng;

    char     psk[256];
    size_t   psk_len;
} sn_profile_t;

/* Derive the full profile from the PSK. 0 on success. */
int sn_profile_init(sn_profile_t *pf, const char *psk);

/* Build an obfuscated salt block from a chosen 16-byte real salt.
 * block must hold pf->salt_block_len bytes; filler positions get random bytes. */
void sn_salt_obfuscate(const sn_profile_t *pf, const uint8_t real_salt[16], uint8_t *block);

/* Recover the 16-byte real salt from a received obfuscated block. */
void sn_salt_deobfuscate(const sn_profile_t *pf, const uint8_t *block, uint8_t real_salt[16]);

/* Length of the prefix padding before the control record of chunk `seq`
 * in the given direction. */
int sn_shape_prefix_len(const sn_profile_t *pf, int dir, uint32_t seq);

/* Per-record c->s chunk-size cap (server choose_chunk @ 0x39610), byte-exact.
 * `target` is the running ramp state (server ctx+0x50): seed it to chunk_min at
 * stream start (sn_shape_chunk_reset), pass &state here, and call
 * sn_shape_chunk_advance() once after each emitted record. `remaining` is unused
 * by the size pick (the caller clamps emitted bytes to min(size,remaining)).
 * Validated vs server s->c: 15,908 records, 0 over-predictions. */
int  sn_shape_chunk_len(const sn_profile_t *pf, uint32_t seq, int remaining, uint16_t *target);
/* Advance the running chunk-size target after a record (ramp by chunk_grow,
 * saturating at chunk_max; seeds to chunk_min if still 0). */
void sn_shape_chunk_advance(const sn_profile_t *pf, uint16_t *target);
/* Seed a fresh stream's running target to chunk_min (server RVA 0x3b9cb). */
void sn_shape_chunk_reset(const sn_profile_t *pf, uint16_t *target);
/* Fill `dest[0..len)` with profile-shaped padding content for chunk `seq`,
 * matching the per-PSK pad distribution the server uses (DPI resistance).
 * Round-trips regardless of content (pad is AAD, sender-chosen, unvalidated). */
void sn_fill_pad(const sn_profile_t *pf, int dir, uint32_t seq, uint8_t *dest, int len);

/* Inter-pad length for a chunk: the server's exact pad-to-target-size pipeline
 * (byte-validated, two independent reconstructions). Depends on the chunk's
 * `payload` length and `prior` (bytes already emitted in this write before this
 * chunk — salt_block_len before handshake chunk 0, else 0). Handles cadence
 * internally (may return 0). Implemented in snell_inter_pad.c. */
int inter_pad_len(const sn_profile_t *pf, uint32_t seq, int payload, int prior);
/* Thin alias kept for existing call sites. */
int sn_shape_inter_len(const sn_profile_t *pf, uint32_t seq, int payload, int prior);

/* In-place de-interleave (involution) of A (inter_pad, lenA) and
 * B (payload_ct, lenB) for chunk `seq` in `dir`. Handles all three modes
 * (0 stride/const-phase, 1 block-swap, 2 stride/PRNG-phase). Same op
 * de-permutes (recv) and permutes (send). */
void sn_deinterleave(const sn_profile_t *pf, int dir, uint32_t seq,
                     uint8_t *A, int lenA, uint8_t *B, int lenB);

#ifdef __cplusplus
}
#endif
#endif
