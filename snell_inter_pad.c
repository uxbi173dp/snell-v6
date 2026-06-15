/*
 * snell_inter_pad.c — byte-EXACT reproduction of the Snell v6 (b2) server's
 * inter-pad LENGTH computation, validated live against /root/snellv6/snell-server.
 *
 * Reverse-engineered from the unpacked memory dump (RVAs == text.bin offsets):
 *   builder      0x3b020  (composition; final pad_len ror'd & stored at 0x3b13d)
 *   stage1       0x39b20  (cadence-gated base length)
 *   cadence      0x39ae0
 *   stage2       0x39b90  (-> refinement loop 0x39bb0)
 *   prefix_len   0x395e0
 *   const        0x39b80  (returns 0x2da)
 *   profile init 0x39d90
 *   PRNG         getter 0x38c30 (jump table @0x1f5ee0), wymix 0x38c90,
 *                splitmix 0x38b70, range_map 0x38b30
 *
 * Struct-offset map (profile base, from init + getter, base shift +0x60 applied):
 *   [0x68+2i] inter_sz_rand[8]   [0xb0] inter_hi   [0xb4] inter_jitter_mode        [0xba] pad_HI
 *   [0xd6+2i] inter_sz_seq[8]   [0x110] inter_lo  [0x11c] pad_LO     [0xca]=8 (table div)
 *   [0xf6] cadence_period         [0x12c] cadence_payload_max[0x146] cadence_warmup    [0x149] inter_warmup_seqs
 *   [0x11e] inter_target_pct           [0x114] inter_jitter_span      [0x150] seq counter
 * NOTE the binary stores the prefix-pad LOW bound at [0x11c] and the HIGH bound
 * at [0xba] (the reverse of the field names in the leaked header); prefix_len =
 * range_map(prng(0x21,seq,0), lo=[0x11c], hi=[0xba]).  sn_profile_init in
 * snell_shape.c already derives pf->pad_lo/pad_hi with this corrected ordering.
 *
 * This file is the inter-pad PIPELINE only; the profile (PRNG ctx seeds, pad_lo/hi,
 * inter_lo/hi, inter_sz_rand/f, inter_jitter_mode/inter_warmup_seqs/inter_jitter_span/inter_target_pct, cadence_period/cadence_payload_max) is derived once
 * by sn_profile_init() in snell_shape.c and read here from the shared sn_profile_t.
 * The one selector that snell_shape.c does NOT pre-store is cadence_warmup (sel 0x09); it
 * is cheap (one PRNG eval) and computed inline in cadence().
 *
 * Public entry: int inter_pad_len(const sn_profile_t *pf, uint32_t seq,
 *                                 int payload, int prior);
 *   payload = plaintext bytes of the record; prior = bytes already emitted in the
 *   same write before this record (salt_block_len for the first c->s record that
 *   shares the salt block's buffer; 0 for all later records — verified on the wire,
 *   prior does NOT accumulate within a build pass).
 *
 * Two independent reconstructions (empirical + static-first) plus a third
 * stage2-focused live capture agree across 2880 differential inputs + 2117 live
 * records and all 6 acceptance points; covers inter_jitter_mode = 0/1/2.
 */
#include <stdint.h>
#include "snell_shape.h"
#include "snell_prng.h"

/* cadence (0x39ae0): true => stage1 emits a base length.
 * cadence_warmup (sel 0x09, [0x146]) = range_map(prng(0x09,0,0),2,8) — computed inline.
 * The periodic `seq % cadence_period == 0` rule applies to ALL payloads (not just
 * payload==0): verified live (period-cadence_period pad on large-payload records that
 * the payload<=cadence_payload_max check would otherwise skip). */
static int ipl_cadence(const sn_profile_t *pf, uint32_t seq, int payload){
    uint32_t cadence_warmup = sn_range_map(sn_prng(&pf->prng,0x09,0,0), 2, 8);
    if(cadence_warmup > seq) return 1;                                  /* early chunks: always pad */
    if(pf->cadence_period != 0 && (seq % (uint32_t)pf->cadence_period) == 0) return 1;  /* periodic cadence */
    if(payload != 0)
        return ((uint64_t)payload <= (uint64_t)(uint32_t)pf->cadence_payload_max) ? 1 : 0;
    return 0;
}

/* stage1 (0x39b20) */
static int ipl_stage1(const sn_profile_t *pf, uint32_t seq, int payload){
    if(!ipl_cadence(pf,seq,payload)) return 0;
    return (int)sn_range_map(sn_prng(&pf->prng,0x22,seq,(uint32_t)payload),
                         (uint16_t)pf->inter_lo, (uint16_t)pf->inter_hi);
}

/* stage2 (0x39b90 -> refinement 0x39bb0). total passed as 64-bit. */
static int ipl_stage2(const sn_profile_t *pf, uint32_t seq, uint64_t total){
    if(total > 0x5b3){
        if(total <= 0xfffe) return (int)total;   /* min(total,0xfffe) */
        return 0xffff;
    }
    uint32_t r10, r11, r13;

    if((uint32_t)pf->inter_warmup_seqs > seq)
        r10 = (uint32_t)pf->inter_sz_seq[seq];                       /* inter_sz_seq[seq], seq<inter_warmup_seqs */
    else
        r10 = (uint32_t)pf->inter_sz_rand[ sn_prng(&pf->prng,0x23,seq,(uint32_t)total) % 8u ];

    if(pf->inter_jitter_mode == 2){
        /* 0x39ced: r10 = (r10w + jitter > 0) ? r10 + jitter : 1
           jitter = prng(0x24,seq,0) % (2*inter_jitter_span+1) - inter_jitter_span */
        uint32_t pv  = sn_prng(&pf->prng,0x24,seq,0);
        uint32_t den = 2u*(uint32_t)pf->inter_jitter_span + 1u;
        int jit  = (int)(pv % den) - (int)pf->inter_jitter_span;
        int eax  = (int)(uint16_t)r10 + jit;
        int edx  = (int)r10 + jit;
        r10 = (eax > 0) ? (uint32_t)edx : 1u;
    }

    /* r11 = min(0x2da, (inter_target_pct*total)/100) */
    uint64_t div100 = ((uint64_t)(uint32_t)pf->inter_target_pct * total) / 100ULL;
    r11 = ((uint32_t)0x2da >= (uint32_t)div100) ? (uint32_t)div100 : 0x2da;

    if(sn_prng(&pf->prng,0x23,seq,r11) & 1){
        /* 0x39d50 subtract */
        uint16_t dx = (uint16_t)((uint16_t)r11 >> 1);
        if((uint16_t)r10 > dx) r10 = r10 - (uint32_t)dx;
    } else {
        /* 0x39c58 add: r10 = (r11 + r10w <= 0xffff) ? r10 + r11 : 0xffffffff */
        uint32_t sum = r11 + (uint32_t)(uint16_t)r10;
        r10 = (sum <= 0xffff) ? (r10 + r11) : 0xffffffffu;
    }
    r13 = 0xffffffffu;

    /* refinement loop 0x39c80..0x39d49 */
    while((uint64_t)(uint16_t)r10 < total){
        uint16_t tv = (uint16_t)pf->inter_sz_rand[ sn_prng(&pf->prng,0x25,seq,r10) % 8u ];
        if((uint16_t)r10 >= tv){
            r11 += (uint32_t)pf->inter_hi;
            r10 += (uint32_t)pf->inter_hi;
            if((int)r11 > 0xffff) r10 = r13;      /* signed compare; r13 = 0xffffffff */
        } else {
            r10 = tv;
        }
    }
    return (int)r10;
}

/* Top-level composition (builder 0x3b020, value stored at 0x3b13d). */
int inter_pad_len(const sn_profile_t *pf, uint32_t seq, int payload, int prior){
    int s1  = ipl_stage1(pf, seq, payload);
    int pfx = sn_shape_prefix_len(pf, SN_DIR_C2S, seq);   /* prefix_len is direction-independent */
    int ovh = (payload != 0) ? 0x10 : 0;
    uint64_t total = (uint64_t)s1 + (uint64_t)(payload + 0x17)
                   + (uint64_t)pfx + (uint64_t)ovh + (uint64_t)prior;
    int s2 = ipl_stage2(pf, seq, total);
    int inter = s1;
    if(total < (uint64_t)(uint32_t)s2){
        uint64_t gap = (uint64_t)(uint32_t)s2 - total;
        inter = s1 + ((gap < 0x2da) ? (int)gap : 0x2da);
    }
    return (int)(uint16_t)inter;   /* stored as 16-bit big-endian pad_len */
}
