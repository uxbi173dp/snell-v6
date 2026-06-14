/*
 * inter_pad_len.c — byte-EXACT reproduction of the Snell v6 (b2) server's
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
 *   [0x68+2i] sztbl_e[8]   [0xb0] inter_hi   [0xb4] f_b4        [0xba] pad_HI
 *   [0xd6+2i] sztbl_f[8]   [0x110] inter_lo  [0x11c] pad_LO     [0xca]=8 (table div)
 *   [0xf6] cad_div         [0x12c] cad_thresh[0x146] field09    [0x149] f149
 *   [0x11e] f11e           [0x114] f114      [0x150] seq counter
 * NOTE the binary stores the prefix-pad LOW bound at [0x11c] and the HIGH bound
 * at [0xba] (the reverse of the field names in the leaked header); prefix_len =
 * range_map(prng(0x21,seq,0), lo=[0x11c], hi=[0xba]).  sn_profile_init in
 * snell_shape.c already derives pf->pad_lo/pad_hi with this corrected ordering.
 *
 * This file is the inter-pad PIPELINE only; the profile (PRNG ctx seeds, pad_lo/hi,
 * inter_lo/hi, sztbl_e/f, f_b4/f149/f114/f11e, cad_div/cad_thresh) is derived once
 * by sn_profile_init() in snell_shape.c and read here from the shared sn_profile_t.
 * The one selector that snell_shape.c does NOT pre-store is field09 (sel 0x09); it
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
 * records and all 6 acceptance points; covers f_b4 = 0/1/2.
 */
#include <stdint.h>
#include "snell_shape.h"

/* ---------- verified PRNG primitives (ipl_-prefixed; mirror snell_shape.c) ---------- */
static uint64_t ipl_splitmix64(uint64_t x){x^=x>>30;x*=0xbf58476d1ce4e5b9ULL;x^=x>>27;x*=0x94d049bb133111ebULL;x^=x>>31;return x;}
static uint64_t ipl_wymix(uint64_t a,uint32_t sel,uint32_t seq,uint32_t round){
    uint64_t rcx=(uint64_t)round*0x589965cc75374cc3ULL+0x33a213ec50ffe2e9ULL;
    uint64_t rsi=(uint64_t)sel*0x9e3779b97f4a7c15ULL;
    uint64_t rdx=(uint64_t)seq*0xe7037ed1a0b428dbULL+0x8f3907f7b2b80c35ULL;
    uint64_t s=ipl_splitmix64(a^rcx^rsi^rdx);
    return (uint32_t)(s^(s>>32));
}
/* getter: selector -> which PRNG context word (jump table @0x1f5ee0). */
static uint64_t ipl_getter(const sn_profile_t *c,uint32_t sel){
    switch(sel){
        case 0: case 1: case 14: case 15: case 33: case 34: return c->s_ctxA8;
        case 2: return c->s_ctx120;
        case 3: case 16: case 17: case 18: case 19: case 20: return c->s_ctx60;
        case 21: case 22: case 23: case 24: case 25: case 26: case 38: case 39: return c->s_ctx108;
        case 28: case 29: case 30: case 31: case 32: case 35: case 36: case 37: return c->s_ctx138;
        default: return c->s_ctxC0;
    }
}
static uint32_t ipl_prng(const sn_profile_t *c,uint32_t sel,uint32_t seq,uint32_t round){
    return (uint32_t)ipl_wymix(ipl_getter(c,sel),sel,seq,round);
}
/* range_map(v, lo, hi) = (hi>lo) ? lo + v%(hi-lo+1) : lo  (binary 0x38b30) */
static uint32_t ipl_rmap(uint32_t v,uint16_t lo,uint16_t hi){
    if(!(hi>lo)) return lo; return lo+(v%((uint32_t)hi-(uint32_t)lo+1u));
}
/* prefix_len (0x395e0) = range_map(prng(0x21,seq,0), lo=pad_lo, hi=pad_hi).
 * Matches sn_shape_prefix_len() in snell_shape.c (same selector & bounds). */
static int ipl_prefix_len(const sn_profile_t *pf, uint32_t seq){
    return (int)ipl_rmap(ipl_prng(pf,0x21,seq,0), (uint16_t)pf->pad_lo, (uint16_t)pf->pad_hi);
}

/* cadence (0x39ae0): true => stage1 emits a base length.
 * field09 (sel 0x09, [0x146]) = range_map(prng(0x09,0,0),2,8) — computed inline.
 * The periodic `seq % cad_div == 0` rule applies to ALL payloads (not just
 * payload==0): verified live (period-cad_div pad on large-payload records that
 * the payload<=cad_thresh check would otherwise skip). */
static int ipl_cadence(const sn_profile_t *pf, uint32_t seq, int payload){
    uint32_t field09 = ipl_rmap(ipl_prng(pf,0x09,0,0), 2, 8);
    if(field09 > seq) return 1;                                  /* early chunks: always pad */
    if(pf->cad_div != 0 && (seq % (uint32_t)pf->cad_div) == 0) return 1;  /* periodic cadence */
    if(payload != 0)
        return ((uint64_t)payload <= (uint64_t)(uint32_t)pf->cad_thresh) ? 1 : 0;
    return 0;
}

/* stage1 (0x39b20) */
static int ipl_stage1(const sn_profile_t *pf, uint32_t seq, int payload){
    if(!ipl_cadence(pf,seq,payload)) return 0;
    return (int)ipl_rmap(ipl_prng(pf,0x22,seq,(uint32_t)payload),
                         (uint16_t)pf->inter_lo, (uint16_t)pf->inter_hi);
}

/* stage2 (0x39b90 -> refinement 0x39bb0). total passed as 64-bit. */
static int ipl_stage2(const sn_profile_t *pf, uint32_t seq, uint64_t total){
    if(total > 0x5b3){
        if(total <= 0xfffe) return (int)total;   /* min(total,0xfffe) */
        return 0xffff;
    }
    uint32_t r10, r11, r13;

    if((uint32_t)pf->f149 > seq)
        r10 = (uint32_t)pf->sztbl_f[seq];                       /* sztbl_f[seq], seq<f149 */
    else
        r10 = (uint32_t)pf->sztbl_e[ ipl_prng(pf,0x23,seq,(uint32_t)total) % 8u ];

    if(pf->f_b4 == 2){
        /* 0x39ced: r10 = (r10w + jitter > 0) ? r10 + jitter : 1
           jitter = prng(0x24,seq,0) % (2*f114+1) - f114 */
        uint32_t pv  = ipl_prng(pf,0x24,seq,0);
        uint32_t den = 2u*(uint32_t)pf->f114 + 1u;
        int jit  = (int)(pv % den) - (int)pf->f114;
        int eax  = (int)(uint16_t)r10 + jit;
        int edx  = (int)r10 + jit;
        r10 = (eax > 0) ? (uint32_t)edx : 1u;
    }

    /* r11 = min(0x2da, (f11e*total)/100) */
    uint64_t div100 = ((uint64_t)(uint32_t)pf->f11e * total) / 100ULL;
    r11 = ((uint32_t)0x2da >= (uint32_t)div100) ? (uint32_t)div100 : 0x2da;

    if(ipl_prng(pf,0x23,seq,r11) & 1){
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
        uint16_t tv = (uint16_t)pf->sztbl_e[ ipl_prng(pf,0x25,seq,r10) % 8u ];
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
    int pfx = ipl_prefix_len(pf, seq);
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
