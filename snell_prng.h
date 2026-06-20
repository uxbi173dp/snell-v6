/*
 * snell_prng.h — the single Snell v6 (b3) shaping-PRNG core.
 *
 * Every shaped byte the protocol emits is a deterministic function of the PSK,
 * computed through this PRNG: a wyhash/splitmix construction seeded from
 * BLAKE2b-256(PREFIX24 || PSK). It is shared by snell_shape, snell_inter_pad and
 * snell_salt (the arithmetic used to be copy-pasted into all three). Byte-exact
 * against the reference server; the stand-alone reference + self-test lives in
 * process/snell_shape_prng.c.
 */
#ifndef SNELL_PRNG_H
#define SNELL_PRNG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Seed plus the seven 64-bit PRNG sub-states the server keeps in its
 * per-connection context. They are named by their server struct offset
 * (ctx+0xNN) for binary traceability; a selector picks one of them via the
 * internal getter() in snell_prng.c.
 */
typedef struct {
    uint8_t  seed[32];   /* BLAKE2b-256(PREFIX24 || PSK)                     */
    uint64_t s_ctx60;    /* ctx+0x60   = subseed(idx 0x10)                   */
    uint64_t s_ctxA8;    /* ctx+0xa8   = subseed(idx 0)                      */
    uint64_t s_ctxC0;    /* ctx+0xc0   = subseed(idx 5)   — the default      */
    uint64_t s_ctx108;   /* ctx+0x108  = subseed(idx 0x15)                   */
    uint64_t s_ctx120;   /* ctx+0x120  = subseed(idx 2)                      */
    uint64_t s_ctx138;   /* ctx+0x138  = subseed(idx 0x1c)                   */
    uint64_t s_ctxE8;    /* ctx+0xe8   = subseed(idx 3) — the salt sub-state */
} sn_prng_t;

/* Derive the seed (BLAKE2b-256 via libsodium) and all sub-states from the PSK. */
void sn_prng_init(sn_prng_t *p, const char *psk);

/*
 * The shaping PRNG: a 32-bit value selected by (selector, seq, round). The
 * server's init-time "fixed" scalar PRNG is just this evaluated with seq == 0.
 */
uint32_t sn_prng(const sn_prng_t *p, uint32_t sel, uint32_t seq, uint32_t round);

/* range_map(v, lo, hi) = lo + v % (hi - lo + 1), or lo when !(hi > lo). */
uint32_t sn_range_map(uint32_t v, uint16_t lo, uint16_t hi);

/* Lower-level primitives the salt KSA / keystream build on directly. */
uint64_t sn_splitmix64(uint64_t x);
uint32_t sn_wymix(uint64_t a, uint32_t sel, uint32_t seq, uint32_t round);

#ifdef __cplusplus
}
#endif
#endif
