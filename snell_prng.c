/*
 * snell_prng.c — see snell_prng.h.
 *
 * Reverse-engineered from the reference server (fcn.0x38b30 range_map,
 * 0x38b70 splitmix64, 0x38bb0 subseed, 0x38c30 getter, 0x38c90 wymix,
 * 0x39d90 init). All multi-byte seed words are little-endian (x86-64).
 */
#include "snell_prng.h"
#include <sodium.h>
#include <string.h>

/* The 24-byte seed prefix baked into the server's rodata. */
static const uint8_t PREFIX24[24] = {
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94,
    0x33, 0x18, 0xc0, 0x6e, 0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac
};

static uint64_t rotr64(uint64_t x, int c) { return (x >> c) | (x << (64 - c)); }
static uint64_t rotl64(uint64_t x, int c) { return (x << c) | (x >> (64 - c)); }

/* Read seed word i as a little-endian u64. */
static uint64_t seed_word(const uint8_t seed[32], int i) {
    uint64_t w = 0;
    for (int j = 0; j < 8; j++) w |= (uint64_t)seed[8 * i + j] << (8 * j);
    return w;
}

/* SplitMix64 finalizer. 0xbf58476d1ce4e5b9 and 0x94d049bb133111eb are Vigna's
 * canonical splitmix64 mixing multipliers (prng.di.unimi.it/splitmix64.c). */
uint64_t sn_splitmix64(uint64_t x) {
    x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27; x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

/* Mix the four seed words into one sub-state, keyed by (idx, K).
 * The bare constants below are off-the-shelf hash mixers used by the server:
 *   0xd6e8feb86659fd93  odd mixing multiplier applied to idx (server-chosen)
 *   0xa0761d6478bd642f  wyhash default secret[0]
 *   0x9e3779b97f4a7c15  golden-ratio constant, 2^64/phi */
static uint64_t subseed(const uint8_t seed[32], uint32_t idx, uint64_t K) {
    uint64_t s0 = seed_word(seed, 0), s1 = seed_word(seed, 1);
    uint64_t s2 = seed_word(seed, 2), s3 = seed_word(seed, 3);
    uint64_t x = ((uint64_t)idx * 0xd6e8feb86659fd93ULL)
               ^ (K + 0xa0761d6478bd642fULL)
               ^ s0
               ^ (s1 + 0x9e3779b97f4a7c15ULL)
               ^ rotl64(s2, 17)
               ^ rotr64(s3, 11);
    return sn_splitmix64(x);
}

/* Map a selector to the sub-state it draws from (server jump table @0x1f5ee0). */
static uint64_t getter(const sn_prng_t *p, uint32_t sel) {
    switch (sel) {
    case 0: case 1: case 14: case 15: case 33: case 34:           return p->s_ctxA8;
    case 2:                                                       return p->s_ctx120;
    case 3: case 16: case 17: case 18: case 19: case 20:          return p->s_ctx60;
    case 21: case 22: case 23: case 24: case 25: case 26:
    case 38: case 39:                                             return p->s_ctx108;
    case 28: case 29: case 30: case 31: case 32:
    case 35: case 36: case 37:                                    return p->s_ctx138;
    default:                                                      return p->s_ctxC0;
    }
}

/* wyhash-style mix of (sub-state, sel, seq, round) folded to 32 bits.
 * Multipliers are wyhash default-secret words; the added terms are the server's
 * own per-field round constants (not part of any standard secret):
 *   0x589965cc75374cc3  wyhash secret[3]  (+ 0x33a213ec50ffe2e9, server const)
 *   0x9e3779b97f4a7c15  golden-ratio constant, 2^64/phi
 *   0xe7037ed1a0b428db  wyhash secret[1]  (+ 0x8f3907f7b2b80c35, server const) */
uint32_t sn_wymix(uint64_t a, uint32_t sel, uint32_t seq, uint32_t round) {
    uint64_t rcx = (uint64_t)round * 0x589965cc75374cc3ULL + 0x33a213ec50ffe2e9ULL;
    uint64_t rsi = (uint64_t)sel   * 0x9e3779b97f4a7c15ULL;
    uint64_t rdx = (uint64_t)seq   * 0xe7037ed1a0b428dbULL + 0x8f3907f7b2b80c35ULL;
    uint64_t s   = sn_splitmix64(a ^ rcx ^ rsi ^ rdx);
    return (uint32_t)(s ^ (s >> 32));   /* fold 64 -> 32 */
}

uint32_t sn_prng(const sn_prng_t *p, uint32_t sel, uint32_t seq, uint32_t round) {
    return sn_wymix(getter(p, sel), sel, seq, round);
}

uint32_t sn_range_map(uint32_t v, uint16_t lo, uint16_t hi) {
    if (!(hi > lo)) return lo;
    return lo + (v % ((uint32_t)hi - (uint32_t)lo + 1u));
}

void sn_prng_init(sn_prng_t *p, const char *psk) {
    memset(p, 0, sizeof(*p));
    size_t pl = strlen(psk);
    if (pl > 512) pl = 512;                          /* server caps the hashed PSK at 512 */
    uint8_t buf[24 + 512];
    memcpy(buf, PREFIX24, 24);
    memcpy(buf + 24, psk, pl);
    crypto_generichash(p->seed, 32, buf, 24 + pl, NULL, 0);   /* BLAKE2b-256, unkeyed */

    /* sub-states: (idx, K) constants exactly as the server's init pipeline. */
    p->s_ctxC0  = subseed(p->seed, 5,    0xb46c2e7d9a1538f1ULL);
    p->s_ctxA8  = subseed(p->seed, 0,    0x5d9217c083e64ab9ULL);
    p->s_ctx120 = subseed(p->seed, 2,    0xa71f0c54d8396e2bULL);
    p->s_ctxE8  = subseed(p->seed, 3,    0x3e8a91b52740f6cdULL);
    p->s_ctx60  = subseed(p->seed, 0x10, 0xc9f4260b7d1e835aULL);
    p->s_ctx108 = subseed(p->seed, 0x15, 0x62d0b5e19c4a783fULL);
    p->s_ctx138 = subseed(p->seed, 0x1c, 0x917b3c48e6a205d4ULL);
}
