/*
 * snell_salt.h — Snell v6 (b3) salt-block obfuscation parameters.
 *
 * Derives, from the shared shaping PRNG, the three things the salt carrier
 * needs: the on-wire block length, the 16 scatter indices S[], and the 16-byte
 * XOR keystream PRF[]. The scatter/gather itself (using S[] and PRF[]) lives in
 * snell_shape.c (sn_salt_obfuscate / sn_salt_deobfuscate). See snell_salt.c.
 */
#ifndef SNELL_SALT_H
#define SNELL_SALT_H

#include <stdint.h>
#include "snell_prng.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Derive (block_len, S[16], PRF[16]) from an initialised shaping PRNG. */
void sn_salt_derive(const sn_prng_t *prng, uint32_t *block_len,
                    uint8_t S[16], uint8_t PRF[16]);

#ifdef __cplusplus
}
#endif
#endif
