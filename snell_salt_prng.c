/* Snell v6 SALT-block obfuscation - reverse-engineered reference implementation.
 *
 * Reproduces, for ANY PSK, the parameters the server uses to de-obfuscate the
 * salt that is scattered across the first <block_len> wire bytes of a session:
 *
 *     real_salt[i] = wire_block[ S[i] ] ^ PRF[i]          (i = 0..15)
 *
 *   (a) block_len           : length of the salt-carrier block on the wire
 *   (b) S[0..15]            : the 16 scatter indices (first 16 of a keyed
 *                             Fisher-Yates permutation of [0..block_len))
 *   (c) PRF[0..15]          : the 16-byte XOR keystream
 *
 * All multi-byte seed words are read LITTLE-ENDIAN (x86-64).
 *
 * Verified byte-exact against the official server binary
 * (snell-server-unpacked, PIE, stripped) and the gdb-extracted ground truth
 * for the test PSK below.
 *
 * Reversed from:
 *   fcn.0x39d90  init (BLAKE2b seed -> sub-states + scalar params)
 *   fcn.0x3aae0  block-length  (= 0x10 + range_map(prng_fixed(0x21,0x7053), lo, hi))
 *   fcn.0x3ab70  KSA / Fisher-Yates permutation  (first 16 entries -> S[])
 *   fcn.0x3ab10  KSA inner PRF
 *   fcn.0x3ac50  salt de-obfuscation driver
 *   fcn.0x38e50  keystream PRF  -> PRF[]
 *   fcn.0x38c90  wymix    fcn.0x38b70 splitmix64    fcn.0x38bb0 subseed
 *   fcn.0x39d70  prng_fixed = wymix(getter(sel), sel, seq=0, arg3)
 *   fcn.0x38b30  range_map
 *
 * Build / self-test:
 *   cc -O2 -o /tmp/snell_salt_ref snell_salt_prng.c && /tmp/snell_salt_ref
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ----------------------------------------------------------------------- */
/* BLAKE2b-256 (unkeyed), minimal reference (RFC 7693).                     */
/* ----------------------------------------------------------------------- */
static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};
static const uint8_t blake2b_sigma[12][16] = {
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
    {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
    {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
    {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
    {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
    {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
    {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
    {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
    {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
    {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
    {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
};
static uint64_t rotr64(uint64_t x, int c){ return (x>>c)|(x<<(64-c)); }
static uint64_t rotl64(uint64_t x, int c){ return (x<<c)|(x>>(64-c)); }
#define G(r,i,a,b,c,d) do{ \
    a=a+b+m[blake2b_sigma[r][2*i+0]]; d=rotr64(d^a,32); \
    c=c+d;                          b=rotr64(b^c,24); \
    a=a+b+m[blake2b_sigma[r][2*i+1]]; d=rotr64(d^a,16); \
    c=c+d;                          b=rotr64(b^c,63); }while(0)
static void blake2b_compress(uint64_t h[8], const uint8_t blk[128],
                             uint64_t t0, int last){
    uint64_t m[16], v[16];
    for(int i=0;i<16;i++){ uint64_t w=0; for(int j=0;j<8;j++) w|=(uint64_t)blk[8*i+j]<<(8*j); m[i]=w; }
    for(int i=0;i<8;i++){ v[i]=h[i]; v[i+8]=blake2b_IV[i]; }
    v[12]^=t0; v[13]^=0; if(last) v[14]^=~0ULL;
    for(int r=0;r<12;r++){
        G(r,0,v[0],v[4],v[8],v[12]); G(r,1,v[1],v[5],v[9],v[13]);
        G(r,2,v[2],v[6],v[10],v[14]);G(r,3,v[3],v[7],v[11],v[15]);
        G(r,4,v[0],v[5],v[10],v[15]);G(r,5,v[1],v[6],v[11],v[12]);
        G(r,6,v[2],v[7],v[8],v[13]); G(r,7,v[3],v[4],v[9],v[14]);
    }
    for(int i=0;i<8;i++) h[i]^=v[i]^v[i+8];
}
/* out must be 32 bytes */
static void blake2b256(uint8_t out[32], const uint8_t *msg, size_t len){
    uint64_t h[8]; for(int i=0;i<8;i++) h[i]=blake2b_IV[i];
    h[0]^=0x01010000 ^ (uint64_t)0 /*keylen*/ ^ (uint64_t)32 /*outlen*/;
    uint8_t blk[128]; uint64_t t=0; size_t off=0;
    while(len-off>128){ memcpy(blk,msg+off,128); off+=128; t+=128; blake2b_compress(h,blk,t,0); }
    size_t rem=len-off; memset(blk,0,128); memcpy(blk,msg+off,rem); t+=rem;
    blake2b_compress(h,blk,t,1);
    for(int i=0;i<32;i++) out[i]=(uint8_t)(h[i/8]>>(8*(i%8)));
}

/* ----------------------------------------------------------------------- */
/* PRNG primitives (shared with the shaping PRNG).                          */
/* ----------------------------------------------------------------------- */
static uint64_t rd_seedword(const uint8_t seed[32], int i){
    uint64_t w=0; for(int j=0;j<8;j++) w|=(uint64_t)seed[8*i+j]<<(8*j); return w;
}

/* splitmix64 finalizer (fcn.0x38b70) */
static uint64_t splitmix64(uint64_t x){
    x ^= x>>30; x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x>>27; x *= 0x94d049bb133111ebULL;
    x ^= x>>31; return x;
}

/* sub-seed generator (fcn.0x38bb0): subseed(idx,K) using seed words S0..S3 */
static uint64_t subseed(const uint8_t seed[32], uint32_t idx, uint64_t K){
    uint64_t S0=rd_seedword(seed,0);
    uint64_t S1=rd_seedword(seed,1);
    uint64_t S2=rd_seedword(seed,2);
    uint64_t S3=rd_seedword(seed,3);
    uint64_t x = ((uint64_t)idx * 0xd6e8feb86659fd93ULL)
               ^ (K + 0xa0761d6478bd642fULL)
               ^ S0
               ^ (S1 + 0x9e3779b97f4a7c15ULL)
               ^ rotl64(S2, 17)
               ^ rotr64(S3, 11);
    return splitmix64(x);
}

/* wymix (fcn.0x38c90): args used as 32-bit (zero-extended).
 *   rcx = a4*C_A + C_B ;  rsi = a2*GR ;  rdx = a3*C_C + C_D
 *   ret = fold32( splitmix64( a1 ^ rcx ^ rsi ^ rdx ) )                     */
static uint32_t wymix(uint64_t a1, uint32_t a2, uint32_t a3, uint32_t a4){
    uint64_t rcx = (uint64_t)a4 * 0x589965cc75374cc3ULL + 0x33a213ec50ffe2e9ULL;
    uint64_t rsi = (uint64_t)a2 * 0x9e3779b97f4a7c15ULL;
    uint64_t rdx = (uint64_t)a3 * 0xe7037ed1a0b428dbULL + 0x8f3907f7b2b80c35ULL;
    uint64_t s = splitmix64(a1 ^ rcx ^ rsi ^ rdx);
    return (uint32_t)(s ^ (s>>32));
}

/* range_map (fcn.0x38b30): lo + val % (hi-lo+1); returns lo if !(hi>lo).
 * NOTE: the value passes through fcn.0x38b10 which is an identity (x^k^k).  */
static uint32_t range_map(uint32_t val, uint16_t lo, uint16_t hi){
    if(!(hi>lo)) return lo;
    uint32_t span=(uint32_t)hi-(uint32_t)lo+1u;
    return lo + (val % span);
}

/* ----------------------------------------------------------------------- */
/* Salt context: the three sub-fields the salt path actually consumes,      */
/* plus the block-length bounds.  (All derived once at init.)               */
/*                                                                          */
/* Internally the server keeps a per-connection ctx; the salt routines are  */
/* called with base = ctx+0x60 and read, relative to that base:             */
/*    +0x88 -> qword  = salt PRNG sub-state  (== ctx+0xe8, subseed idx 3)    */
/*    +0xb2 -> byte   = KSA round count      (== ctx+0x112, in [1..4])       */
/*    +0xe2 -> byte   = keystream multiplier (== ctx+0x142, in [0x11..0xfb]) */
/* The block-length bounds live at absolute ctx+0xcc (lo) and ctx+0x130(hi).*/
/* ----------------------------------------------------------------------- */
typedef struct {
    uint8_t  seed[32];     /* BLAKE2b-256(PREFIX24 || PSK)                   */
    /* the seeded sub-states the salt selectors resolve to (fcn.0x39d90).    */
    uint64_t s_ctxA8;      /* ctx+0xa8  : subseed(0,  0x5d9217c083e64ab9)    */
    uint64_t s_ctxC0;      /* ctx+0xc0  : subseed(5,  0xb46c2e7d9a1538f1)    */
    uint64_t s_ctx60;      /* ctx+0x60  : subseed(16, 0xc9f4260b7d1e835a)    */
    uint64_t salt_state;   /* ctx+0xe8  : subseed(3,  0x3e8a91b52740f6cd)    */
    uint8_t  ksa_rounds;   /* ctx+0x112 : KSA Fisher-Yates round count       */
    uint8_t  multiplier;   /* ctx+0x142 : keystream byte multiplier          */
    uint16_t blk_lo;       /* ctx+0xcc  : block-length variable-part low     */
    uint16_t blk_hi;       /* ctx+0x130 : block-length variable-part high    */
} snell_salt_ctx;

/* getter (fcn.0x38c30) selector mapping (full table verified in
 * snell_shape_prng.c).  Salt path uses sel 0x0e,0x0f,0x11,0x12,0x21:
 *   sel 14,15 (0x0e,0x0f) -> ctx+0xa8  (s_ctxA8)
 *   sel 16..20 (0x11,0x12)-> ctx+0x60  (s_ctx60)
 *   sel 33    (0x21)      -> ctx+0xa8  (s_ctxA8)                            */
static uint64_t getter(const snell_salt_ctx *c, uint32_t sel){
    switch(sel){
        case 0: case 1: case 14: case 15: case 33: case 34: return c->s_ctxA8;
        case 3: case 16: case 17: case 18: case 19: case 20: return c->s_ctx60;
        default:                                             return c->s_ctxC0;
    }
}

/* prng_fixed (fcn.0x39d70): wymix(getter(sel), sel, seq=0, arg3) */
static uint32_t prng_fixed(const snell_salt_ctx *c, uint32_t sel, uint32_t arg3){
    return wymix(getter(c,sel), sel, 0u, arg3);
}

/* ----------------------------------------------------------------------- */
/* Initialization (fcn.0x39d90, salt-relevant subset).                      */
/* ----------------------------------------------------------------------- */
static const uint8_t PREFIX24[24] = {
 0x8d,0x41,0xa7,0x13,0x5c,0xe2,0x09,0xbb,0x70,0x2f,0xd6,0x94,
 0x33,0x18,0xc0,0x6e,0x4a,0x91,0x25,0xfd,0xb8,0x03,0x77,0xac};

void snell_salt_init(snell_salt_ctx *c, const uint8_t *psk, size_t psklen){
    memset(c,0,sizeof(*c));
    uint8_t buf[24+512]; memcpy(buf,PREFIX24,24); memcpy(buf+24,psk,psklen);
    blake2b256(c->seed, buf, 24+psklen);

    /* sub-states that the salt selectors resolve to (same constants as the
     * shape-PRNG init pipeline, fcn.0x39d90). */
    c->s_ctxC0    = subseed(c->seed, 5,    0xb46c2e7d9a1538f1ULL); /* ctx+0xc0  */
    c->s_ctxA8    = subseed(c->seed, 0,    0x5d9217c083e64ab9ULL); /* ctx+0xa8  */
    c->s_ctx60    = subseed(c->seed, 0x10, 0xc9f4260b7d1e835aULL); /* ctx+0x60  */
    c->salt_state = subseed(c->seed, 3,    0x3e8a91b52740f6cdULL); /* ctx+0xe8  */

    /* block-length bounds (ctx+0xcc lo, ctx+0x130 hi) */
    c->blk_lo = (uint16_t)range_map(prng_fixed(c,0x0e,0x7053), 0x10, 0x60);
    c->blk_hi = (uint16_t)(c->blk_lo +
                range_map(prng_fixed(c,0x0f,0x7053), 0x10, 0xa0));
    /* clamp pass (fcn.0x39d90 @0x3a535): hi=min(hi,0x80); lo=min(lo,hi). */
    if(c->blk_hi > 0x80) c->blk_hi = 0x80;
    if(c->blk_lo > c->blk_hi) c->blk_lo = c->blk_hi;

    /* KSA round count (ctx+0x112) and keystream multiplier (ctx+0x142) */
    c->ksa_rounds = (uint8_t)range_map(prng_fixed(c,0x11,0x51a7), 1, 4);
    c->multiplier = (uint8_t)range_map(prng_fixed(c,0x12,0x51a7), 0x11, 0xfb);
}

/* ----------------------------------------------------------------------- */
/* (a) block length (fcn.0x3aae0): 0x10 + range_map(prng_fixed(0x21,0x7053))*/
/* The selector 0x21 resolves to the SAME sub-state as 0x0e/0x0f.           */
/* ----------------------------------------------------------------------- */
uint32_t snell_salt_block_len(const snell_salt_ctx *c){
    uint32_t r = range_map(prng_fixed(c, 0x21, 0x7053), c->blk_lo, c->blk_hi);
    return 0x10u + r;
}

/* ----------------------------------------------------------------------- */
/* (b) S[0..15] : keyed Fisher-Yates permutation (fcn.0x3ab70 + 0x3ab10).   */
/*                                                                          */
/* inner PRF (fcn.0x3ab10): 3 args (state, salt, idx)                       */
/*   rdx = idx  * 0x589965cc75374cc3 + 0x33a213ec50ffe2e9                    */
/*   rdi = state ^ 0xdaa66d2c7ddf743f                                       */
/*   rdx ^= rdi                                                             */
/*   rsi = salt * 0xe7037ed1a0b428db + 0x8f3907f7b2b80c35                    */
/*   ret = fold32( splitmix64( rsi ^ rdx ) )                                */
/* (note: NO golden-ratio term, and state is pre-XORed with a constant.)    */
/* ----------------------------------------------------------------------- */
static uint32_t ksa_prf(uint64_t state, uint32_t salt, uint32_t idx){
    uint64_t rdx = (uint64_t)idx  * 0x589965cc75374cc3ULL + 0x33a213ec50ffe2e9ULL;
    rdx ^= (state ^ 0xdaa66d2c7ddf743fULL);
    uint64_t rsi = (uint64_t)salt * 0xe7037ed1a0b428dbULL + 0x8f3907f7b2b80c35ULL;
    uint64_t s = splitmix64(rsi ^ rdx);
    return (uint32_t)(s ^ (s>>32));
}

/* Fills perm[0..block_len-1].  S[i] = perm[i] for i<16. */
void snell_salt_permutation(const snell_salt_ctx *c, uint32_t block_len,
                            uint8_t *perm /* size block_len */){
    uint32_t n = block_len;
    for(uint32_t i=0;i<n;i++) perm[i]=(uint8_t)i;        /* identity */
    uint32_t R = c->ksa_rounds ? c->ksa_rounds : 1;      /* cmove to 1 if 0 */
    for(uint32_t round=0; round<R; round++){
        uint32_t salt = 0x51a7u + round;
        for(uint32_t j=0;j<n;j++){
            uint32_t h = ksa_prf(c->salt_state, salt, j);
            uint32_t pick = j + (h % (n - j));           /* j + h mod (n-j) */
            uint8_t t = perm[j]; perm[j]=perm[pick]; perm[pick]=t;
        }
    }
}

/* ----------------------------------------------------------------------- */
/* (c) PRF[0..15] : keystream (fcn.0x38e50, called with k = i, i=0..15).     */
/*   wmix = wymix(state=salt_state, a2=2, a3=0x51a7, a4=k)                   */
/*   ret  = (uint16)(k * multiplier) ^ wmix32   (only low 8 bits used)      */
/* ----------------------------------------------------------------------- */
static uint8_t keystream_byte(const snell_salt_ctx *c, uint32_t k){
    uint32_t wmix = wymix(c->salt_state, 2u, 0x51a7u, k);
    uint16_t mul  = (uint16_t)((uint16_t)(k & 0xff) * (uint16_t)c->multiplier);
    return (uint8_t)((mul ^ wmix) & 0xff);
}

void snell_salt_keystream(const snell_salt_ctx *c, uint8_t prf[16]){
    for(uint32_t i=0;i<16;i++) prf[i]=keystream_byte(c, i);
}

/* Convenience: compute all three deliverables at once. */
void snell_salt_params(const snell_salt_ctx *c, uint32_t *block_len_out,
                       uint8_t S[16], uint8_t PRF[16]){
    uint32_t bl = snell_salt_block_len(c);
    if(block_len_out) *block_len_out = bl;
    uint8_t perm[256];
    snell_salt_permutation(c, bl, perm);
    for(int i=0;i<16;i++) S[i]=perm[i];
    snell_salt_keystream(c, PRF);
}

/* de-obfuscate the salt given the wire block (size >= block_len). */
void snell_salt_deobfuscate(const snell_salt_ctx *c, const uint8_t *wire_block,
                            uint8_t real_salt[16]){
    uint32_t bl = snell_salt_block_len(c);
    uint8_t perm[256];
    snell_salt_permutation(c, bl, perm);
    for(int i=0;i<16;i++){
        uint8_t prf = keystream_byte(c, i);
        real_salt[i] = (uint8_t)(wire_block[perm[i]] ^ prf);
    }
}

/* one-shot: derive salt obfuscation params directly from a PSK. */
void snell_salt_from_psk(const uint8_t *psk, size_t psklen,
                         uint32_t *block_len, uint8_t S[16], uint8_t PRF[16]){
    snell_salt_ctx c; snell_salt_init(&c, psk, psklen);
    snell_salt_params(&c, block_len, S, PRF);
}

/* ----------------------------------------------------------------------- */
#ifdef SALT_SELFTEST
static void hexd(const char *t,const uint8_t *p,int n){
    printf("%s",t); for(int i=0;i<n;i++) printf("%02x ",p[i]); printf("\n");
}
/* PSK-agnostic self-test: derive the salt params for a USER-SUPPLIED PSK and verify
 * the obfuscate/de-obfuscate round-trip. No PSK or PSK-derived ground truth is
 * embedded in source — test PSKs live in the project memory, not here. */
int main(int argc, char **argv){
    if(argc<2){ fprintf(stderr,"usage: %s <psk>\n",argv[0]); return 2; }
    const char *psk = argv[1];
    snell_salt_ctx c;
    snell_salt_init(&c,(const uint8_t*)psk,strlen(psk));

    uint32_t bl; uint8_t S[16], PRF[16];
    snell_salt_params(&c,&bl,S,PRF);

    printf("seed = "); for(int i=0;i<32;i++) printf("%02x",c.seed[i]); printf("\n");
    printf("salt_state=%016llx ksa_rounds=%u mult=0x%02x blk_lo=%u blk_hi=%u\n",
        (unsigned long long)c.salt_state,c.ksa_rounds,c.multiplier,c.blk_lo,c.blk_hi);
    printf("block_len = %u\n", bl);
    hexd("S   = ", S, 16);
    hexd("PRF = ", PRF, 16);

    /* round-trip check: build a wire block from a known salt via the inverse
       mapping (wire[S[i]] = salt[i] ^ PRF[i]), then de-obfuscate and confirm. */
    uint8_t known_salt[16]; for(int i=0;i<16;i++) known_salt[i]=(uint8_t)(0xA0+i);
    uint8_t wire[256]; for(uint32_t i=0;i<bl;i++) wire[i]=(uint8_t)(i*7+3);
    for(int i=0;i<16;i++) wire[S[i]]=(uint8_t)(known_salt[i]^PRF[i]);
    uint8_t got_salt[16]; snell_salt_deobfuscate(&c, wire, got_salt);
    int rt_ok = !memcmp(got_salt, known_salt, 16);

    printf("de-obfuscation round-trip:  %s\n", rt_ok?"PASS":"FAIL");
    return rt_ok?0:1;
}
#endif
