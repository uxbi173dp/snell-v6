# Snell v6 (b3) — Complete Protocol Specification

Reverse-engineered from the official Snell **server** binary `snell-server` v6.0.0b3
(stripped static PIE, x86-64) and verified end-to-end against a live server. This is a
self-contained client-oriented spec: everything here is implemented in this directory and
verified on a remote box across **three different PSKs** (see §15).

b3 added a **`mode` setting** (`default` | `unshaped` | `unsafe-raw`; §1.1). The protocol below
describes **`default`** mode, which is **byte-identical to b2 on the wire** — live-verified: the
client's predicted s→c inter-pad length matches the b3 server *exactly on every record including the
first*, across small and large payloads (`-DIPL_VERIFY`, 0 mismatches), and the unmodified b2 client
drives a b3 default server end-to-end. (A static b2↔b3 diff suggested b3 refactored the first-record
shaping path internally; the live check shows no resulting on-wire change, so it is **not** mirrored
in the client.) The other two modes are deltas off this, given in §1.1.

> Status legend: ✅ verified end-to-end · 🔎 verified by disassembly · ⚠️ understood, not implemented

All multi-byte integers in the *crypto/PRNG* layer are **little-endian** (x86-64 word reads).
All multi-byte integers on the *wire* (ports, lengths in records) are **big-endian** unless noted.

---

## 1. Overview

A Snell v6 session is a single TCP connection from client → server. There is no TLS/HTTP
obfuscation layer (v6 dropped it); instead every session is **traffic-shaped** by a
per-PSK *profile* deterministically derived from the PSK. The wire is:

```
client → server:  [client salt block] [chunk 0] [chunk 1] ...
server → client:  [server salt block] [chunk 0] [chunk 1] ...
```

Each `chunk` is an AEAD-protected, shaped frame carrying a *control record* + a *payload
record* (§7). Chunk 0 c→s carries the **request header** (target + command). The first s2c
payload byte is a **status** code.

The whole construction is keyed by:
- a **profile** (≈42 shaping parameters) — deterministic from the PSK (§3);
- a **salt obfuscation** scheme — deterministic from the PSK (§4);
- a **session key** — Argon2id(PSK, per-direction salt) (§2.5, §12);
- **AES-128-GCM** record encryption (§2.6).

---

## 1.1 Protocol modes (b3 `mode` setting)  ✅

b3 adds a `mode` setting (server config `mode = …`; client `--mode …`) — **client and server must
match**. It is a pure both-directions wire switch: the request header (§6) and the lazy-status reply
(§5, §11) are mode-independent; only the salt encoding and which framing/crypto layers run differ.
Mode is **not** derived from the PSK (it is out-of-band config). Enum: `default=0, unshaped=1,
unsafe-raw=2` (the server stores it per-connection and, for non-default, never builds the PSK profile).

| layer | `default` | `unshaped` | `unsafe-raw` |
|---|---|---|---|
| salt (§4) | obfuscated scatter block (`salt_block_len`) | **raw 16 bytes** | **none** |
| session key | Argon2id(PSK, salt) | Argon2id(PSK, salt) | **none** |
| record crypto | AES-128-GCM | AES-128-GCM | **plaintext** |
| control record | sealed 23 B, AAD = prefix_pad | sealed 23 B, **empty AAD** | — (cleartext header) |
| prefix_pad (§7) | `prefix_pad_len(seq)` | **0** | — |
| inter_pad (§7) | `inter_pad_len(…)` | **0** | — |
| de-interleave (§8) | yes | no (pad_len 0) | no |
| pad content (§8.1) | yes | no | no |
| chunk ramp | profile ramp | flat, ≤ `0x3fff`/rec | flat, ≤ `0x3fff`/rec |

**`unshaped`** ≈ Snell v3: AES only, so after the raw salt the stream is all ciphertext+tags (looks
random). It is *exactly* the default framing (§7) with `prefix_pad_len = inter_pad_len = 0` — both
AEAD seals then use empty AAD and de-interleave is a no-op — plus a raw 16-byte salt instead of the
obfuscated block. Per-direction key derivation, nonces (2/record), and control/payload sealing are
unchanged.

**`unsafe-raw`** forwards plaintext (use only inside another secure tunnel): after TCP connect the
client sends **no salt and derives no key**; every record is a cleartext length-prefixed frame:
```
[0]    0x04            # frame type (DATA)
[1..2] 0x00 0x00
[3..4] 0x00 0x00
[5..6] payload_len (BE16, ≤ 0x3fff)
[7..]  payload (cleartext)
```
The first c→s frame's payload is the request header (§6); the first s→c frame's payload still leads
with the status byte (§5, §11). A zero-length frame signals write-EOF (half-close).

Per-record payload cap is `0x3fff` (16383 bytes) for both `unshaped` and `unsafe-raw`.

---

## 2. Cryptographic & PRNG primitives

### 2.1 Seed
```
PREFIX24 = 8d 41 a7 13 5c e2 09 bb 70 2f d6 94 33 18 c0 6e 4a 91 25 fd b8 03 77 ac
seed32   = BLAKE2b-256( PREFIX24 || PSK )        # unkeyed, no salt, no personalization
```

### 2.2 splitmix64
```
splitmix64(x): x ^= x>>30; x *= 0xbf58476d1ce4e5b9;
               x ^= x>>27; x *= 0x94d049bb133111eb;
               x ^= x>>31; return x
```

### 2.3 Sub-state seeding (`subseed`)
`Si = LE u64 word i of seed32` (i = 0..3).
```
subseed(idx, K) = splitmix64( idx*0xd6e8feb86659fd93
                            ^ (K + 0xa0761d6478bd642f)
                            ^ S0
                            ^ (S1 + 0x9e3779b97f4a7c15)
                            ^ rotl64(S2,17)
                            ^ rotr64(S3,11) )
```
Seven sub-states are precomputed (offsets are the server's `ctx+…` fields):

| field      | subseed(idx, K)                         | role                         |
|------------|------------------------------------------|------------------------------|
| `s_ctxA8`  | `subseed(0,  0x5d9217c083e64ab9)`        | getter target                |
| `s_ctx120` | `subseed(2,  0xa71f0c54d8396e2b)`        | getter target (sel 2)        |
| `s_ctxE8`  | `subseed(3,  0x3e8a91b52740f6cd)`        | **salt PRNG sub-state**      |
| `s_ctxC0`  | `subseed(5,  0xb46c2e7d9a1538f1)`        | getter default               |
| `s_ctx60`  | `subseed(16, 0xc9f4260b7d1e835a)`        | getter target                |
| `s_ctx108` | `subseed(21, 0x62d0b5e19c4a783f)`        | getter target                |
| `s_ctx138` | `subseed(28, 0x917b3c48e6a205d4)`        | getter target                |

### 2.4 The shaping PRNG
```
wymix(a, sel, seq, round):
    rcx = round*0x589965cc75374cc3 + 0x33a213ec50ffe2e9
    rsi = sel  *0x9e3779b97f4a7c15
    rdx = seq  *0xe7037ed1a0b428db + 0x8f3907f7b2b80c35
    s   = splitmix64(a ^ rcx ^ rsi ^ rdx)
    return (u32)(s ^ (s>>32))

prng(sel, seq, round) = wymix( getter(sel), sel, seq, round )
range_map(v, lo, hi)  = (hi>lo) ? lo + v % (hi-lo+1) : lo
```
`getter(sel)` resolves a selector to one of the sub-states (decimal `sel`):

| sel (dec)                        | sub-state |
|----------------------------------|-----------|
| 0, 1, 14, 15, 33, 34             | `s_ctxA8` |
| 2                                | `s_ctx120`|
| 3, 16, 17, 18, 19, 20            | `s_ctx60` |
| 21, 22, 23, 24, 25, 26, 38, 39   | `s_ctx108`|
| 28, 29, 30, 31, 32, 35, 36, 37   | `s_ctx138`|
| (default)                        | `s_ctxC0` |

### 2.5 KDF — Argon2id (libsodium `crypto_pwhash`)
```
key32 = Argon2id( pwd = PSK, salt = real_salt[16],
                  opslimit = 3, memlimit = 8192 bytes, alg = ARGON2ID13 )
AES-128 key = key32[0..15]          # first 16 bytes
```

### 2.6 AEAD — AES-128-GCM (OpenSSL EVP)
- Tag 16 bytes, appended inline: record = `ciphertext || tag`.
- Nonce: **12-byte little-endian counter**, starts at 0, **+1 per AEAD op** (`sodium_increment`).
- Two independent directions, each its own key and its own nonce counter from 0.

---

## 3. Profile = f(PSK)

The profile is deterministic per PSK (confirmed identical across reconnects). Scalar
shaping params, all via `prng(sel, 0, 0)` then `range_map`:

| param          | derivation                                   | range        |
|----------------|----------------------------------------------|--------------|
| `pad_lo`       | `range_map(prng(0x0e), 8, 0x50)`             | [8, 80]      |
| `pad_hi`       | `pad_lo + range_map(prng(0x0f), 0x10, 0xa0)` | then `hi=min(hi,0x80); lo=min(lo,hi)` |
| `deint_mode`   | `prng(0x10) % 3`                             | {0,1,2}      |
| `R` (rounds)   | `range_map(prng(0x11), 1, 3)`                | [1, 3]       |
| `stride_base`  | `range_map(prng(0x12), 2, 0x0d)`             | [2, 13]      |
| `phase_seed`   | `range_map(prng(0x13), 0, 0x0f)`             | [0, 15]      |
| `deint_block_len`      | `range_map(prng(0x14), 8, 0x40)`             | [8, 64]      |

Per-chunk shaping lengths (direction-independent; each side keeps its own `seq` counter):

```
prefix_pad_len(seq) = range_map( prng(0x21, seq, 0), pad_lo, pad_hi )   # REQUIRED (both dirs)
inter_pad_len       = pad-to-target-size pipeline (see §8.1)            # NOT [pad_lo,pad_hi]
```
The inter_pad length is a multi-stage pad-to-target-size pipeline (sel 0x07/0x08 base bounds +
sel 0x1e/0x1f size tables + refinement), depending on the chunk's payload length and the bytes
already emitted. The server reads pad_len from the control record, so any value round-trips;
matching the server's (large, ~hundreds of bytes) range is stealth-only — see §8.1.

The remaining profile selectors drive **pad-content distribution** (§8.1), **chunk-size
selection**, and **inter-pad cadence**. Key ones (offsets are `profile+…`; all `prng(sel,0,r)`):
`0x06 r0`→pad-content mode `&3` (0xfc); `0x06 r1..r6`→mode params (0x116,0x147,0xd4,0x136,0x104,
0x148); `0x0c`/`0x0d`→mode-0 params (0xb8,0x12a); `0x15`→chunk-size mode `%3` (0x118),
`0x16`/`0x17`/`0x18`→chunk min/max/grow (0xc8,0xf8,0x128); `0x09`/`0x0a`/`0x0b`→inter-pad cadence
(0x146,0xf6,0x12c). Selectors `0x1a`/`0x1e`/`0x1f` are 8-entry size tables. (Chunk-size selection
and cadence are server-side shaping the client need not mirror for interop; pad content matters
for stealth — see §8.1.)

---

## 4. Salt obfuscation = f(PSK)

The 16-byte real salt is **scattered** inside a larger wire "salt block" of length
`block_len`, with a per-PSK permutation `S[]` and XOR keystream `PRF[]`:

```
de-obfuscate:  real_salt[i] = wire_block[ S[i] ] ^ PRF[i]      (i = 0..15)
  obfuscate:   wire_block = random[block_len]; wire_block[ S[i] ] = real_salt[i] ^ PRF[i]
```

The salt path uses a *fixed-arg* PRNG `prng_fixed(sel, arg3) = wymix(getter(sel), sel, 0, arg3)`
and its **own** length bounds (distinct from the shaping `pad_lo/hi`):

```
salt_state = s_ctxE8 = subseed(3, 0x3e8a91b52740f6cd)
blk_lo  = range_map(prng_fixed(0x0e, 0x7053), 0x10, 0x60)
blk_hi  = blk_lo + range_map(prng_fixed(0x0f, 0x7053), 0x10, 0xa0);  hi=min(hi,0x80); lo=min(lo,hi)
ksa_rounds = range_map(prng_fixed(0x11, 0x51a7), 1, 4)
multiplier = range_map(prng_fixed(0x12, 0x51a7), 0x11, 0xfb)
block_len  = 0x10 + range_map(prng_fixed(0x21, 0x7053), blk_lo, blk_hi)
```

**`S[]`** = first 16 entries of a keyed Fisher-Yates permutation of `[0..block_len)`:
```
ksa_prf(state, salt, idx):
    rdx = idx*0x589965cc75374cc3 + 0x33a213ec50ffe2e9
    rdx ^= (state ^ 0xdaa66d2c7ddf743f)
    rsi  = salt*0xe7037ed1a0b428db + 0x8f3907f7b2b80c35
    return fold32( splitmix64(rsi ^ rdx) )

perm = identity[0..block_len)
for round in 0..ksa_rounds-1:
    salt = 0x51a7 + round
    for j in 0..block_len-1:
        pick = j + ksa_prf(salt_state, salt, j) % (block_len - j)
        swap(perm[j], perm[pick])
S[i] = perm[i]   for i in 0..15
```

**`PRF[]`** keystream:
```
PRF[i] = ( (u8)((i & 0xff) * multiplier) ^ wymix(salt_state, 2, 0x51a7, i) ) & 0xff
```

(For the canonical test PSK this yields `block_len = 87`. Sending an all-zero 87-byte block
makes the server derive the fixed real salt `7b 82 5e 7c 55 38 f0 1b ac b1 45 00 6f 3c 8e e7`
— a useful single-PSK shortcut, but the client implements the general derivation above.)

---

## 5. Session handshake

**Client → server (chunk 0):** *(default mode; see §1.1 for `unshaped`/`unsafe-raw`)*
1. Pick a random 16-byte `real_salt`; build the obfuscated `salt block` (§4).
   `key_cs = Argon2id(PSK, real_salt)`. (`unshaped`: send the raw 16-byte salt, no block;
   `unsafe-raw`: no salt, no key.)
2. Send: `[salt block]` then `[chunk 0]` whose payload is the **request header** (§6),
   encoded with the chunk framing (§7), `seq = 0`, nonces 0/1.

**Server → client:**
1. The server emits its **own** obfuscated salt block first. Client de-obfuscates with the
   *same* per-PSK `S[]/PRF[]` → `server_real_salt`; `key_sc = Argon2id(PSK, server_real_salt)`.
2. Then shaped chunks. The **first s2c payload's leading byte is a status code**:
   `0x00` = tunnel established (`SN_REPLY_TUNNEL`), non-zero = error (e.g. `0x02`
   `SN_REPLY_ERROR`). The client strips this one status byte from the first payload.

---

## 6. Request header (payload of c→s chunk 0)

```
[0]      version = 0x01
[1]      cmd
[2]      client_id_len  (cid)        # this client sends 0
[3..]    client_id[cid]
 cmd 0x01 (CONNECT) / 0x05 (CONNECT + half-close):
   [..]  host_len
   [..]  host[host_len]              # domain or literal IP string
   [..]  port (BE16)
 cmd 0x06 (native UDP):  -- NO host/port --
```

### Command set & dispatch  🔎 (server fn @0x3fb34)
```
cmp cmd, 6            ; == 0x06  -> native UDP        (jumps before host/port parse)
ecx = cmd & 0xFB; cmp ecx,1; jne UNKNOWN   ; accepts 0x01 and 0x05  (bit 0x04 = UDP flag)
cmp cmd, 5           ; == 0x05  -> UDP-over-TCP  (sets ctx+0x271, then CONNECT path)
                     ; else     -> 0x01 CONNECT
```
| cmd  | meaning                    | header host/port | status                    |
|------|----------------------------|------------------|---------------------------|
| 0x00 | (none)                     | —                | → E06 "unknown command"   |
| 0x01 | CONNECT (TCP)              | yes              | ✅ implemented & verified  |
| 0x05 | CONNECT + half-close (TCP) | yes              | ✅ implemented & verified  |
| 0x06 | native UDP                 | **no**           | ✅ implemented & verified  |

**cmd 0x05 is NOT "UDP-over-TCP"** (a common misnomer / the name in some docs). Verified by
disasm + empirically: it takes the **exact CONNECT (TCP) relay path** as 0x01, byte-for-byte
identical framing (raw stream in chunk payloads; first s→c byte = status 0x00/0x02), with one
difference — `0x3ffce` sets `ctx+0x271=1`, read only in the outgoing-socket UV_EOF handler
(`0x3f20e`): the **target's TCP half-close does not abort the session**. It never touches the
0x06 UDP codec. Client: issue it exactly like 0x01 (the handshake already carries host/port for
cmd≠0x06); selected via `--connect-cmd 5`. (Full half-close *relay* in the proxy front-end —
honoring a local client half-close — is a separate enhancement; cmd coverage itself is complete.)

There is **no PING request command**; idle handling is socket-level (TCP keepalive).

---

## 7. Chunk framing  ✅

Every chunk (both directions), `seq` = 0,1,2,… per direction:

```
[ prefix_pad ]      prefix_pad_len(seq) random bytes   — AAD of the control record
[ control rec ]     AES-128-GCM( nonce = 2*seq )  of 7-byte plaintext, +16 tag = 23 bytes
[ inter_pad ]       pad_len bytes                       — AAD of the payload record
[ payload rec ]     AES-128-GCM( nonce = 2*seq+1 ) ct||tag = payload_len + 16 bytes
```

Control plaintext (7 bytes):
```
[0] type = 0x04        # data chunk
[1] 0x00
[2] 0x00
[3..4] pad_len      (BE16)   # = inter_pad length
[5..6] payload_len  (BE16)
```

**De-interleave** (§8) is applied to the `(inter_pad || payload_ct||tag)` region — i.e.
buffers `A = inter_pad (pad_len)` and `B = payload ct||tag (payload_len+16)`.

Order of operations:
- **send (encode):** seal payload with `AAD = inter_pad` → `ct||tag`; then *interleave* `(A,B)`.
- **recv (decode):** *de-interleave* `(A,B)`; then open payload with `AAD = de-interleaved inter_pad`.

`pad_len = 0` is legal (server reads it from the control record): no inter_pad, no
de-interleave. The client defaults to shaped `pad_len = inter_pad_len(seq)` for stealth.
In **`unshaped`** mode this framing is used with `prefix_pad = inter_pad = 0` (empty-AAD seals);
**`unsafe-raw`** replaces the whole sealed frame with a cleartext length-prefixed frame (§1.1).

---

## 8. Traffic shaping — de-interleave (involution)  ✅ modes 0/1/2

`L = min(lenA, lenB)`. Because every round is a self-inverse over a partition of the byte
positions, the *same* routine both permutes (send) and de-permutes (recv).

### mode 1 — block-swap (length-derived; `stride_base`/`phase_seed` unused)
```
P = max(deint_block_len, 1);  nblk = L / P
for k in 0..R-1:
    parity = k & 1
    for i = parity; i < nblk; i += 2:
        swap the P-byte blocks  A[i*P .. i*P+P-1]  <->  B[i*P .. i*P+P-1]
```

### modes 0 & 2 — stride-swap
```
for r in 0..R-1:
    stride = max(stride_base + (r % 3), 1)
    phase  = (mode==2) ? (prng(3, seq, r) + phase_seed) % stride       # data-PRNG phase
                       : (phase_seed % stride)                          # mode 0: constant phase
    for j = phase; j < L; j += stride:  swap A[j] <-> B[j]
```

(`deint_block_len` selector is `0x14`; verified general across PSKs: PSK1→44, PSK2→49, PSK3→44.)

## 8.1 Pad CONTENT shaping (DPI resistance)  ✅

Padding bytes (prefix_pad, inter_pad, salt-block filler) are **plaintext on the wire**. The server
fills them via `fill_pad` (RVA 0x39750): a deterministic base keystream `stream_fill(sel=0,seq,len)`
then a per-byte transform by `pad_mode = prng(0x06,0,0)&3`. The **receiver never validates pad
content** (disasm @0x3b3f0 + empirical) — it's stealth-only — but the pad is **deterministic per
(PSK, seq, len)**, so a real client emits fixed bytes per position; random fill is distinguishable.
**This client reproduces `stream_fill` + all four mode transforms byte-exactly**, so its c→s pad is
bit-for-bit identical to a real client's (verified: my pad == the server's actual pad, 0 mismatches).

`stream_fill(sel,seq,len)`: `S=(0xb57de1f3f82cb33f+seq*0xd6e8feb86659fd93)^(sel*0xa24baed4963ee407)
^(len*0x165667b19e3779f9+0x0d4cd3e7b14a36d7)^getter(sel)`; per 8-byte block `S+=0x9e3779b97f4a7c15`,
emit LE `splitmix64(S)`. getter(0)=s_ctxA8 (pad), getter(2)=s_ctx120 (mode-3 scratch). The four modes
(all BYTE-EXACT, validated live; see `PADSHAPE_RE.md` for the GF table + full transforms):
- **mode 2** (PSK1/PSK2): nibble-mix decimal — `low=((a&0xf)+(i&1)+off)%10; high=((a>>4)+(i&3)+3)&0xf`.
- **mode 1** (PSK3): 3-class histogram — class1 `map_byte(a+i,0x20,0x7e)`, class2 `map_byte(a^i,0x80,0xbf)`, class3 `map_byte(a+i*7,0xc0,0xff)`.
- **mode 0**: GF-table byte-walk (128-byte table @rodata 0x1f5f80, `rol8`).
- **mode 3**: periodic alphabet (period=prng(0x06,0,6)[7,0x17], base=prng(0x06,0,5)[1,8]).

**Verified BYTE-EXACT** vs the live server's pad for all 4 modes (a mode-2, mode-1, mode-0, and
mode-3 PSK respectively): 0 mismatches each. (Test PSKs are recorded in the project memory, not here.)

**inter_pad LENGTH** (pad-to-target-size) — **BYTE-EXACT** ✅ (`snell_inter_pad.c`, builder @0x3b020).
Three independent reconstructions agree (2 RE + 1 stage2-focused live capture) across 2880 differential
inputs + 2117 live records + 6 acceptance points + 37 live captures covering `inter_jitter_mode`∈{0,1,2}; a local
differential harness confirms 35,280 cases, 0 mismatches. The pipeline:
```
cadence(seq,payload): field09(sel 0x09,[2,8]) > seq → 1            # early chunks always pad
                      else cadence_period≠0 && seq%cadence_period==0   → 1       # periodic, ALL payloads
                      else payload≠0 → (payload ≤ cadence_payload_max)       # small payloads
                      else 0
   (the periodic seq%cadence_period rule fires regardless of payload size — verified against the
    live server's actual pad_len over 7,026 s→c records / 3 PSKs incl. inter_jitter_mode==2, 0 mismatches.)
stage1  = cadence ? range_map(prng(0x22,seq,payload), inter_lo, inter_hi) : 0
total   = stage1 + (payload+0x17) + prefix_len(seq) + (payload?0x10:0) + prior
stage2(total): total>0x5b3 → (total≤0xfffe ? total : 0xffff)   # either way total≥stage2 → inter=stage1
   else: r10 = (inter_warmup_seqs>seq) ? inter_sz_seq[seq] : inter_sz_rand[prng(0x23,seq,total)%8]
         if inter_jitter_mode==2: r10 += (prng(0x24,seq,0) % (2*inter_jitter_span+1) - inter_jitter_span)   [floor 1]
         r11 = min(0x2da, inter_target_pct*total/100)
         prng(0x23,seq,r11)&1 ? r10 -= r11>>1 : r10 += r11
         while (u16)r10 < total: tv=inter_sz_rand[prng(0x25,seq,r10)%8];
                                 r10 = (r10>=tv) ? r10+inter_hi : tv     [overflow→0xffffffff]
inter   = (total < stage2) ? stage1 + min(0x2da, stage2-total) : stage1   → (u16), range 0..0x5b4
```
**prefix_len bounds note:** the binary stores the prefix-pad LOW bound at struct `[0x11c]` (sel 0x0e)
and the HIGH bound at `[0xba]` (sel 0x0f) — the reverse of the leaked header field names;
`prefix_len(seq) = range_map(prng(0x21,seq,0), pad_lo=[0x11c], pad_hi=[0xba])`. **prior** = the bytes
already emitted in the same write before this record: `salt_block_len` for the first c→s record (it
shares the salt-block buffer) and **0 for every later record** — verified on the wire, prior does NOT
accumulate within a build pass. The receiver reads `pad_len` from the control record and never
recomputes it, so length is stealth-only (correctness-neutral); but matching it removes a c→s tell.
Shaping is on by default; `--no-shape` disables outbound shaping. `pad_test.c` checks pad bytes /
inter lengths (`pad_test <psk> inter <seq> <payload> <prior>`).

---

## 9. TCP CONNECT data relay  ✅

After handshake, application bytes are carried as payloads of successive chunks. The
per-record payload cap is the **byte-exact chunk-size ramp** (`sn_shape_chunk_len`, server
`choose_chunk`@0x39610 + `update_chunk_state`@0x39700): a running target seeded to `chunk_min`
on a fresh stream (chunk 0 = wire record 0), ramping by `chunk_grow` (sel 0x18, [0x400,0x1000]
clamp 0xb68) per record and saturating at `chunk_max`. Per record:
```
tgt = target ? target : chunk_min
mode 0: picked = tgt
mode 1: picked = chunk_hist[ prng(0x26, seq, tgt) % 8 ]
mode 2: picked = max(0x40, tgt + (prng(0x27, seq, tgt) % (2*chunk_jitter+1) - chunk_jitter))
size = max(0x40, min(picked, chunk_max))
emit  min(size, bytes_available);  then target = min(target + chunk_grow, chunk_max)
```
The receiver reads `payload_len` from the control record and accepts any split, so chunk size
is stealth-only (correctness-neutral); matching the ramp removes a c→s tell. Validated vs the
server's s→c sizes over 15,908 records (0 over-predictions); the PSK1 mode-1 picks reproduce the
real server's observed chunk sizes (7740/7821/11029/11832/12115/12932/13546) exactly.

**One write per pass.** The server's response builder (RVA 0x3b990) concatenates ALL records of
one build pass into a single contiguous buffer and emits them in **one `uv_write` (nbufs=1**, caller
0x3eff5), not a record-per-write scatter. The client mirrors this: `sn_tunnel_write` encodes every
chunk of a single call into one buffer and does one `tun_send` — matching the server's wire
segmentation and saving a syscall per chunk. `prior` stays 0 for every record in the pass (it does
NOT accumulate — wire-verified; see §8.1).

**Idle-reset** (server RVA 0x3b990 entry → 0x3bb40). At the start of each build pass the server reads
`time(NULL)` (whole seconds; `call 0x36560`, GOT-resolved to libc `time`) and if
`now − last_pass_seconds > idle_gap_s` (sel 0x1b → field [0x144] = `range_map(prng(0x1b,0,0),0xc,0x5a)`,
in **seconds**) it resets the running target to `chunk_min` BEFORE emitting any record, then stores
`now`; `seq` is NOT reset. The client mirrors this at the top of `sn_tunnel_write` using `time(NULL)`
(NOT `uv_now()` ms — integer-second granularity matters for the boundary). Live-verified: the reset
fires at exactly `> idle_gap_s` (boundaries 48|49 s and 17|18 s on two PSKs, matching field [0x144]),
and a real upload across a 14 s gap (PSK idle_gap_s=12) reset to `chunk_min` and round-tripped
byte-exact. Stealth-only (the server accepts any split); matching it removes a post-idle c→s tell.
(Mode-1 histogram modulus is the constant field [0x12e] = 8, confirmed live — 97% exact-match on
8,284 mode-1 records — so `chunk_hist[… % 8]` is correct.)

Server→client payloads are de-shaped and decrypted, the first one's status byte stripped, and
delivered to the local client. Verified: HTTPS browsing, byte-perfect 7 MB downloads AND 7 MB
c→s upload echo round-trips (all 3 PSKs × cmd 0x01/0x05), ASan+UBSan-clean, bounded memory
(backpressure).

---

## 10. UDP relay (cmd 0x06)  ✅

Native UDP multiplexes datagrams to many destinations over **one** Snell connection (the
server binds a single dual-stack UDP socket). Request header is `[01][06][cid_len][cid]`
(no host/port); the server replies with a 1-byte `0x00` ack (carried as the first chunk
payload → consumed as the status byte). Thereafter **one datagram = one chunk payload**
(the chunk boundary delimits the datagram; no inner length field):

```
client → server datagram:
  [0x01][name_len][ name(name_len)  |  (name_len==0: atyp + addr) ][port BE16][payload]
       atyp 0x04 = IPv4 (4-byte addr),  atyp 0x06 = IPv6 (16-byte addr)

server → client datagram (ASYMMETRIC — no leading 0x01):
  [atyp 0x04/0x06][addr 4/16][port BE16][payload]
```

The client front-end maps this to **SOCKS5 UDP ASSOCIATE** (§13). Verified: real DNS
queries to 8.8.8.8/1.1.1.1/8.8.4.4:53 and 4-datagram multiplexing on a single association.

---

## 11. Error replies & status  ✅

Two distinct server reactions:
- **Handshake/parse errors** → the server **silently closes the TCP** (no status frame). The
  client sees EOF and tears down. Triggers (all WARN-logged server-side, abort-sender @0x3de10
  NOT used): `E01` (handshake AEAD auth fail = wrong PSK / corrupt control or payload, decryptor
  -1), `E05` (per-record AEAD/structural fail, decryptor -2), `E06` (bad version byte ≠ 0x01),
  `Unknown command` (cmd ∉ {0,1,5,6}), `Invalid request` (header length overruns plaintext),
  `getaddrinfo` start error, partial/EOF handshake. (`E02/E03/E04/E07` are VERBOSE "need-more-data"
  / teardown breadcrumbs, **not** errors.)
- **Post-connect tunnel errors** → AEAD frame `[0x02 opcode][status][len][ASCII reason]`. `0x02`
  is the constant frame opcode; the **real status is the next byte**. The first s→c reply opcode
  is `0x00` on success (then data) / `0x02` on error / `0x01` for a PING pong (cmd 0).

Status bytes (exhaustive — all abort-sender callers):

| status | reason            | trigger                                                    |
|--------|-------------------|------------------------------------------------------------|
| `0x64` | "DNS Failed"      | DNS resolution failure (bad/empty host)                    |
| `0x65` | "Remote EOF"      | **cmd 5** target sends EOF before any data                 |
| `0x01` | addr family       | EAFNOSUPPORT (errno table @0x1f6020, mapper 0x3bdb0)       |
| `0x02` | network is down   | ENETDOWN                                                   |
| `0x03` | network unreach.  | ENETUNREACH                                                |
| `0x04` | conn reset        | ECONNRESET                                                 |
| `0x05` | conn timed out    | ETIMEDOUT                                                  |
| `0x06` | conn refused      | ECONNREFUSED                                               |
| `0x08` | no route to host  | EHOSTUNREACH                                               |
| `0xFF` | uv_strerror       | any unmapped libuv errno (e.g. UV_EOF on a cmd-1 conn)     |

(`0x07` is never emitted.) The client always parses the frame — status+reason are logged and
exposed as `t->err_status`/`err_reason`, and the connection is torn down cleanly.

**Lazy status — why the local CONNECT reply is optimistic (REQUIRED, not a choice).** The server
emits **no standalone connect-ack**: the first s→c frame is `[0x00 || first target data]` on
success, or an error frame on failure. Verified empirically — a target that accepts but stays
silent produces *no* s→c byte at all (the `0x00` rides the first data). Consequently a SOCKS5/HTTP
proxy **cannot wait for a connect result before replying**: for any client-speaks-first protocol
(HTTP, TLS) that deadlocks — the local client awaits the reply, the reply would await the server's
first frame, the server awaits target data, and the target awaits the client's request. (Confirmed:
a `--strict-connect` "wait for status" mode was prototyped and made *all* HTTPS hang; it was
removed.) So the proxy replies **optimistically** the moment the handshake is sent.

Implication for error reporting: a target failure that the server reports *after* the optimistic
reply (the usual case for client-speaks-first targets) surfaces to the local client as a **clean
connection close**, not a specific code — `curl` sees "empty reply" rather than "connection
refused". The precise `snell_status_to_socks5()` mapping (0x01→0x08, 0x02/0x03→0x03, 0x04/0x06→0x05,
0x05→0x06, 0x08/0x64→0x04, else→0x01; HTTP front-end → `502`) is wired in and used for any failure
that arrives before the reply is sent (e.g. the server connection itself failing), but for
post-reply target failures it cannot retroactively change the SOCKS reply. This is an inherent
property of the Snell protocol, not a client limitation.

**Cipher/version are FIXED** — AES-128-GCM + version `0x01`, no negotiation (the ChaCha/AES-256
OpenSSL strings are dead, zero xrefs). There is **nothing to negotiate**; wrong version → E06 close.

---

## 12. Per-direction keys summary

| direction | salt source                          | key                                  | nonce ctr |
|-----------|--------------------------------------|--------------------------------------|-----------|
| c → s     | client's random real_salt (obfusc.)  | `Argon2id(PSK, client_real_salt)`    | from 0    |
| s → c     | server's salt block (client deobfusc)| `Argon2id(PSK, server_real_salt)`    | from 0    |

---

## 13. Client architecture (this directory)

| file                  | responsibility                                                        |
|-----------------------|-----------------------------------------------------------------------|
| `snell_crypto.{c,h}`  | Argon2id KDF, AES-128-GCM seal/open, params.                          |
| `snell_shape.{c,h}`   | profile derivation (PRNG), prefix/inter pad lengths, de-interleave 0/1/2, pad-content shaping (`sn_fill_pad`, modes 0–3). |
| `snell_salt.c`   | general salt obfuscation (`block_len`, `S[]`, `PRF[]`) + self-test.   |
| `pad_test.c`          | measures `sn_fill_pad` output distribution for a PSK (vs the server). |
| `snell_shape_prng.c`  | stand-alone shaping-PRNG reference + self-test (not linked).          |
| `snell_tunnel.{c,h}`  | libuv tunnel: async connect, handshake, chunk encode/decode, backpressure, datagram send. |
| `proxy.c`             | SOCKS5 (CONNECT + UDP ASSOCIATE) and HTTP CONNECT front ends.         |

Performance: async libuv, offset-based RX (no per-chunk `memmove`), **bidirectional** write-queue
backpressure (s→c: pause server reads when the local-client write queue >512 KB, resume <128 KB;
c→s: pause the local-client read when the tunnel's server-side write queue >512 KB, resume <128 KB
via the `on_tx_drain` callback), **per-direction AEAD context reuse** (the AES-128-GCM key schedule
is built once per direction and only the 12-byte nonce is reset per record, via `sn_aead_seal`/
`sn_aead_open`), graceful `uv_shutdown` drain on close. Outbound shaping default-on; `--no-shape`
disables it for raw throughput.

---

## 14. Disassembly reference (server, gdb load base `0x555555400000`)

| offset    | function                                                            |
|-----------|---------------------------------------------------------------------|
| `0x39d90` | profile init (BLAKE2b seed → sub-states + scalar params)            |
| `0x39a90` | Argon2id key derivation (called @0x3b803)                           |
| `0x38570` | AEAD seal/open (AES-128-GCM)                                        |
| `0x38e80` | de-interleave (read @0x3b69e / build @0x3b2c2)                      |
| `0x3aae0` | salt block length · `0x3ab70` Fisher-Yates · `0x38e50` PRF keystream · `0x3ac50` de-obfuscate |
| `0x3fb34` | request command dispatch (0x01/0x05/0x06)                          |
| `0x40013` | cmd 0x06 native-UDP setup · `0x40980` UDP socket bind              |
| `0x40a60` | UDP datagram decode (c→s) · `0x40380` UDP datagram encode (s→c)    |
| `0x3f86a` | session error E01                                                  |
| `0x39750` | `fill_pad` (pad content) · `0x39898` mode2 · `0x399b0` mode1 · `0x39920` mode0 · `0x397b0` mode3 |
| `0x39610` | chunk-size `choose_chunk` · `0x39700` `update_chunk_state` (ramp) · `0x39ae0` inter-pad cadence |
| `0x3b020` | per-record encoder (inter-pad `total`/`bp` composition) · `0x39b20` stage1 · `0x39b90`→`0x39bb0` stage2 · `0x395e0` prefix_len |
| `0x3b990` | response builder (concatenates a pass) → one `uv_write` @0x3eff5 (nbufs=1) · `0x3b3f0` RX parser |
| `0x3de10` | abort/error-frame sender (`[0x02][status][len][reason]`) · `0x3bdb0` errno→status mapper · `0x1f6020` errno table (17B) |
| `0x3ffce` | cmd 0x05 setup (`ctx+0x271=1` → CONNECT path) · `0x3f20e` half-close EOF gate |
| `0x38c30` | PRNG getter (jump table `0x1f5ee0`, sel 0..0x27) · `0x38c90` wymix · `0x38b70` splitmix · `0x38b30` range_map |

See `SELECTORS_RE.md` for the full selector→consumer map, `UDP_RE.md` for raw cmd-0x05/UDP
evidence, and `PADSHAPE_RE.md` for the pad-shaping RE.

---

## 15. Verification (remote box, 3 distinct PSKs, full shaping ON)

| PSK  | deint/pad/chunk mode | HTTPS | TCP dl 7 MB | TCP ul 7 MB echo | UDP DNS relay      | cmd 0x05 | error reply |
|------|----------------------|-------|-------------|------------------|--------------------|----------|-------------|
| PSK1 | deint 2 / pad 2 / chunk 1 | 301 | OK | OK | ancount=2, valid A | OK | graceful |
| PSK2 | deint 1 / pad 2 / chunk ? | 301 | OK | OK | ancount=2, valid A | OK | graceful |
| PSK3 | deint 1 / pad 1 / chunk 2 | 301 | OK | OK | ancount=2, valid A | OK | graceful |

- All downloads + 7 MB c→s upload echoes byte-perfect for **3 PSKs × {cmd 0x01, cmd 0x05}**;
  ASan+UBSan-clean on both download and the large-upload path (the buffers that previously sized
  inter_pad ≤0x2da were enlarged to hold the exact ≤0x5b4 range — `send_eof`/`sn_tunnel_write`/
  `send_datagram`/`send_handshake`). 50 MB stream byte-perfect at ~177 MB/s (shaped) / ~204 MB/s
  (unshaped); peak RSS ≈ 6.6 MB; UDP 4-datagram multiplex across 3 resolvers on one association.
- Lifecycle hardened: ASan-clean under TCP churn (160 conns), UDP churn (60 associations), and
  half-close churn (cmd 0x05, bidirectional + early-kill).
- **BYTE-EXACT vs the live server:** **inter_pad length** validated the strongest way possible —
  the client's `inter_pad_len` prediction compared to the server's actual decrypted `pad_len` over
  **7,026 s→c records / 3 PSKs incl. an inter_jitter_mode==2 PSK, 0 mismatches** (build with `-DIPL_VERIFY`; this
  live check caught a cadence bug that 3 agreeing offline reconstructions all missed). Pad CONTENT
  byte-exact for all 4 modes and confirmed **inter_jitter_mode-independent** (150/150 on an inter_jitter_mode==2/mode-0 PSK);
  inter_pad inter_jitter_mode==2 length jitter byte-exact and load-bearing (328/328 with, 28/328 without).
  **chunk-size ramp** (15,908 records, 0 over-predictions; PSK1 picks reproduce the server's observed
  sizes). salt-block filler (71/71 & 58/58 non-scatter bytes). de-interleave (true involution,
  AEAD-valid after de-interleave). AEAD nonce (96-bit LE counter, cannot wrap). cmd 0x05 verified;
  client_id accepted; IPv6 server-connect + listener + IPv6-UDP target egress (4/4 DNS resolvers).

## 15.1 Stream lifecycle & half-close
- **No CONNECT reuse:** one Snell TCP connection = one CONNECT stream (the dispatcher only parses a
  request header in the closing state). The only multi-stream is cmd 0x06 (UDP), already implemented.
- **Only record type 0x04.** Stream-end / half-close is a **zero-length type-0x04 record (“zero
  trunk”)** = `[prefix][control(payload_len=0)][inter_pad]`, NO payload record (1 AEAD op / nonce).
- **Half-close relay (cmd 0x05):** s→c zero-trunk → client `shutdown(SHUT_WR)` to the local peer and
  keeps c→s flowing; local-peer write-EOF → client sends a c→s zero-trunk and keeps s→c. Full
  teardown when both sides are done. Verified bidirectionally + ASan-clean. (cmd 0x01: EOF = full close.)

## 15.2 Client feature flags (proxy front-end)
`--connect-cmd 1|5` (5 = half-close-tolerant CONNECT) · `--client-id <id>` · `--tcp-fastopen`
(TFO via TCP_FASTOPEN_CONNECT — client verified requesting it, but **this b2 server does not enable
TFO on its listen socket**, so it falls back; off by default) · `--no-shape` · `-v` (verbose; default
quiet) · IPv6 listen/connect (AF_UNSPEC).

---

## 16. Known / not implemented (residuals)

**No wire-behavior residuals remain.** Every PRNG selector that drives an observable wire behavior
is now reproduced byte-exact and live-verified against the server. The items previously listed here
are all resolved:
- **inter_pad LENGTH** → byte-exact, live-verified (§8.1).
- **chunk-size ramp** (incl. `chunk_grow` and the seconds-based **idle-reset**, sel 0x1b) → byte-exact,
  live-verified (§9).
- **"fixed-prefix one-shot record"** → RE proved it is simply the **salt block itself** (sel 0x21@0x7053
  / bounds sel 0x0e/0x0f@0x7053: `salt_block_len = 0x10 + range_map(prng(0x21,0,0x7053), blk_lo=[0xcc],
  blk_hi=[0x130])`, `blk_hi` additive) — first record of every connection in both directions, already
  byte-exact in `snell_salt.c` (state-0 path of fn 0x3b3f0, hbreak-verified). Not a gap.
- **mode-1 chunk modulus** field [0x12e] = const 8 → confirmed (§9).

What's left are non-wire-behavior items only:
- **Reserved selectors** sel 0x00, 0x04, 0x05, 0x28–0x39 are written-but-never-read or never
  invoked in the server (full accounting in `SELECTORS_RE.md`); correctly omitted by the client.
- **`client_id`** is supported (`--client-id`) but optional; default `cid_len=0`.
- **TFO server side** is absent in this build (client support is in place + falls back gracefully).
- **TLS/HTTP obfs**: v6 dropped it; not applicable (we never enable obfs).
