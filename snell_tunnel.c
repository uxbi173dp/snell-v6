/*
 * snell_tunnel.c — see snell_tunnel.h
 */
#include "snell_tunnel.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

/* chatty per-connection diagnostics, quiet unless -v (sn_log_verbose) */
#define TLOG(...) do { if (sn_log_verbose) fprintf(stderr, __VA_ARGS__); } while (0)

#define TX_CHUNK_MAX 16384  /* max application bytes per client->server chunk (matches server range) */

/* Record framing. Each chunk is [prefix_pad][control][inter_pad][payload], where
 * the control record is AEAD-sealed with the prefix_pad as AAD. Control plaintext
 * (SN_CTRL_PLAIN_LEN bytes): [type][rsv:2][pad_len:2 BE][payload_len:2 BE]. */
#define SN_CTRL_PLAIN_LEN 7                                  /* control record plaintext bytes */
#define SN_CTRL_WIRE_LEN  (SN_CTRL_PLAIN_LEN + SN_TAG_LEN)   /* 23: sealed control on the wire  */
#define SN_REC_TYPE_DATA  0x04   /* control "type" byte for a data (or zero-length) record */
#define SN_S2C_OK         0x00   /* first s->c payload byte: success, target data follows   */
#define SN_S2C_ERROR      0x02   /* first s->c payload byte: error frame [0x02][status][len][reason] */

/* server->client reassembly: bytes are read straight into the tail of rx_buf
 * (see rx_alloc), so a chunk is reassembled in place — no per-read malloc, no
 * append copy. RX_READ_WINDOW is the minimum tail room offered to libuv per read
 * (and the consumed-prefix compaction trigger). */
#define RX_READ_WINDOW (64 * 1024)

static void tun_fail(sn_tunnel_t *t, int err) {
    if (t->closed) return;
    TLOG("[tun] FAIL err=%d connected=%d handshook=%d rx_have_salt=%d rx_seq=%u tx_seq=%u rx_len=%zu\n",
            err, t->connected, t->handshook, t->rx_have_salt, t->rx_seq, t->tx_seq, t->rx_len);
    t->closed = 1;
    if (t->on_close) t->on_close(t, err);
}

/* Offer libuv the tail of rx_buf so server->client data lands in place. Reclaim
 * the consumed prefix and grow the buffer here (before the read) as needed. */
static void rx_alloc(uv_handle_t *h, size_t suggested, uv_buf_t *b) {
    sn_tunnel_t *t = (sn_tunnel_t*)h->data; (void)suggested;
    if (t->rx_off == t->rx_len) t->rx_off = t->rx_len = 0;   /* fully drained: reset */
    if (t->rx_cap - t->rx_len < RX_READ_WINDOW) {            /* tail too small for a read */
        if (t->rx_off > 0 && (t->rx_cap - t->rx_len) + (size_t)t->rx_off >= RX_READ_WINDOW) {
            memmove(t->rx_buf, t->rx_buf + t->rx_off, t->rx_len - t->rx_off);   /* reclaim suffices */
            t->rx_len -= t->rx_off; t->rx_off = 0;
        } else {                                            /* grow (realloc keeps unconsumed bytes in place) */
            size_t nc = t->rx_cap ? t->rx_cap : 2 * RX_READ_WINDOW;
            while (nc - t->rx_len < RX_READ_WINDOW) nc *= 2;
            uint8_t *nb = realloc(t->rx_buf, nc);
            if (!nb) { b->base = NULL; b->len = 0; return; }   /* OOM -> libuv delivers UV_ENOBUFS */
            t->rx_buf = nb; t->rx_cap = nc;
        }
    }
    b->base = (char*)(t->rx_buf + t->rx_len);
    b->len  = t->rx_cap - t->rx_len;
}
static void on_write_done(uv_write_t *w, int status) {
    (void)status;
    sn_tunnel_t *t = (sn_tunnel_t*)w->handle->data;   /* tcp.data == t (set in start_connect) */
    free(w->data); free(w);
    if (t && !t->closed && t->on_tx_drain) t->on_tx_drain(t);   /* c->s write drained: maybe resume client read */
}

/* write `len` bytes from `wire` (heap-owned copy made here; for stack/borrowed buffers) */
static int tun_send(sn_tunnel_t *t, const uint8_t *wire, size_t len) {
    uint8_t *copy = malloc(len); if (!copy) return -1;
    memcpy(copy, wire, len);
    uv_buf_t b = uv_buf_init((char*)copy, len);
    uv_write_t *w = malloc(sizeof(*w)); if (!w) { free(copy); return -1; }
    w->data = copy;
    int rc = uv_write(w, (uv_stream_t*)&t->tcp, &b, 1, on_write_done);
    if (rc != 0) { free(copy); free(w); }   /* on_write_done won't fire on sync failure */
    return rc;
}
/* like tun_send but TAKES OWNERSHIP of `buf` (no second copy) — for a heap buffer the
 * caller is done with. Freed in on_write_done (or here on sync failure). */
static int tun_send_owned(sn_tunnel_t *t, uint8_t *buf, size_t len) {
    uv_write_t *w = malloc(sizeof(*w)); if (!w) { free(buf); return -1; }
    uv_buf_t b = uv_buf_init((char*)buf, len);
    w->data = buf;
    int rc = uv_write(w, (uv_stream_t*)&t->tcp, &b, 1, on_write_done);
    if (rc != 0) { free(buf); free(w); }
    return rc;
}

/* Encode one client->server chunk for `payload` into out (caller-sized). Returns length.
 *
 * Wire: [prefix_pad][control(=AEAD of 7B, AAD=prefix_pad)][inter_pad][payload(=AEAD, AAD=inter_pad)].
 * With shaping on, inter_pad has a profile-derived length and the
 * (inter_pad || payload_ct) region is interleaved (the involution the server
 * de-interleaves on receive). The server reads pad_len/payload_len from the
 * control record, so this round-trips while matching the v6 traffic profile. */
static size_t encode_chunk(sn_tunnel_t *t, uint32_t seq, const uint8_t *payload, size_t plen, uint8_t *out, int prior) {
    int prefix_len = sn_shape_prefix_len(t->profile, SN_DIR_C2S, seq);
    int pad_len = t->shape_out ? sn_shape_inter_len(t->profile, seq, (int)plen, prior) : 0;
    size_t off = 0;
    sn_fill_pad(t->profile, SN_DIR_C2S, seq, out, prefix_len); off += prefix_len;  /* prefix pad (control AAD), profile-shaped */
    uint8_t ctl[SN_CTRL_PLAIN_LEN] = {SN_REC_TYPE_DATA, 0,0, (uint8_t)(pad_len>>8),(uint8_t)(pad_len&0xff),
                                      (uint8_t)(plen>>8),  (uint8_t)(plen&0xff)};
    if (sn_aead_seal(&t->tx_aead_ctx, t->key_cs, t->tx_nonce++, out, prefix_len, ctl, SN_CTRL_PLAIN_LEN, out+off) != 0)
        return 0;   /* AEAD failure: signal error (0 is never a valid encoded length) */
    off += SN_CTRL_PLAIN_LEN + SN_TAG_LEN;
    uint8_t *A = out + off;          /* inter_pad region (payload AAD)   */
    uint8_t *B = A + pad_len;        /* payload ciphertext||tag region   */
    if (pad_len > 0) sn_fill_pad(t->profile, SN_DIR_C2S, seq, A, pad_len);  /* inter pad, profile-shaped */
    if (sn_aead_seal(&t->tx_aead_ctx, t->key_cs, t->tx_nonce++, A, pad_len, payload, plen, B) != 0)
        return 0;
    if (pad_len > 0)                 /* interleave so the server de-interleaves it back */
        sn_deinterleave(t->profile, SN_DIR_C2S, seq, A, pad_len, B, (int)plen + SN_TAG_LEN);
    off += (size_t)pad_len + plen + SN_TAG_LEN;
    return off;
}

int sn_tunnel_write(sn_tunnel_t *t, const uint8_t *data, size_t len) {
    if (!t || t->closed || !t->handshook) return -1;
    /* One sn_tunnel_write == one upstream read == one server "build pass": split into
     * chunk-sized records and emit them ALL in a single uv_write (nbufs=1), matching the
     * server's builder (verified RVA 0x3b990 -> one uv_write @0x3eff5). prior stays 0 for
     * every record (it does NOT accumulate within a pass — wire-verified). Correctness is
     * identical to per-chunk writes (TCP coalesces); this matches the server's segmentation
     * and cuts a syscall per chunk. */
    /* Chunk-ramp IDLE-RESET (server RVA 0x3b990 driver): the server reads time(NULL)
     * ONCE per build pass (rdi=0 -> time(NULL), seconds) at function entry, and if
     * (now - last_pass_time) > ctx+0x144 (profile.idle_gap_s seconds) it resets the
     * running chunk target ctx+0x50 to chunk_min (ctx+0xc8) BEFORE emitting any record;
     * it then stores now into ctx+0x58. seq (ctx+0x150) is NOT reset. We mirror that
     * here so our c->s record sizes match the server's after an idle gap. Use whole
     * seconds via time(NULL) (NOT uv_now()/ms) to match the server's time_t granularity
     * exactly: the boundary is integer floor(now_s)-floor(last_s) > idle_gap_s. */
    if (t->shape_out) {
        long now_s = (long)time(NULL);
        if (t->tx_last_write_s != 0 &&
            (now_s - t->tx_last_write_s) > (long)t->profile->idle_gap_s) {
            t->tx_chunk_target = (uint16_t)t->profile->chunk_min;   /* server 0x3bb53/0x3bb5b */
            TLOG("[tun] chunk-ramp idle-reset: gap=%lds > %ds -> target=chunk_min(%d)\n",
                 now_s - t->tx_last_write_s, t->profile->idle_gap_s, t->profile->chunk_min);
        }
        t->tx_last_write_s = now_s;                                /* server 0x3bb60 / 0x3b9c7 */
    }
    size_t cap = len + len/4 + 4096, pos = 0, wl = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return -1;
    while (pos < len) {
        size_t ch = len - pos;
        int want = t->shape_out ? sn_shape_chunk_len(t->profile, t->tx_seq, (int)(len - pos), &t->tx_chunk_target)
                                : TX_CHUNK_MAX;
        if (ch > (size_t)want) ch = (size_t)want;
        if (ch > TX_CHUNK_MAX) ch = TX_CHUNK_MAX;
        size_t need = wl + 2048 + ch + 64;   /* worst-case encoded size of this record */
        if (need > cap) { cap = need * 2; uint8_t *nb = realloc(buf, cap); if (!nb) { free(buf); return -1; } buf = nb; }
        size_t n = encode_chunk(t, t->tx_seq++, data + pos, ch, buf + wl, 0);
        if (n == 0) { free(buf); return -1; }   /* AEAD seal failed: abort the pass */
        wl += n;
        if (t->shape_out) sn_shape_chunk_advance(t->profile, &t->tx_chunk_target);  /* ramp per record */
        pos += ch;
    }
    return tun_send_owned(t, buf, wl);   /* single uv_write for the whole pass (no extra copy) */
}

/* Send one datagram as exactly one chunk (UDP cmd 0x06). The chunk boundary
 * is the datagram boundary, so payload must fit one chunk (payload_len is u16). */
int sn_tunnel_send_datagram(sn_tunnel_t *t, const uint8_t *rec, size_t len) {
    if (!t || t->closed || !t->handshook) return -1;
    if (len == 0 || len > 65535) return -1;
    uint8_t *out = malloc(2048 + len + 64); if (!out) return -1;   /* prefix+control+inter_pad(≤0x5b4)+payload+tag */
    size_t n = encode_chunk(t, t->tx_seq++, rec, len, out, 0);
    if (n == 0) { free(out); return -1; }   /* AEAD seal failed */
    return tun_send_owned(t, out, n);       /* hand the record to uv_write (no extra copy) */
}

/* Send a c->s half-close: a "zero trunk" = prefix_pad + control(payload_len=0) +
 * inter_pad, with NO payload record (matches the server's zero-trunk; only the
 * control consumes a nonce). The server reads payload_len=0 as client write-EOF. */
int sn_tunnel_send_eof(sn_tunnel_t *t) {
    if (!t || t->closed || !t->handshook) return -1;
    uint32_t seq = t->tx_seq++;
    int prefix_len = sn_shape_prefix_len(t->profile, SN_DIR_C2S, seq);
    int pad_len = t->shape_out ? sn_shape_inter_len(t->profile, seq, 0, 0) : 0;
    uint8_t out[2048]; size_t off = 0;   /* prefix(≤0x80) + control(23) + inter_pad(≤0x5b4), no payload */
    sn_fill_pad(t->profile, SN_DIR_C2S, seq, out, prefix_len); off += prefix_len;
    uint8_t ctl[SN_CTRL_PLAIN_LEN] = {SN_REC_TYPE_DATA,0,0, (uint8_t)(pad_len>>8),(uint8_t)(pad_len&0xff), 0,0};  /* payload_len=0 */
    if (sn_aead_seal(&t->tx_aead_ctx, t->key_cs, t->tx_nonce++, out, prefix_len, ctl, SN_CTRL_PLAIN_LEN, out+off) != 0) return -1;
    off += SN_CTRL_PLAIN_LEN + SN_TAG_LEN;
    if (pad_len > 0) { sn_fill_pad(t->profile, SN_DIR_C2S, seq, out+off, pad_len); off += pad_len; }
    return tun_send(t, out, off);    /* no payload record */
}

/* Send the handshake: salt block + chunk0 carrying the request header. */
static void send_handshake(sn_tunnel_t *t) {
    /* client salt: random real salt -> obfuscated block; key_cs = argon2id(psk, real) */
    uint8_t real_salt[16]; randombytes_buf(real_salt, 16);
    uint8_t block[160];   /* salt_block_len = 0x10 + range_map(.,blk_lo,blk_hi<=0x80) <= 144 */
    if (t->profile->salt_block_len < 16 || (size_t)t->profile->salt_block_len > sizeof block) {
        tun_fail(t, -1); return;   /* defensive: never let a PSK-derived length overflow block[] */
    }
    sn_salt_obfuscate(t->profile, real_salt, block);
    if (sn_derive_key(t->profile->psk, real_salt, t->key_cs) != 0) { tun_fail(t, -1); return; }

    /* request header */
    uint8_t hdr[600]; size_t hl = 0;
    hdr[hl++] = SN_PROTO_VERSION; hdr[hl++] = t->cmd;          /* version, cmd */
    hdr[hl++] = t->client_id_len;                              /* client-id len */
    if (t->client_id_len) { memcpy(hdr+hl, t->client_id, t->client_id_len); hl += t->client_id_len; }
    if (t->cmd != SN_CMD_UDP) {   /* native UDP carries NO host/port in the header */
        size_t thl = strlen(t->target_host); hdr[hl++] = (uint8_t)thl;
        memcpy(hdr+hl, t->target_host, thl); hl += thl;
        hdr[hl++] = (uint8_t)(t->target_port>>8); hdr[hl++] = (uint8_t)(t->target_port&0xff);
    }

    /* seed the chunk-size ramp: chunk 0 is wire record 0 on a fresh stream (server
     * RVA 0x3b9cb seeds the running target to chunk_min before the first record). */
    if (t->shape_out) sn_shape_chunk_reset(t->profile, &t->tx_chunk_target);

    uint8_t wire[4096]; size_t wl = 0;   /* salt + prefix + control + inter_pad(≤0x5b4) + hdr(≤516) + tag */
    memcpy(wire, block, t->profile->salt_block_len); wl += t->profile->salt_block_len;
    /* chunk 0; prior = the salt block already in this buffer (matches the server's accounting) */
    size_t n = encode_chunk(t, t->tx_seq++, hdr, hl, wire + wl, t->profile->salt_block_len);
    if (n == 0) { tun_fail(t, -1); return; }   /* AEAD seal failed: abort the handshake */
    wl += n;
    tun_send(t, wire, wl);
    /* chunk 0 is a wire record → advance the ramp so the first data record sees chunk_min+grow */
    if (t->shape_out) sn_shape_chunk_advance(t->profile, &t->tx_chunk_target);
    t->handshook = 1;
}

/* RX: consume server salt + decode chunks. Shaping (prefix length & de-interleave
 * phases) is computed directly from the PRNG per chunk — no per-chunk brute force. */
#define RX_PAYLOAD_MAX 65535

static void rx_process(sn_tunnel_t *t) {
    for (;;) {
        uint8_t *base = t->rx_buf + t->rx_off;       /* unconsumed window [rx_off, rx_len) */
        size_t   avail = t->rx_len - t->rx_off;
        if (!t->rx_have_salt) {
            if (avail < (size_t)t->profile->salt_block_len) return;
            uint8_t real_salt[16];
            sn_salt_deobfuscate(t->profile, base, real_salt);
            if (sn_derive_key(t->profile->psk, real_salt, t->key_sc) != 0) { tun_fail(t,-1); return; }
            t->rx_off += t->profile->salt_block_len;
            t->rx_have_salt = 1;
            continue;
        }
        if (!t->pend) {                              /* compute prefix, decrypt control */
            int prefix_len = sn_shape_prefix_len(t->profile, SN_DIR_S2C, t->rx_seq);
            if (avail < (size_t)prefix_len + SN_CTRL_WIRE_LEN) return;     /* need control */
            uint8_t ctl[SN_CTRL_PLAIN_LEN]; size_t cl;
            if (sn_aead_open(&t->rx_aead_ctx, t->key_sc, t->rx_nonce, base, prefix_len,
                             base + prefix_len, SN_CTRL_WIRE_LEN, ctl, &cl) != 0 || cl != SN_CTRL_PLAIN_LEN) {
                TLOG("[tun] rx CTRL decrypt fail: seq=%u prefix=%d avail=%zu\n", t->rx_seq, prefix_len, avail);
                tun_fail(t,-1); return; }
            t->pend = 1; t->pend_prefix = prefix_len;
            t->pend_pad = (ctl[3]<<8)|ctl[4]; t->pend_payload = (ctl[5]<<8)|ctl[6];
            if (t->pend_payload > RX_PAYLOAD_MAX) { tun_fail(t,-1); return; }
#ifdef IPL_VERIFY
            {   /* compare my inter_pad_len prediction to the SERVER's actual pad_len */
                int prior = (t->rx_seq == 0) ? t->profile->salt_block_len : 0;
                int pred  = inter_pad_len(t->profile, t->rx_seq, t->pend_payload, prior);
                fprintf(stderr, "IPL %s seq=%u payload=%d prior=%d pred=%d actual=%d\n",
                        pred==t->pend_pad ? "OK" : "MISMATCH",
                        t->rx_seq, t->pend_payload, prior, pred, t->pend_pad);
                fflush(stderr);
            }
#endif
        }
        if (t->pend_payload == 0) {   /* zero-trunk (half-close): prefix+control+inter_pad, NO payload record */
            size_t ztot = (size_t)t->pend_prefix + SN_CTRL_WIRE_LEN + t->pend_pad;
            if (avail < ztot) return;
            t->rx_nonce += 1; t->rx_seq++; t->pend = 0; t->rx_off += ztot;
            if (t->on_peer_eof && !t->peer_eof_seen) { t->peer_eof_seen = 1; t->on_peer_eof(t); }
            if (t->closed) return;
            continue;
        }
        size_t total = (size_t)t->pend_prefix + SN_CTRL_WIRE_LEN + t->pend_pad + t->pend_payload + SN_TAG_LEN;
        if (avail < total) return;                    /* await full chunk */
        uint8_t *A = base + t->pend_prefix + SN_CTRL_WIRE_LEN;
        uint8_t *B = A + t->pend_pad;
        sn_deinterleave(t->profile, SN_DIR_S2C, t->rx_seq, A, t->pend_pad, B, t->pend_payload + SN_TAG_LEN);
        /* Decrypt the payload in place (GCM allows in==out); B then holds the
         * plaintext, delivered straight from rx_buf — no scratch buffer, no copy. */
        size_t ol;
        if (sn_aead_open(&t->rx_aead_ctx, t->key_sc, t->rx_nonce + 1, A, t->pend_pad, B, t->pend_payload + SN_TAG_LEN, B, &ol) != 0) {
            tun_fail(t,-1); return;
        }
        t->rx_nonce += 2; t->rx_seq++; t->pend = 0;
        t->rx_off += total;                          /* consume by offset (no memmove) */
        if (ol) {
            const uint8_t *dp = B; size_t dl = ol;
            if (!t->s2c_started) {            /* first s2c payload: reply opcode */
                t->s2c_started = 1;
                uint8_t opcode = B[0];
                if (opcode != SN_S2C_OK) {    /* error reply: [SN_S2C_ERROR][status][len][ASCII reason] */
                    int status = (opcode == SN_S2C_ERROR && ol >= 2) ? B[1] : opcode;
                    int rlen   = (opcode == SN_S2C_ERROR && ol >= 3) ? B[2] : 0;
                    t->err_status = status; t->err_reason[0] = 0;
                    if (rlen > 0 && (size_t)(3 + rlen) <= ol) {
                        int n = rlen < (int)sizeof(t->err_reason)-1 ? rlen : (int)sizeof(t->err_reason)-1;
                        memcpy(t->err_reason, B + 3, n); t->err_reason[n] = 0;
                    }
                    TLOG("[tun] server error opcode=0x%02x status=0x%02x reason=\"%s\"\n",
                            opcode, status, t->err_reason);
                    tun_fail(t,-1); return;
                }
                dp = B + 1; dl = ol - 1;
            }
            if (dl && t->on_data) t->on_data(t, dp, dl);
        }
        if (t->closed) return;
    }
}

static void on_server_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *b) {
    sn_tunnel_t *t = (sn_tunnel_t*)s->data;
    (void)b;   /* rx_alloc read straight into rx_buf + rx_len; nothing to copy or free */
    if (nread < 0) { tun_fail(t, nread == UV_EOF ? 0 : -1); return; }
    if (nread == 0) return;
    t->rx_len += (size_t)nread;
    rx_process(t);
}

void sn_tunnel_pause(sn_tunnel_t *t) {
    if (t && !t->rx_paused && !t->closed) { uv_read_stop((uv_stream_t*)&t->tcp); t->rx_paused = 1; }
}
void sn_tunnel_resume(sn_tunnel_t *t) {
    if (t && t->rx_paused && !t->closed) { uv_read_start((uv_stream_t*)&t->tcp, rx_alloc, on_server_read); t->rx_paused = 0; }
}

static void on_connect(uv_connect_t *req, int status) {
    sn_tunnel_t *t = (sn_tunnel_t*)req->data; free(req);
    if (status < 0) { tun_fail(t, status); return; }
    t->connected = 1;
    uv_tcp_nodelay(&t->tcp, 1);
    uv_tcp_keepalive(&t->tcp, 1, 60);   /* idle keepalive (no PING command in v6) */
    send_handshake(t);
    if (t->closed) return;   /* handshake failed (AEAD/key/length): teardown already under way */
    TLOG("[tun] connected+handshake sent (target %s:%d)\n", t->target_host, t->target_port);
    uv_read_start((uv_stream_t*)&t->tcp, rx_alloc, on_server_read);
    /* Signal ready as soon as the handshake is sent (optimistic). This is REQUIRED, not just
     * a perf choice: the server is lazy-status — its first s->c frame is [0x00 + first target
     * data] or an error frame; there is NO standalone connect-ack (verified: a silent target
     * yields no s->c byte). So a SOCKS5/HTTP proxy cannot wait for a connect-ack before
     * replying — for any client-speaks-first protocol (HTTP/TLS) that would deadlock (client
     * awaits reply ← reply awaits server frame ← server awaits target data ← target awaits the
     * client request). Optimistic reply is the only workable design. Post-connect target
     * failures therefore surface as a connection close, not a SOCKS error code. */
    if (t->on_ready) t->on_ready(t);
}

static void start_connect(sn_tunnel_t *t, const struct sockaddr_storage *ss) {
    int fam = ss->ss_family; (void)fam;
    uv_tcp_init(t->loop, &t->tcp); t->tcp.data = t; t->tcp_inited = 1;
#ifdef TCP_FASTOPEN_CONNECT
    if (t->tcp_fastopen) {   /* kernel sends the handshake in the SYN; falls back if unsupported */
        int fd = socket(fam, SOCK_STREAM, 0);
        if (fd >= 0) {
            int one = 1;
            int r = setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &one, sizeof one);
            TLOG("[tun] TFO_CONNECT setsockopt rc=%d errno=%d (opt=%d) fd=%d\n", r, errno, TCP_FASTOPEN_CONNECT, fd);
            if (r == 0) uv_tcp_open(&t->tcp, fd);
            else close(fd);
        }
    }
#endif
    uv_connect_t *cr = malloc(sizeof(*cr)); if (!cr) { tun_fail(t,-1); return; }
    cr->data = t;
    if (uv_tcp_connect(cr, &t->tcp, (const struct sockaddr*)ss, on_connect) != 0) { free(cr); tun_fail(t,-1); }
}

static void on_resolved(uv_getaddrinfo_t *r, int status, struct addrinfo *res) {
    sn_tunnel_t *t = (sn_tunnel_t*)r->data;
    t->resolving = 0;
    if (t->closed) {   /* torn down (uv_cancel/timeout) while DNS was in flight: no tcp handle was ever
                        * created, so on_tcp_closed can't run the deferred free — do it here instead. */
        if (res) uv_freeaddrinfo(res);
        if (t->on_tcp_closed_cb) t->on_tcp_closed_cb(t->user);
        return;
    }
    TLOG("[tun] resolved status=%d res=%p\n", status, (void*)res);
    if (status < 0 || !res) { tun_fail(t, status); return; }
    /* take the first result; supports IPv4 and IPv6 servers (AF_UNSPEC resolve) */
    struct sockaddr_storage ss; memset(&ss, 0, sizeof ss);
    if (res->ai_family == AF_INET6) {
        memcpy(&ss, res->ai_addr, sizeof(struct sockaddr_in6));
        ((struct sockaddr_in6*)&ss)->sin6_port = htons(t->server_port);
    } else {
        memcpy(&ss, res->ai_addr, sizeof(struct sockaddr_in));
        ((struct sockaddr_in*)&ss)->sin_port = htons(t->server_port);
    }
    uv_freeaddrinfo(res);
    start_connect(t, &ss);
}

int sn_tunnel_open(sn_tunnel_t *t, uv_loop_t *loop,
                   const char *server_host, int server_port, const sn_profile_t *profile,
                   const char *target_host, int target_port, uint8_t cmd,
                   sn_tun_data_cb on_data, sn_tun_ready_cb on_ready,
                   sn_tun_close_cb on_close, void *user) {
    memset(t, 0, sizeof(*t));
    t->loop = loop; t->server_port = server_port; t->target_port = target_port; t->cmd = cmd;
    t->shape_out = 1;   /* outbound shaping on by default (v6 anti-detection) */
    strncpy(t->server_host, server_host, sizeof(t->server_host)-1);
    strncpy(t->target_host, target_host, sizeof(t->target_host)-1);
    t->on_data = on_data; t->on_ready = on_ready; t->on_close = on_close; t->user = user;
    t->profile = profile;   /* shared, PSK-derived; built once by the caller */
    /* IP-literal fast path: skip DNS for numeric addresses */
    struct sockaddr_storage ss; memset(&ss, 0, sizeof ss);
    /* start_connect can fail synchronously (it invokes on_close via tun_fail);
     * report that as a non-zero return so the caller tears down via conn_close
     * (idempotent) instead of arming the connect watchdog on a doomed conn. */
    if (uv_ip4_addr(server_host, server_port, (struct sockaddr_in*)&ss) == 0) {
        TLOG("[tun] ip-literal IPv4 %s:%d — skipping DNS\n", server_host, server_port);
        start_connect(t, &ss); return t->closed ? -1 : 0;
    } else if (uv_ip6_addr(server_host, server_port, (struct sockaddr_in6*)&ss) == 0) {
        TLOG("[tun] ip-literal IPv6 %s:%d — skipping DNS\n", server_host, server_port);
        start_connect(t, &ss); return t->closed ? -1 : 0;
    }
    /* hostname: fall through to async DNS resolution */
    t->resolver.data = t;
    struct addrinfo hints; memset(&hints,0,sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;  /* IPv4 or IPv6 server */
    t->resolving = 1;   /* DNS in flight: close must uv_cancel (no tcp handle to uv_close yet) */
    int grc = uv_getaddrinfo(loop, &t->resolver, on_resolved, server_host, NULL, &hints);
    if (grc != 0) t->resolving = 0;   /* sync failure: on_resolved won't fire */
    return grc;
}

static void on_tcp_closed(uv_handle_t *h) {
    sn_tunnel_t *t = (sn_tunnel_t*)h->data;
    free(t->rx_buf); t->rx_buf=NULL;
    sn_aead_ctx_free(t->tx_aead_ctx); t->tx_aead_ctx=NULL;   /* free cached EVP contexts */
    sn_aead_ctx_free(t->rx_aead_ctx); t->rx_aead_ctx=NULL;
    if (t->on_tcp_closed_cb) t->on_tcp_closed_cb(t->user);  /* owner may now free us */
}
void sn_tunnel_close(sn_tunnel_t *t) {
    if (!t) return;
    if (t->resolving && !t->tcp_inited) {   /* DNS still in flight, no tcp handle yet: mark closed and
                                             * cancel. on_resolved still fires (UV_ECANCELED) and, seeing
                                             * t->closed, runs the deferred free via on_tcp_closed_cb. */
        t->closed = 1;
        uv_cancel((uv_req_t*)&t->resolver);
        return;
    }
    if (!t->tcp_inited) return;   /* never uv_close an uninitialized handle (aborts) */
    if (!uv_is_closing((uv_handle_t*)&t->tcp)) uv_close((uv_handle_t*)&t->tcp, on_tcp_closed);
}
