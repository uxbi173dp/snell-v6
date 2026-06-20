/*
 * proxy.c — local SOCKS5 + HTTP CONNECT proxy front end over Snell v6 (b3).
 *
 * Each accepted local connection: parse target (SOCKS5 or HTTP CONNECT),
 * open a Snell tunnel to the server, then relay bidirectionally.
 *
 * Usage: snell-proxy --server HOST --server-port N --psk KEY
 *                    [--socks5 1080] [--http 8080] [--listen 127.0.0.1]
 */
#include "snell_tunnel.h"
#include <uv.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <signal.h>

typedef struct {
    uv_tcp_t   listener;
    uv_loop_t *loop;
    int        is_socks;          /* 1=SOCKS5, 0=HTTP CONNECT */
    char       server[256]; int server_port;
    const sn_profile_t *profile;  /* PSK-derived; built once in main(), shared by all conns */
    char       bind_addr[64];     /* local listen addr (also the UDP relay BND.ADDR) */
} listener_t;

typedef struct {
    uv_tcp_t    client;
    sn_tunnel_t tunnel;
    uv_loop_t  *loop;
    listener_t *L;
    int         phase;            /* 0=parsing, 1=relaying */
    int         socks_step;       /* SOCKS5 sub-state */
    uint8_t     buf[8192]; size_t blen;
    char        target_host[256]; int target_port;
    int         tunnel_ready, closing, paused;   /* paused = s->c read paused (server side) */
    int         crd_paused;       /* client read paused for c->s backpressure (tunnel TX queue high) */
    int         client_weof, peer_weof;   /* half-close (cmd 0x05): local/peer write side closed */
    size_t      up_bytes, down_bytes, client_wq;   /* client_wq = bytes queued to local client */

    uv_timer_t  ctimer;           /* connect/handshake watchdog (pre-ready window) */
    int         ctimer_inited;    /* ctimer was uv_timer_init'd (needs closing) */

    /* UDP ASSOCIATE (SOCKS5 CMD 0x03 -> Snell cmd 0x06) */
    int         is_udp;           /* this conn is a UDP association */
    uv_udp_t    udp;              /* local relay socket for client datagrams */
    int         udp_inited;       /* udp handle was uv_udp_init'd (needs closing) */
    int         nclose;           /* outstanding handle-close callbacks before free */
    struct sockaddr_storage client_uaddr;  /* where the client sends datagrams from */
    int         have_client_uaddr;
    struct sockaddr_storage ctrl_peer;     /* TCP control-conn peer; only accept datagrams from this IP (RFC 1928) */
    int         have_ctrl_peer;
    uint8_t    *relay_rdbuf;      /* pooled client->server read buffer (relay phase), freed at teardown */
} conn_t;

#define WQ_HIGH (512*1024)   /* pause server reads when client write queue exceeds this */
#define WQ_LOW  (128*1024)   /* resume when it drains below this */
#ifndef SN_CONNECT_TIMEOUT_MS
#define SN_CONNECT_TIMEOUT_MS 15000   /* watchdog for the pre-ready window (DNS + connect + handshake); -D to override */
#endif

static int g_shape_out = 1;  /* outbound traffic shaping (--no-shape disables) */
static int g_mode = SN_MODE_DEFAULT;  /* --mode default|unshaped|unsafe-raw (must match server) */
static uint8_t g_connect_cmd = SN_CMD_CONNECT;  /* TCP CONNECT; --connect-cmd 5 selects SN_CMD_CONNECT_HC (half-close tolerant) */
static char g_client_id[256] = ""; static uint8_t g_client_id_len = 0;  /* --client-id */
static int g_tcp_fastopen = 0;  /* --tcp-fastopen: TFO for the client->server connection */
int sn_log_verbose = 0;  /* -v: chatty per-connection diagnostics (default quiet) */
#define PLOG(...) do { if (sn_log_verbose) fprintf(stderr, __VA_ARGS__); } while (0)

#define CLIENT_RDBUF_SZ 65536   /* per-read window for client (c->s) reads */
static void alloc_cb(uv_handle_t *h, size_t sz, uv_buf_t *b){ (void)h; size_t n=sz<CLIENT_RDBUF_SZ?CLIENT_RDBUF_SZ:sz; b->base=malloc(n); b->len=b->base?n:0; }
/* Pooled allocator for the client->server RELAY read: hands libuv a persistent
 * per-conn buffer that on_client_relay consumes synchronously (encrypts into the
 * wire record) — so the hot c->s path has no per-read malloc, mirroring the s->c
 * rx_alloc design. Freed once at conn teardown. */
static void relay_alloc(uv_handle_t *h, size_t sz, uv_buf_t *b){
    (void)sz; conn_t *c=(conn_t*)h->data;
    if (!c->relay_rdbuf) c->relay_rdbuf = malloc(CLIENT_RDBUF_SZ);
    b->base=(char*)c->relay_rdbuf; b->len=c->relay_rdbuf?CLIENT_RDBUF_SZ:0;
}
static void after_write(uv_write_t *w, int st){ (void)st; free(w->data); free(w); }

/* write bytes to a uv_stream (copies) */
static void stream_write(uv_stream_t *s, const void *p, size_t n){
    char *c=malloc(n); if(!c) return; memcpy(c,p,n);
    uv_write_t *w=malloc(sizeof(*w)); if(!w){ free(c); return; }
    uv_buf_t b=uv_buf_init(c,n); w->data=c;
    uv_write(w,s,&b,1,after_write);
}

static void conn_destroy(conn_t *c){ free(c->relay_rdbuf); free(c); }   /* the one place a conn_t is freed */
static void conn_free(uv_handle_t *h){ conn_destroy((conn_t*)h->data); }   /* accept-fail path only (no tunnel) */
/* The conn embeds the client TCP, an optional UDP relay socket, AND the tunnel's
 * TCP handle. Each has an async uv_close callback; the conn must be freed only
 * after ALL of them fire, or a late tunnel-tcp close callback reads freed memory
 * (heap-use-after-free, snell_tunnel.c on_tcp_closed). `nclose` counts them. */
static void dec_free(conn_t *c){ if (--c->nclose <= 0) conn_destroy(c); }
static void on_handle_closed(uv_handle_t *h){ dec_free((conn_t*)h->data); }     /* client / udp */
static void on_tun_tcp_closed(void *user){ dec_free((conn_t*)user); }           /* tunnel tcp   */
/* Begin closing every handle the conn owns; free happens in the last callback. */
static void conn_close(conn_t *c){
    if (c->closing) return; c->closing=1;
    PLOG("[proxy] close: udp=%d ready=%d up=%zu down=%zu\n", c->is_udp, c->tunnel_ready, c->up_bytes, c->down_bytes);
    c->nclose = 0;
    if (c->tunnel.tcp_inited && !uv_is_closing((uv_handle_t*)&c->tunnel.tcp)) { c->nclose++; sn_tunnel_close(&c->tunnel); }
    else if (c->tunnel.resolving) { c->nclose++; sn_tunnel_close(&c->tunnel); }   /* DNS in flight: cancel; deferred free via on_tun_tcp_closed */
    if (c->ctimer_inited && !uv_is_closing((uv_handle_t*)&c->ctimer)) { c->nclose++; uv_close((uv_handle_t*)&c->ctimer, on_handle_closed); }
    if (!uv_is_closing((uv_handle_t*)&c->client)) { c->nclose++; uv_close((uv_handle_t*)&c->client, on_handle_closed); }
    if (c->udp_inited && !uv_is_closing((uv_handle_t*)&c->udp)) { c->nclose++; uv_close((uv_handle_t*)&c->udp, on_handle_closed); }
    if (c->nclose==0) conn_destroy(c);
}

/* ---- tunnel callbacks ---- */
/* tracked write to the local client (for backpressure accounting) */
typedef struct { uv_write_t req; conn_t *c; size_t n; char *buf; } cwreq_t;
static void after_client_write(uv_write_t *w, int st){
    (void)st; cwreq_t *wr=(cwreq_t*)w; conn_t *c=wr->c; size_t n=wr->n; free(wr->buf); free(wr);
    if (c->closing) return;
    c->client_wq -= n;
    if (c->paused && c->client_wq <= WQ_LOW) { PLOG("[proxy] backpressure resume (wq=%zu)\n", c->client_wq); c->paused=0; sn_tunnel_resume(&c->tunnel); }
}
static void client_write(conn_t *c, const void *p, size_t n){
    if (c->closing || n == 0) return;
    size_t sent = 0;
    /* When nothing is queued, write synchronously: uv_try_write copies straight
     * into the socket buffer with no allocation. We must NOT do this while ANY
     * write is pending in libuv's queue — a queued client_write remainder OR the
     * SOCKS5/HTTP success reply sent via stream_write (which client_wq does not
     * track) — or the sync bytes would overtake it and reorder the stream. Gate
     * on the real libuv write-queue depth, which counts every pending uv_write. */
    if (uv_stream_get_write_queue_size((uv_stream_t*)&c->client) == 0) {
        uv_buf_t b = uv_buf_init((char*)p, n);
        int w = uv_try_write((uv_stream_t*)&c->client, &b, 1);
        if (w > 0) sent = (size_t)w;
        if (sent >= n) return;   /* fully flushed; nothing to queue */
    }
    /* queue the remainder (partial sync write, EAGAIN, or queue not empty) */
    size_t rn = n - sent; char *buf = malloc(rn); if (!buf) return; memcpy(buf, (const uint8_t*)p + sent, rn);
    cwreq_t *wr = malloc(sizeof(*wr)); if (!wr) { free(buf); return; }
    wr->c=c; wr->n=rn; wr->buf=buf;
    uv_buf_t qb = uv_buf_init(buf, rn); c->client_wq += rn;
    if (uv_write((uv_write_t*)wr,(uv_stream_t*)&c->client,&qb,1,after_client_write) != 0) { c->client_wq -= rn; free(buf); free(wr); }
}
/* ---- UDP ASSOCIATE relay (SOCKS5 CMD 0x03 <-> Snell cmd 0x06) ---- */
typedef struct { uv_udp_send_t req; char *buf; } udp_send_req_t;
static void on_udp_send_done(uv_udp_send_t *req, int st){ (void)st; udp_send_req_t *r=(udp_send_req_t*)req; free(r->buf); free(r); }
/* send one datagram to the local SOCKS5 client's UDP source address */
static void udp_to_client(conn_t *c, const uint8_t *data, size_t n){
    if (!c->have_client_uaddr || c->closing) return;
    uv_buf_t b = uv_buf_init((char*)data, n);
    /* try a synchronous datagram send first (no allocation); UDP sends are atomic */
    if (uv_udp_try_send(&c->udp, &b, 1, (const struct sockaddr*)&c->client_uaddr) >= 0) return;
    /* would block / transient: fall back to a queued async send */
    char *buf=malloc(n); if(!buf) return; memcpy(buf,data,n);
    udp_send_req_t *r=malloc(sizeof(*r)); if(!r){ free(buf); return; }
    r->buf=buf; uv_buf_t qb=uv_buf_init(buf,n);
    if (uv_udp_send((uv_udp_send_t*)r,&c->udp,&qb,1,(const struct sockaddr*)&c->client_uaddr,on_udp_send_done)!=0){ free(buf); free(r); }
}
/* server->client datagram from the tunnel: [atyp 0x04/0x06][addr][port BE][data]
 * -> wrap in a SOCKS5 UDP reply header and deliver to the client. */
static void udp_relay_from_tunnel(conn_t *c, const uint8_t *rec, size_t n){
    if (n < 1) return;
    uint8_t atyp=rec[0], socks_atyp; size_t alen;
    if (atyp==0x04){ alen=4;  socks_atyp=0x01; }
    else if (atyp==0x06){ alen=16; socks_atyp=0x04; }
    else { PLOG("[proxy] udp rx unknown atyp=0x%02x\n", atyp); return; }
    if (n < 1+alen+2) return;
    const uint8_t *addr=rec+1, *port=rec+1+alen, *data=rec+1+alen+2;
    size_t datalen=n-(1+alen+2);
    uint8_t *out=malloc(4+alen+2+datalen); if(!out) return; size_t o=0;
    out[o++]=0; out[o++]=0; out[o++]=0;          /* RSV(2)=0, FRAG=0 */
    out[o++]=socks_atyp;
    memcpy(out+o,addr,alen); o+=alen;
    out[o++]=port[0]; out[o++]=port[1];
    memcpy(out+o,data,datalen); o+=datalen;
    udp_to_client(c,out,o); free(out);
}
/* same source IP? (port may differ — the client's UDP source port is ephemeral) */
static int same_ip(const struct sockaddr *a, const struct sockaddr *b){
    if (!a || !b || a->sa_family != b->sa_family) return 0;
    if (a->sa_family == AF_INET)
        return ((const struct sockaddr_in*)a)->sin_addr.s_addr == ((const struct sockaddr_in*)b)->sin_addr.s_addr;
    if (a->sa_family == AF_INET6)
        return memcmp(&((const struct sockaddr_in6*)a)->sin6_addr,
                      &((const struct sockaddr_in6*)b)->sin6_addr, 16) == 0;
    return 0;
}
/* local SOCKS5 client -> tunnel: strip the SOCKS5 UDP header, build a Snell
 * UDP record [01][name_len][name|atyp+addr][port BE][data], send as one chunk. */
static void on_udp_recv(uv_udp_t *h, ssize_t nread, const uv_buf_t *b,
                        const struct sockaddr *addr, unsigned flags){
    conn_t *c=(conn_t*)h->data;
    if (nread<=0 || !addr){ if(b->base) free(b->base); return; }
    if (flags & UV_UDP_PARTIAL){ free(b->base); return; }
    /* RFC 1928: drop datagrams whose source IP isn't the association's client (the TCP
     * control-connection peer). Stops an off-path host from injecting into the relay. */
    if (c->have_ctrl_peer && !same_ip(addr, (const struct sockaddr*)&c->ctrl_peer)){ free(b->base); return; }
    if (!c->have_client_uaddr){
        memcpy(&c->client_uaddr, addr, addr->sa_family==AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
        c->have_client_uaddr=1;
    }
    uint8_t *p=(uint8_t*)b->base; size_t n=(size_t)nread;
    if (n<4 || p[2]!=0){ free(b->base); return; }   /* need RSV/FRAG/ATYP; no fragmentation */
    uint8_t atyp=p[3];
    uint8_t *rec=malloc(3+256+2+n); if(!rec){ free(b->base); return; }
    size_t rl=0, doff;
    if (atyp==0x01){           /* IPv4 */
        if (n<10){ free(rec); free(b->base); return; }
        rec[rl++]=0x01; rec[rl++]=0x00; rec[rl++]=0x04; memcpy(rec+rl,p+4,4); rl+=4;
        rec[rl++]=p[8]; rec[rl++]=p[9]; doff=10;
    } else if (atyp==0x04){    /* IPv6 */
        if (n<22){ free(rec); free(b->base); return; }
        rec[rl++]=0x01; rec[rl++]=0x00; rec[rl++]=0x06; memcpy(rec+rl,p+4,16); rl+=16;
        rec[rl++]=p[20]; rec[rl++]=p[21]; doff=22;
    } else if (atyp==0x03){    /* domain name */
        uint8_t dl=p[4]; if (n<(size_t)5+dl+2){ free(rec); free(b->base); return; }
        rec[rl++]=0x01; rec[rl++]=dl; memcpy(rec+rl,p+5,dl); rl+=dl;
        rec[rl++]=p[5+dl]; rec[rl++]=p[5+dl+1]; doff=(size_t)5+dl+2;
    } else { free(rec); free(b->base); return; }
    size_t datalen=n-doff; memcpy(rec+rl,p+doff,datalen); rl+=datalen;
    c->up_bytes += datalen;
    sn_tunnel_send_datagram(&c->tunnel, rec, rl);
    free(rec); free(b->base);
}

static void on_tun_data(sn_tunnel_t *t, const uint8_t *data, size_t len){
    conn_t *c = (conn_t*)t->user; if (c->closing) return;
    c->down_bytes += len;
    if (c->is_udp){ udp_relay_from_tunnel(c, data, len); return; }
    client_write(c, data, len);
    if (c->client_wq >= WQ_HIGH && !c->paused) { PLOG("[proxy] backpressure pause (wq=%zu)\n", c->client_wq); c->paused=1; sn_tunnel_pause(&c->tunnel); }
}
/* client write side flushed: now close the client handle (counted). */
static void on_shutdown_done(uv_shutdown_t *req, int st){
    (void)st; conn_t *c=(conn_t*)req->data; free(req);
    if (!uv_is_closing((uv_handle_t*)&c->client)) uv_close((uv_handle_t*)&c->client, on_handle_closed);
    else dec_free(c);
}
/* Map a Snell error-frame status byte to the closest SOCKS5 reply (REP) code.
 * Snell statuses (see PROTOCOL.md / E-code catalog): 0x64 DNS Failed, 0x65 Remote
 * EOF (cmd5), and an errno table 0x01..0x08 (EAFNOSUPPORT/ENETDOWN/ENETUNREACH/
 * ECONNRESET/ETIMEDOUT/-/ECONNREFUSED/-/EHOSTUNREACH); 0xFF/other = unmapped. */
static uint8_t snell_status_to_socks5(int st){
    switch (st){
        case 0x01: return 0x08;  /* addr family not supported -> addr type not supported */
        case 0x02: return 0x03;  /* network is down          -> network unreachable     */
        case 0x03: return 0x03;  /* network is unreachable   -> network unreachable     */
        case 0x04: return 0x05;  /* connection reset by peer -> connection refused      */
        case 0x05: return 0x06;  /* connection timed out     -> TTL expired             */
        case 0x06: return 0x05;  /* connection refused       -> connection refused      */
        case 0x08: return 0x04;  /* no route to host         -> host unreachable        */
        case 0x64: return 0x04;  /* DNS Failed               -> host unreachable        */
        default:   return 0x01;  /* 0x65 Remote EOF, 0xFF, none -> general failure       */
    }
}

/* tunnel (server) side closed/errored. Close every owned handle (counted free);
 * for TCP, first uv_shutdown the client to flush buffered server->client data so
 * streamed downloads aren't truncated. */
static void on_tun_close(sn_tunnel_t *t, int err){
    conn_t *c=(conn_t*)t->user;
    if (c->closing) return; c->closing=1;
    PLOG("[proxy] tun closed: udp=%d up=%zu down=%zu err=%d snell_status=0x%02x reason=\"%s\"\n",
            c->is_udp, c->up_bytes, c->down_bytes, err, c->tunnel.err_status, c->tunnel.err_reason);
    /* failed before the success reply was sent → give the local client a proper error
     * reply (mapped from the snell status) instead of a silent drop. */
    if (!c->tunnel_ready && !c->is_udp && !uv_is_closing((uv_handle_t*)&c->client)) {
        int st = c->tunnel.err_status;
        if (c->L->is_socks) {
            uint8_t rep = snell_status_to_socks5(st);
            uint8_t r[10]={0x05,rep,0x00,0x01,0,0,0,0,0,0}; stream_write((uv_stream_t*)&c->client,r,10);
        } else {
            const char *e = "HTTP/1.1 502 Bad Gateway\r\n\r\n"; stream_write((uv_stream_t*)&c->client,e,strlen(e));
        }
    }
    c->nclose = 0;
    if (c->tunnel.tcp_inited && !uv_is_closing((uv_handle_t*)&c->tunnel.tcp)) { c->nclose++; sn_tunnel_close(&c->tunnel); }
    else if (c->tunnel.resolving) { c->nclose++; sn_tunnel_close(&c->tunnel); }   /* DNS in flight: cancel; deferred free via on_tun_tcp_closed */
    if (c->ctimer_inited && !uv_is_closing((uv_handle_t*)&c->ctimer)) { c->nclose++; uv_close((uv_handle_t*)&c->ctimer, on_handle_closed); }
    if (c->udp_inited && !uv_is_closing((uv_handle_t*)&c->udp)) { c->nclose++; uv_close((uv_handle_t*)&c->udp, on_handle_closed); }
    if (!uv_is_closing((uv_handle_t*)&c->client)) {
        c->nclose++;
        uv_shutdown_t *sr = c->is_udp ? NULL : malloc(sizeof(*sr));   /* UDP control conn: nothing to drain */
        if (sr) { sr->data=c; if (uv_shutdown(sr,(uv_stream_t*)&c->client,on_shutdown_done)==0) goto done; free(sr); }
        uv_close((uv_handle_t*)&c->client, on_handle_closed);
    }
done:
    if (c->nclose==0) conn_destroy(c);
}

/* half-close: shut our write side to the local client without closing the conn */
static void on_halfclose_shutdown_done(uv_shutdown_t *req, int st){ (void)st; free(req); }
/* peer (server/target) closed its write side in-band (s->c zero-trunk, cmd 0x05):
 * signal EOF to the local client's read side, keep relaying local->tunnel. */
static void on_tun_peer_eof(sn_tunnel_t *t){
    conn_t *c=(conn_t*)t->user; if (c->closing || c->peer_weof) return;
    if (c->tunnel.cmd != SN_CMD_CONNECT_HC) return;   /* in-band half-close (zero-trunk) only applies to cmd 0x05 */
    c->peer_weof = 1;
    if (sn_log_verbose) PLOG("[proxy] peer half-close (s->c EOF)\n");
    if (c->client_weof) { conn_close(c); return; }          /* both sides done */
    if (!uv_is_closing((uv_handle_t*)&c->client)) {
        uv_shutdown_t *sr=malloc(sizeof(*sr));
        if (sr){ sr->data=c; if (uv_shutdown(sr,(uv_stream_t*)&c->client,on_halfclose_shutdown_done)!=0) free(sr); }
    }
}

/* local client -> tunnel (relay phase) */
static void on_client_relay(uv_stream_t *s, ssize_t n, const uv_buf_t *b){
    conn_t *c=(conn_t*)s->data;
    if (n == UV_EOF) {                       /* local client closed its write side */
        if (c->tunnel.cmd == SN_CMD_CONNECT_HC && !c->client_weof) {  /* half-close: signal c->s EOF in-band */
            c->client_weof = 1;
            if (sn_log_verbose) PLOG("[proxy] local half-close (c->s EOF)\n");
            sn_tunnel_send_eof(&c->tunnel);
            uv_read_stop(s);
            if (c->peer_weof) conn_close(c);                /* both sides done */
        } else {
            conn_close(c);                                  /* cmd 0x01 / already half-closed: full close */
        }
        return;
    }
    if (n < 0) { conn_close(c); return; }     /* error/RST */
    if (n == 0) return;                       /* EAGAIN, not EOF */
    c->up_bytes += n;
    int wr = sn_tunnel_write(&c->tunnel,(const uint8_t*)b->base,n);   /* b->base is the pooled relay_rdbuf */
    if (wr != 0) { conn_close(c); return; }   /* don't silently drop c->s bytes on encode/write failure */
    /* c->s backpressure: stop reading the local client while the server-side TCP write
     * queue is large; on_tun_tx_drain resumes it once the queue drains. */
    if (!c->crd_paused && uv_stream_get_write_queue_size((uv_stream_t*)&c->tunnel.tcp) >= WQ_HIGH) {
        c->crd_paused = 1; uv_read_stop(s);
        PLOG("[proxy] c->s backpressure pause (txwq=%zu)\n",
             uv_stream_get_write_queue_size((uv_stream_t*)&c->tunnel.tcp));
    }
}

/* tunnel's client->server TCP write queue drained: resume the local client read
 * if it was paused for c->s backpressure. */
static void on_tun_tx_drain(sn_tunnel_t *t){
    conn_t *c=(conn_t*)t->user;
    if (c->closing || c->is_udp || !c->crd_paused || c->client_weof) return;
    if (uv_stream_get_write_queue_size((uv_stream_t*)&t->tcp) > WQ_LOW) return;
    if (uv_is_closing((uv_handle_t*)&c->client)) return;
    c->crd_paused = 0;
    uv_read_start((uv_stream_t*)&c->client, relay_alloc, on_client_relay);
    PLOG("[proxy] c->s backpressure resume (txwq=%zu)\n", uv_stream_get_write_queue_size((uv_stream_t*)&t->tcp));
}

/* TCP control connection of a UDP association: carries no relay data; its
 * closure (RFC 1928) tears the association down. */
static void on_udp_control_read(uv_stream_t *s, ssize_t n, const uv_buf_t *b){
    conn_t *c=(conn_t*)s->data;
    if (n<0){ free(b->base); conn_close(c); return; }
    if (b->base) free(b->base);
}

static void on_tun_ready(sn_tunnel_t *t){
    conn_t *c=(conn_t*)t->user; if (c->closing) return;
    c->tunnel_ready=1;
    if (c->ctimer_inited) uv_timer_stop(&c->ctimer);   /* past the pre-ready window; handle closed in teardown */
    if (c->is_udp){
        /* SOCKS5 UDP ASSOCIATE reply: BND.ADDR/PORT of our local relay socket */
        struct sockaddr_storage ss; int nl=sizeof ss;
        uv_udp_getsockname(&c->udp,(struct sockaddr*)&ss,&nl);
        uint16_t bport = ((struct sockaddr_in*)&ss)->sin_port;   /* network order */
        const char *ba = c->L->bind_addr[0] ? c->L->bind_addr : "127.0.0.1";
        struct in_addr ip4; if (inet_pton(AF_INET, ba, &ip4)!=1) inet_pton(AF_INET,"127.0.0.1",&ip4);
        uint8_t r[10]; r[0]=0x05; r[1]=0x00; r[2]=0x00; r[3]=0x01;
        memcpy(r+4,&ip4,4); memcpy(r+8,&bport,2);
        stream_write((uv_stream_t*)&c->client,r,10);
        c->phase=1;
        uv_udp_recv_start(&c->udp, alloc_cb, on_udp_recv);
        uv_read_start((uv_stream_t*)&c->client, alloc_cb, on_udp_control_read);
        PLOG("[proxy] udp associate ready, relay on :%d\n", ntohs(bport));
        return;
    }
    if (c->L->is_socks){
        uint8_t r[10]={0x05,0x00,0x00,0x01,0,0,0,0,0,0};
        stream_write((uv_stream_t*)&c->client,r,10);
    } else {
        const char *ok="HTTP/1.1 200 Connection Established\r\n\r\n";
        stream_write((uv_stream_t*)&c->client,ok,strlen(ok));
    }
    c->phase=1;
    PLOG("[proxy] tunnel ready -> client (success sent), relaying\n");
    uv_read_start((uv_stream_t*)&c->client, relay_alloc, on_client_relay);
}

/* Pre-ready watchdog: the server is lazy-status (no connect-ack), so a black-holed
 * server or a stuck DNS/handshake would otherwise hang the local client forever.
 * Fires only before on_tun_ready. Delegate to on_tun_close: it sends the mapped
 * failure reply to the local client AND flushes it via uv_shutdown before closing
 * (a plain conn_close would uv_close the client and drop the unsent reply). */
static void on_connect_timeout(uv_timer_t *h){
    conn_t *c=(conn_t*)h->data;
    if (c->closing || c->tunnel_ready) return;   /* past the guarded window: nothing to do */
    PLOG("[proxy] connect/handshake timeout (%dms) for %s:%d\n", SN_CONNECT_TIMEOUT_MS, c->target_host, c->target_port);
    c->tunnel.err_status = 0x05;   /* Snell "connection timed out" -> SOCKS REP 0x06 (TTL expired) */
    on_tun_close(&c->tunnel, UV_ETIMEDOUT);
}

static void start_tunnel(conn_t *c){
    uv_read_stop((uv_stream_t*)&c->client);
    PLOG("[proxy] %s %s:%d\n", c->L->is_socks?"SOCKS5":"CONNECT", c->target_host, c->target_port);
    int rc = sn_tunnel_open(&c->tunnel, c->loop, c->L->server, c->L->server_port, c->L->profile,
                       c->target_host, c->target_port, g_connect_cmd, g_mode,
                       on_tun_data, on_tun_ready, on_tun_close, c);
    c->tunnel.shape_out = g_shape_out;
    c->tunnel.tcp_fastopen = g_tcp_fastopen;
    c->tunnel.on_tcp_closed_cb = on_tun_tcp_closed;
    c->tunnel.on_peer_eof = on_tun_peer_eof;   /* half-close relay (cmd 0x05) */
    c->tunnel.on_tx_drain = on_tun_tx_drain;   /* c->s backpressure resume */
    memcpy(c->tunnel.client_id, g_client_id, g_client_id_len); c->tunnel.client_id_len = g_client_id_len;
    PLOG("[proxy] sn_tunnel_open rc=%d\n", rc);
    if (rc != 0) { conn_close(c); return; }
    uv_timer_init(c->loop, &c->ctimer); c->ctimer.data = c; c->ctimer_inited = 1;
    uv_timer_start(&c->ctimer, on_connect_timeout, SN_CONNECT_TIMEOUT_MS, 0);
}

/* SOCKS5 UDP ASSOCIATE: bind a local relay socket, open a Snell UDP (cmd 0x06)
 * tunnel; the associate reply (with the relay addr) is sent once the tunnel is ready. */
static void start_udp_associate(conn_t *c){
    uv_read_stop((uv_stream_t*)&c->client);
    c->is_udp=1;
    int pnl=sizeof(c->ctrl_peer);   /* record the association's client IP (RFC 1928 datagram filter) */
    if (uv_tcp_getpeername(&c->client,(struct sockaddr*)&c->ctrl_peer,&pnl)==0) c->have_ctrl_peer=1;
    uv_udp_init(c->loop,&c->udp); c->udp.data=c; c->udp_inited=1;
    struct sockaddr_in ba; uv_ip4_addr(c->L->bind_addr[0]?c->L->bind_addr:"127.0.0.1", 0, &ba);
    if (uv_udp_bind(&c->udp,(const struct sockaddr*)&ba,0)!=0){ PLOG("[proxy] udp bind failed\n"); conn_close(c); return; }
    PLOG("[proxy] SOCKS5 UDP ASSOCIATE -> snell udp (cmd 0x06)\n");
    int rc=sn_tunnel_open(&c->tunnel,c->loop,c->L->server,c->L->server_port,c->L->profile,
                          "",0,SN_CMD_UDP, g_mode, on_tun_data,on_tun_ready,on_tun_close,c);
    c->tunnel.shape_out = g_shape_out;
    c->tunnel.tcp_fastopen = g_tcp_fastopen;
    c->tunnel.on_tcp_closed_cb = on_tun_tcp_closed;
    memcpy(c->tunnel.client_id, g_client_id, g_client_id_len); c->tunnel.client_id_len = g_client_id_len;
    if (rc!=0) { conn_close(c); return; }
    uv_timer_init(c->loop, &c->ctimer); c->ctimer.data = c; c->ctimer_inited = 1;
    uv_timer_start(&c->ctimer, on_connect_timeout, SN_CONNECT_TIMEOUT_MS, 0);
}

/* ---- HTTP CONNECT parsing ---- */
static void on_http_parse(uv_stream_t *s, ssize_t n, const uv_buf_t *b){
    conn_t *c=(conn_t*)s->data;
    if (n<=0){ free(b->base); conn_close(c); return; }
    if (c->blen + n > sizeof(c->buf)){ free(b->base); conn_close(c); return; }
    memcpy(c->buf+c->blen,b->base,n); c->blen+=n; free(b->base);
    c->buf[c->blen<sizeof(c->buf)?c->blen:sizeof(c->buf)-1]=0;
    char *end=strstr((char*)c->buf,"\r\n\r\n"); if(!end) return;
    char method[16]={0}, url[300]={0};
    if (sscanf((char*)c->buf,"%15s %299s",method,url)!=2){ conn_close(c); return; }
    if (strcasecmp(method,"CONNECT")!=0){
        const char *e="HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        stream_write(s,e,strlen(e)); conn_close(c); return;
    }
    char *colon=strrchr(url,':');
    if (colon){ *colon=0; c->target_port=atoi(colon+1); } else c->target_port=443;
    strncpy(c->target_host,url,sizeof(c->target_host)-1);
    start_tunnel(c);
}

/* ---- SOCKS5 parsing ---- */
static void on_socks_parse(uv_stream_t *s, ssize_t n, const uv_buf_t *b){
    conn_t *c=(conn_t*)s->data;
    if (n<=0){ free(b->base); conn_close(c); return; }
    if (c->blen + n > sizeof(c->buf)){ free(b->base); conn_close(c); return; }
    memcpy(c->buf+c->blen,b->base,n); c->blen+=n; free(b->base);

    if (c->socks_step==0){                         /* greeting: 05 nm methods... */
        if (c->blen<2) return; uint8_t nm=c->buf[1];
        if (c->blen < (size_t)2+nm) return;
        uint8_t rep[2]={0x05,0x00}; stream_write(s,rep,2);
        c->socks_step=1;
        size_t consumed=(size_t)2+nm;              /* keep any request bytes pipelined after the greeting */
        c->blen-=consumed;
        if (c->blen) memmove(c->buf, c->buf+consumed, c->blen);
        /* fall through: parse a request that arrived in the same segment (no early return) */
    }
    /* request: 05 cmd 00 atyp addr port  (cmd 0x01 CONNECT, 0x03 UDP ASSOCIATE) */
    if (c->blen<4) return;
    uint8_t scmd=c->buf[1];
    if (scmd!=0x01 && scmd!=0x03){ uint8_t r[10]={0x05,0x07,0,0x01,0,0,0,0,0,0}; stream_write(s,r,10); conn_close(c); return; }
    uint8_t atyp=c->buf[3]; size_t need;
    if (atyp==0x01) need=4+4+2;
    else if (atyp==0x03) { if (c->blen<5) return; need=4+1+c->buf[4]+2; }  /* buf[4]=domain len */
    else if (atyp==0x04) need=4+16+2;
    else { conn_close(c); return; }
    if (c->blen<need) return;
    if (atyp==0x01){ struct in_addr a; memcpy(&a,c->buf+4,4); inet_ntop(AF_INET,&a,c->target_host,sizeof c->target_host); }
    else if (atyp==0x03){ uint8_t dl=c->buf[4]; memcpy(c->target_host,c->buf+5,dl); c->target_host[dl]=0; }
    else { struct in6_addr a6; memcpy(&a6,c->buf+4,16); inet_ntop(AF_INET6,&a6,c->target_host,sizeof c->target_host); }
    uint16_t port; memcpy(&port,c->buf+need-2,2); c->target_port=ntohs(port);
    if (scmd==0x03) start_udp_associate(c);   /* DST.ADDR/PORT ignored for associate */
    else start_tunnel(c);
}

static void on_new_conn(uv_stream_t *sv, int st){
    if (st<0) return; listener_t *L=(listener_t*)sv->data;
    conn_t *c=calloc(1,sizeof(*c)); if(!c) return; c->loop=sv->loop; c->L=L;
    uv_tcp_init(c->loop,&c->client); c->client.data=c;
    if (uv_accept(sv,(uv_stream_t*)&c->client)!=0){ uv_close((uv_handle_t*)&c->client,conn_free); return; }
    uv_tcp_nodelay(&c->client,1);
    uv_read_start((uv_stream_t*)&c->client, alloc_cb, L->is_socks?on_socks_parse:on_http_parse);
}

static int start_listener(listener_t *L, uv_loop_t *loop, int is_socks, const char *addr, int port,
                          const char *server, int sport, const sn_profile_t *profile){
    memset(L,0,sizeof(*L)); L->loop=loop; L->is_socks=is_socks; L->server_port=sport;
    strncpy(L->server,server,sizeof L->server-1); L->profile=profile;
    strncpy(L->bind_addr,addr,sizeof L->bind_addr-1);
    uv_tcp_init(loop,&L->listener); L->listener.data=L;
    struct sockaddr_storage a; memset(&a,0,sizeof a);
    if (strchr(addr,':')) uv_ip6_addr(addr,port,(struct sockaddr_in6*)&a);
    else                  uv_ip4_addr(addr,port,(struct sockaddr_in*)&a);
    uv_tcp_bind(&L->listener,(const struct sockaddr*)&a,0);
    return uv_listen((uv_stream_t*)&L->listener,128,on_new_conn);
}

int main(int argc,char**argv){
    if (sodium_init()<0){ fprintf(stderr,"sodium init failed\n"); return 1; }
    signal(SIGPIPE, SIG_IGN);   /* a peer that vanishes mid-write must yield EPIPE, not kill us
                                 * (uv_try_write writes synchronously, without MSG_NOSIGNAL) */
    char server[256]="", psk[256]="", listen_addr[64]="127.0.0.1";
    int sport=0, socks_port=1080, http_port=8080, en_socks=1, en_http=1;
    static struct option lo[]={{"server",1,0,'s'},{"server-port",1,0,'p'},{"psk",1,0,'k'},
        {"socks5",1,0,'S'},{"http",1,0,'H'},{"listen",1,0,'l'},{"no-socks5",0,0,'A'},{"no-http",0,0,'B'},
        {"no-shape",0,0,'N'},{"connect-cmd",1,0,'C'},{"client-id",1,0,'I'},{"verbose",0,0,'v'},
        {"tcp-fastopen",0,0,'F'},{"mode",1,0,'m'},{0,0,0,0}};
    int o; while((o=getopt_long(argc,argv,"s:p:k:S:H:l:v",lo,0))!=-1){ switch(o){
        case 's':strncpy(server,optarg,255);break; case 'p':sport=atoi(optarg);break; case 'k':strncpy(psk,optarg,255);break;
        case 'S':socks_port=atoi(optarg);break; case 'H':http_port=atoi(optarg);break; case 'l':strncpy(listen_addr,optarg,63);break;
        case 'A':en_socks=0;break; case 'B':en_http=0;break; case 'N':g_shape_out=0;break;
        case 'C':g_connect_cmd=(atoi(optarg)==5)?SN_CMD_CONNECT_HC:SN_CMD_CONNECT;break;
        case 'I':{ strncpy(g_client_id,optarg,255); size_t n=strlen(g_client_id); g_client_id_len=(uint8_t)(n>255?255:n); break; }
        case 'v':sn_log_verbose=1;break; case 'F':g_tcp_fastopen=1;break;
        case 'm':
            if(!strcasecmp(optarg,"default")) g_mode=SN_MODE_DEFAULT;
            else if(!strcasecmp(optarg,"unshaped")) g_mode=SN_MODE_UNSHAPED;
            else if(!strcasecmp(optarg,"unsafe-raw")) g_mode=SN_MODE_UNSAFE_RAW;
            else { fprintf(stderr,"--mode must be one of: default, unshaped, unsafe-raw\n"); return 1; }
            break; } }
    if(!server[0]||!psk[0]||!sport){ fprintf(stderr,"usage: %s --server H --server-port P --psk K [--socks5 1080] [--http 8080] [--mode default|unshaped|unsafe-raw]\n",argv[0]); return 1; }

    /* One PSK -> one profile: build the PSK-derived shaping profile once and share
     * it (read-only) across every tunnel, instead of recomputing it per connection. */
    static sn_profile_t profile;
    if (sn_profile_init(&profile, psk) != 0){ fprintf(stderr,"profile init failed\n"); return 1; }

    uv_loop_t *loop=uv_default_loop();
    static listener_t s5,hp;
    if(en_socks && start_listener(&s5,loop,1,listen_addr,socks_port,server,sport,&profile)==0)
        PLOG("[proxy] SOCKS5 on %s:%d\n",listen_addr,socks_port);
    if(en_http && start_listener(&hp,loop,0,listen_addr,http_port,server,sport,&profile)==0)
        PLOG("[proxy] HTTP CONNECT on %s:%d\n",listen_addr,http_port);
    PLOG("[proxy] -> snell %s:%d\n",server,sport);
    uv_run(loop,UV_RUN_DEFAULT);
    return 0;
}
