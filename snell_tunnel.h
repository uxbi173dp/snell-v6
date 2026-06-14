/*
 * snell_tunnel.h — libuv Snell v6 (b2) client tunnel.
 *
 * One tunnel = one TCP connection to the Snell server carrying one proxied
 * target stream. Handles: async connect, the shaped handshake (salt + request
 * header chunk), chunked AEAD relay both directions, and de-shaping of replies.
 */
#ifndef SNELL_TUNNEL_H
#define SNELL_TUNNEL_H

#include <uv.h>
#include <stdint.h>
#include "snell_crypto.h"
#include "snell_shape.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sn_tunnel sn_tunnel_t;

extern int sn_log_verbose;   /* chatty diagnostics gate (set by the proxy via -v) */

/* server -> client application data (already de-shaped & decrypted) */
typedef void (*sn_tun_data_cb)(sn_tunnel_t *t, const uint8_t *data, size_t len);
/* tunnel ready to carry data (handshake sent, relay armed) */
typedef void (*sn_tun_ready_cb)(sn_tunnel_t *t);
/* tunnel closed/errored (err 0 = clean EOF) */
typedef void (*sn_tun_close_cb)(sn_tunnel_t *t, int err);
/* peer (server/target) closed its write side in-band (s->c zero-trunk, cmd 0x05
 * half-close): no more s->c data, but the connection stays open for c->s. */
typedef void (*sn_tun_eof_cb)(sn_tunnel_t *t);
/* the client->server TCP write queue drained (a uv_write completed): lets the
 * owner resume reading from the local client if it paused for c->s backpressure. */
typedef void (*sn_tun_drain_cb)(sn_tunnel_t *t);

struct sn_tunnel {
    uv_tcp_t        tcp;
    uv_loop_t      *loop;
    uv_getaddrinfo_t resolver;

    char            server_host[256];
    int             server_port;
    char            target_host[256];
    int             target_port;
    uint8_t         cmd;            /* 0x01 connect, 0x05 connect+half-close, 0x06 udp */
    char            client_id[256]; /* optional multi-user id (handshake cid field) */
    uint8_t         client_id_len;

    sn_profile_t    profile;
    sn_params_t     params;         /* AES-128-GCM, etc. */
    uint8_t         key_cs[32];     /* client->server key */
    uint8_t         key_sc[32];     /* server->client key (after server salt) */
    void           *tx_aead_ctx;    /* cached EVP ctx for key_cs (seal); built once */
    void           *rx_aead_ctx;    /* cached EVP ctx for key_sc (open); built once */

    /* TX (client->server) */
    uint64_t        tx_nonce;
    uint32_t        tx_seq;
    uint16_t        tx_chunk_target;  /* running chunk-size ramp state (server ctx+0x50) */
    long            tx_last_write_s;  /* time(NULL) of the previous write-pass (server ctx+0x58);
                                       * 0 = none yet. Idle gap > profile.idle_gap_s resets the ramp. */

    /* RX (server->client) */
    int             rx_have_salt;
    uint64_t        rx_nonce;
    uint32_t        rx_seq;
    uint8_t        *rx_buf;
    size_t          rx_len, rx_cap, rx_off;   /* rx_off = consumed offset (no per-chunk memmove) */
    int             rx_paused;                /* server read paused for backpressure */
    /* in-progress chunk (control decrypted, awaiting full payload) */
    int             pend, pend_prefix, pend_pad, pend_payload;

    sn_tun_data_cb  on_data;
    sn_tun_ready_cb on_ready;
    sn_tun_close_cb on_close;
    sn_tun_eof_cb   on_peer_eof;   /* s->c half-close (zero-trunk) received */
    sn_tun_drain_cb on_tx_drain;   /* c->s TCP write queue drained (resume client read) */
    int             peer_eof_seen; /* guard: deliver peer EOF once */
    void           *user;

    int             connected, handshook, closed;
    int             resolving;     /* async DNS in flight (no tcp handle yet); close must uv_cancel, not uv_close */
    int             tcp_inited;    /* t->tcp has been uv_tcp_init'd (safe to uv_close) */
    int             s2c_started;   /* first server->client payload carries a status byte */
    int             err_status;    /* server error status byte (0=none); see PROTOCOL.md */
    char            err_reason[128];/* ASCII reason from the server error frame */
    int             shape_out;     /* apply outbound inter-pad + interleave (stealth) */
    int             tcp_fastopen;  /* use TCP Fast Open for the server connection */

    /* invoked once t->tcp's uv_close has fully completed (after rx_buf freed).
     * lets an owner that embeds this struct defer its own free until then. */
    void          (*on_tcp_closed_cb)(void *user);
};

/* Start a tunnel: resolve+connect to server, send handshake for target. */
int sn_tunnel_open(sn_tunnel_t *t, uv_loop_t *loop,
                   const char *server_host, int server_port, const char *psk,
                   const char *target_host, int target_port, uint8_t cmd,
                   sn_tun_data_cb on_data, sn_tun_ready_cb on_ready,
                   sn_tun_close_cb on_close, void *user);

/* Send application data through the tunnel (client->server). */
int sn_tunnel_write(sn_tunnel_t *t, const uint8_t *data, size_t len);

/* Send a c->s half-close (in-band zero-length type-0x04 record / "zero trunk"):
 * tells the server this side is done sending while keeping s->c open. */
int sn_tunnel_send_eof(sn_tunnel_t *t);

/* Send one pre-framed datagram record as exactly one chunk (UDP, cmd 0x06):
 * the chunk boundary delimits the datagram, so it must not be split. `rec` is
 * the full Snell UDP record [01][name_len][name|atyp+addr][port][payload]. */
int sn_tunnel_send_datagram(sn_tunnel_t *t, const uint8_t *rec, size_t len);

/* Backpressure: pause/resume reading server->client data (e.g. when the local
 * client's write queue is large). */
void sn_tunnel_pause(sn_tunnel_t *t);
void sn_tunnel_resume(sn_tunnel_t *t);

void sn_tunnel_close(sn_tunnel_t *t);

#ifdef __cplusplus
}
#endif
#endif
