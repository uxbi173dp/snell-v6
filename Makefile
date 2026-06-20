# Snell v6 (b3) client — FINAL product.
# Builds the deliverable proxy `snell-proxy` (SOCKS5 + HTTP CONNECT front ends,
# full byte-exact Snell v6 shaping). See PROTOCOL.md / PROTOCOL_RFC.md.
UNAME_S := $(shell uname -s)
CC      = cc
CFLAGS  = -Wall -Wextra -O2 -g -Wno-deprecated-declarations
LDFLAGS = -lsodium -lssl -lcrypto

ifeq ($(UNAME_S),Darwin)
  BREW := $(shell brew --prefix 2>/dev/null)
  SSL  := $(shell brew --prefix openssl@3 2>/dev/null)
  CFLAGS  += -I$(BREW)/include -I$(SSL)/include
  LDFLAGS += -L$(BREW)/lib -L$(SSL)/lib
endif

SRC = proxy.c snell_tunnel.c snell_shape.c snell_prng.c snell_inter_pad.c snell_salt.c snell_crypto.c
HDR = snell_tunnel.h snell_shape.h snell_crypto.h snell_prng.h snell_salt.h

.PHONY: all clean
all: snell-proxy

snell-proxy: $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o snell-proxy $(SRC) $(LDFLAGS) -luv

clean:
	rm -f snell-proxy
	rm -rf snell-proxy.dSYM
