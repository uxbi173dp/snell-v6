# Snell v6 (b2) client

An opensource reimplementation of the Surge **Snell v6 (beta2)** tunneling protocol
(client side), reverse-engineered from the reference server binary and verified end-to-end
against a live server.

## Build & run
```
make
./snell-proxy --server <host> --server-port <port> --psk <psk> --socks5 1080 [--http 8080]

# test
curl --socks5 127.0.0.1:1080 -o /dev/null https://hil-speed.hetzner.com/1GB.bin
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 1024M  100 1024M    0     0  24.8M      0  0:00:41  0:00:41 --:--:-- 25.9M
```
