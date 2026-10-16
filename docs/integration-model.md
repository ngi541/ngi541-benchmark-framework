# Server-side cryptographic integration boundary

## Baseline and candidate

The comparison deliberately changes the **NGINX QUIC server cryptographic execution path**, not the load generator, TLS endpoint semantics or the physical network:

| Layer | Baseline (internal `stock`) | Candidate (`ngi541-direct`) |
| --- | --- | --- |
| HTTP/3 and QUIC state | NGINX | Same NGINX integration base |
| TLS 1.3 handshake and key schedule | OpenSSL | OpenSSL |
| Certificate handling and peer verification | OpenSSL / client validation | Same |
| AES-based QUIC payload AEAD | Existing OpenSSL-backed QUIC path | Direct NGI541 prepared-key AES-GCM API |
| AES-based QUIC header mask | Existing path | NGI541 AES-based execution |
| HTTP/3 client, workload corpus and link | Pinned common setup | Same |

In the candidate, NGINX obtains QUIC protection keys through its existing TLS machinery, prepares the supported NGI541 key object, then invokes NGI541 for eligible QUIC protection operations. NGI541 does **not** replace OpenSSL as a full TLS provider or PKI library. This is direct data-path integration, distinct from an OpenSSL provider.

## Why system-level measurement is necessary

Per-packet AEAD overhead interacts with QUIC packetization, event-loop scheduling, socket queues, CPU contention and link service capacity. A cryptographic primitive's cycles/byte metric is not sufficient evidence for application-level HTTP/3 throughput or CPU/GiB.

The framework measures normalized server CPU cost per delivered GiB, observed application goodput, diagnostic load-generator CPU headroom and supported same-host energy estimates under matched client and workload conditions.

## Source and validation boundary

The repository carries the pinned NGINX patch in `integration/patches/nginx-1.31.6/`, the nghttp2 load-generator patch, version pins in `integration/versions/versions.env`, and NGINX regression tests in `integration/tests/nginx-tests/`.

The engine itself is separately maintained at [ngi541/ngi541](https://github.com/ngi541/ngi541). Build/integration validation and transport-security qualification are required before numerical comparisons are accepted.

## Not implemented in this reference experiment

Conventional TLS-over-TCP record encryption, reverse-proxy dual-leg TLS crypto, ChaCha20-Poly1305 and generic provider integration are **not** implied by this NGINX QUIC result. Each requires its own integration boundary and explicit experiment definition.

See [HTTP/3 workload](http3-workload.md) and [scope](experimental-scope.md).
