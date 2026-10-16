# HTTP/3 / QUIC scientific-object execution

The implemented application workload measures end-to-end delivery of deterministic scientific objects over **HTTP/3, QUIC and TLS 1.3**, not standalone AES throughput.

The client is a pinned HTTP/3-capable load-generator runtime and remains unchanged across comparison pairs. The server variants are the baseline NGINX/OpenSSL QUIC cryptographic path (internal name `stock`) and the same NGINX server with NGI541 direct AES-GCM packet protection and AES-based header protection (`ngi541-direct`). Handshake, certificate validation, key derivation and the surrounding protocol logic retain their existing ownership in NGINX/OpenSSL.

The selected transport contract enforces `TLS_AES_128_GCM_SHA256`, verified peer and disabled 0-RTT. AES-CTR is used as an implementation mechanism for the QUIC header-protection mask, **not** as a TLS cipher suite.

An attempt stages exact runtime binaries and libraries, validates object hashes, checks server readiness, runs warm-up, records only the main measurement window, samples the DUT, retains raw client/server diagnostics and evaluates validity. Server and client resource evidence are different measurements.

The primary quantities are **delivered application goodput** and **DUT process CPU seconds per delivered GiB**. Estimated energy/GiB is explicitly secondary and depends on available host instrumentation. Failure and outlier policies are specified by the frozen protocol.

See [full HTTP/3 contract](../../../docs/http3-workload.md), [integration](../../../docs/integration-model.md) and [experiment topology](../../../docs/topology.md).
