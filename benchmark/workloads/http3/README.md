# HTTP/3 workload adapter

The HTTP/3 workload adapter executes controlled NGI541 experiments through NGINX QUIC/HTTP/3.

It is the current application-level workload used to evaluate whether NGI541 changes the resource cost of encrypted data delivery without changing the intended transport and application semantics.

## Variants

The current paired methodology compares:

```text
stock
ngi541-direct
```

`stock` uses the normal NGINX/OpenSSL QUIC cryptographic path.

`ngi541-direct` uses the NGI541 integration for supported QUIC packet-protection operations while retaining the surrounding NGINX/OpenSSL TLS 1.3 and certificate machinery.

## Per-run execution

For each frozen scheduled run the adapter:

1. resolves the sealed variant;
2. verifies required binary/library SHA-256 identities;
3. stages exact runtime artifacts;
4. resolves the deterministic scientific object;
5. generates run-specific NGINX configuration;
6. establishes the required TLS test identity;
7. validates NGINX configuration;
8. starts the server;
9. verifies HTTP/3 readiness;
10. performs warm-up;
11. executes the frozen measurement phase;
12. records client/server outputs and telemetry;
13. evaluates validity gates;
14. persists append-only raw evidence;
15. removes transient attempt runtime state when configured.

## Transport contract

The current controlled scientific path requires:

```text
HTTP/3 only
TLS 1.3
TLS_AES_128_GCM_SHA256
peer verification enabled
0-RTT disabled
```

Transport-security qualification occurs before performance execution.

## Scientific objects

The workload can consume deterministic objects produced from the scientific profile/corpus layer. Object identity and expected content hash are verified so application delivery is not accepted solely because an HTTP request returned successfully.

## Measurement semantics

The main measurement phase is separated from warm-up and readiness traffic.

Current primary analysis includes:

```text
application goodput
DUT process CPU seconds per delivered GiB
```

Secondary evidence includes estimated same-host energy cost where available and load-generator CPU headroom.

The adapter does not decide statistical significance or publication claims. Those responsibilities belong to the frozen protocol and analysis layer.

## Scope

HTTP/3 is currently the first fully implemented network-data-path workload.

The framework architecture permits future workload adapters, but a new workload class should be added only with an explicit scientific question, reproducible execution contract, and corresponding validation tests.
