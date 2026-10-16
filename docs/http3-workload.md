# HTTP/3 scientific-object workload contract

## Request and server roles

The pinned HTTP/3-capable client requests deterministic scientific objects over HTTP/3/QUIC with verified TLS 1.3 and cipher `TLS_AES_128_GCM_SHA256`. Identical client binary, object sequence, HTTP semantics, network path and planned load are used for the baseline NGINX/OpenSSL server (`stock`) and the NGI541-integrated server (`ngi541-direct`). The server variants execute **sequentially** in the balanced paired schedule.

NGI541 substitutes the supported **server-side AES-GCM QUIC packet-protection path** and **AES-based header protection**; NGINX/OpenSSL retain TLS 1.3 handshake, key derivation, certificate machinery and QUIC control flow. AES-CTR supports the header mask and is not a negotiated TLS cipher suite.

## Scientific input materialization

`scientific-corpus` realizes content-addressable objects according to the CLAS12, LCLS and HACC-inspired definitions. A valid transport check confirms content/expected hashes, not merely HTTP success. HACC uses the frozen planner subset and must never be described as transferring a complete real HACC dataset.

## Attempt execution and validity

Each scheduled attempt stages the exact hashed server executable, shared libraries and run-specific NGINX config. Server prestart UDP port state, remote HTTP/3 readiness and stable shutdown/release are checked before/after requests. Warm-up and readiness events are excluded from the strict main measurement window. Client execution and server telemetry are recorded separately, and all HTTP request failures invalidate an observation.

The accepted protocol requires no host throttling and adequate client headroom (≤85% aggregate CPU busy, ≤95% busiest core); sampling is nonblocking in the measurement window. Failed attempts remain append-only evidence. The framework must not select a later attempt merely because it improves the outcome.

## Outputs

Primary: `application_goodput_mbps` and `dut_process_cpu_seconds_per_gib`. Secondary: `dut_estimated_energy_j_per_gib` and generator aggregate/core CPU busy percentages. Report measured quantity and unit together; goodput and cryptographic primitive speed are not interchangeable.

See [topology](topology.md), [integration](integration-model.md) and [analysis](analysis.md).
