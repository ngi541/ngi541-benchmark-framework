# Scientific scope and claim boundary

## Implemented system under test

**NGINX QUIC/HTTP/3** delivering deterministic scientific-style objects. The treatment is specific to **server-side supported AES-based QUIC packet protection (AES-GCM)** and **header protection (AES execution)** via the NGI541 direct public API. The baseline uses the normal NGINX/OpenSSL cryptographic path. The client is unchanged; OpenSSL still owns TLS 1.3 handshake, certificates and key schedule. The current evaluation enforces `TLS_AES_128_GCM_SHA256` and verified transport; AES-based header protection is **not** a separate cipher suite.

This is a system-level data path experiment. NGI541's independent primitive performance is a different scope and is not inferred from NGINX HTTP/3 results.

## Transfer workloads and scientific relevance

The deterministic corpus contains three **shape models**, with their own versioned JSON parameters:

- [CLAS12 event stream](../benchmark/scientific-profiles/clas12-event-stream-v1.json): event-oriented object transfer.
- [LCLS detector frames](../benchmark/scientific-profiles/lcls-detector-frame-v1.json): detector-frame-oriented transfer.
- [HACC multifile dataset](../benchmark/scientific-profiles/hacc-multifile-dataset-v1.json): multifile/multi-object transfer, **evaluated through a frozen planner subset rather than a full archive**.

These workloads encode reproducible transfer structure relevant to scientific data movement and the general Science DMZ/DTN research context; they are not actual instrument output, detector-validated traces, official datasets or proof of equivalence to ESnet traffic.

## Measured claims

Application goodput and DUT CPU seconds per delivered GiB are **primary**. Estimated energy/GiB and generator CPU headroom are **secondary**. Validity includes transport correctness, zero HTTP errors, no throttling and generator CPU ≤85% total/≤95% busiest core. A controlled paired observation is defined by frozen condition and repetition, not post-hoc sample matching.

Current local evidence supports an **environment-specific CPU-efficiency observation** under a bandwidth-limited service envelope. It does not validate >10 Gbit/s performance, multiple CPU families, commercial hardware acceleration, all cipher suites, security certification, side-channel properties, or end-to-end instrument-to-HPC deployment.

## Generalization boundaries

Scientific protocol identity is independent of provider and hardware. **Scientific conclusion is not**: a new NIC/CPU/NUMA/topology requires its own qualification and execution provenance. Different network capacity can reveal bottlenecks not visible in the local campaign. The protocol may be reused without pretending that local results apply elsewhere.

See [methodology](benchmark-methodology.md), [integration](integration-model.md) and [topology](topology.md).
