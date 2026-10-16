# Reproducibility, artifact identity and claim provenance

## What can be reproduced

**Framework validation:** Python-standard-library tests and syntax checks can run without NGINX binaries or benchmark hosts. They establish implementation-level invariants, not measured acceleration.

**Portable lifecycle smoke:** `create --deployment environments/local/single-host.json` and `plan <experiment-id>` generate an experiment identity and deterministic run order without a network benchmark. It is not a four-repetition controlled campaign.

**Functional integration:** pinned dependencies, NGI541 engine installation, NGINX/QUIC build and regression tests establish working TLS/HTTP/3 integration. Functional correctness alone is not performance evidence.

**Controlled scientific execution:** qualification, frozen source/corpus/runtime SHA-256, reference topology, predeclared schedule, paired measurement, deterministic analysis and publication verification are all required. The current executable reference configs are environment-specific.

## Claim traceability

An externally auditable result must identify, at minimum:

| Class | Required record |
| --- | --- |
| Scientific definition | Frozen protocol version and SHA-256, workload object profile/corpus digest, condition set, pairing policy |
| Source/runtime | Exact Git revisions, NGINX/NGI541/library/toolchain SHA-256 and patches |
| Deployment | Client/DUT hardware roles, CPU/ISA, OS, NIC, NUMA, network capacity, frequency/thermal policy |
| Qualification | Network, load generator, HTTP/3/TLS, corpus and host telemetry gates |
| Raw evidence | Complete ordered run/attempt records, failure reasons, timing, HTTP counts, host sensors |
| Analysis | Accepted-attempt selection, within-condition pairs, metric definitions, summary and derived figures |
| Publication | Revalidated result bundle, SHA manifest and stable external archive identifier **once issued** |

## Non-negotiable validity rules

Four paired repetitions per condition, balanced/rotating order, strict main measurement interval, zero HTTP failures, no throttling, ≤85% client total CPU and ≤95% client busiest-core CPU, no metric-dependent retry and retention of all valid samples. Baseline workload planning must complete before seeing candidate performance. Any material deviation must be disclosed as a different methodology, not silently labeled R6.5.4.5.

## Current local result record

A previously accepted bandwidth-limited local paired execution reported ~8.216% lower DUT CPU seconds/GiB, 44/48 CPU-cost pair wins, approximately unchanged application goodput and ~0.248% lower **estimated** energy/GiB. The repository does not currently supply a public Zenodo DOI or raw archive URL for those figures; this statement is a **local evidence summary**, not a substitute for independently inspectable preserved measurement data. Once an external archive is verified, its DOI and artifact SHA can be placed in `README.md` and the release record.

## Immutability and deterministic derivatives

Inputs, schedule and manifest are frozen, raw attempts append-only, lifecycle state explicitly mutable, and summaries/plots deterministically regenerated from the raw/schedule pair. A different deployment has different provenance even if the same protocol hash is used. A successful `results --experiment` export validates the chain and creates a publication bundle under ignored `artifacts/results/`.

See [analysis](analysis.md), [experiment schema](experiment-schema.md), [portability](portability-contract.md) and [experimental scope](experimental-scope.md).
