# Controlled HTTP/3 benchmark methodology

## Controlled independent variable

The implemented comparison changes one explicit server-side ownership boundary: **the NGINX QUIC AES packet-protection and AES-based header-protection execution path**. Baseline = standard NGINX/OpenSSL-backed path (`stock`); candidate = NGINX invoking the NGI541 prepared-key public API for supported operations (`ngi541-direct`). The same pinned client, scientific object contents, TLS 1.3 cipher suite, QUIC/HTTP/3 semantics, measured network path and experiment schedule are used within each pair. NGINX/OpenSSL retain handshake, certificate verification, key derivation and protocol control.

Protocol throughput is not interchangeable with isolated AES-GCM throughput: a delivered scientific HTTP/3 object is segmented into QUIC packets and cryptographic operations, interacting with socket processing, packet scheduling and CPU/interrupt behavior.

## Frozen R6.5.4.5 controls

| Domain | Protocol value / interpretation |
| --- | --- |
| Repetitions | 4 paired repetitions per condition |
| Pairing | `paired-balanced`; within-condition, within-repetition |
| Order | `rotating-rounds`, `balanced-by-condition-round` |
| Measurement | strict main window; 1-second telemetry sampling |
| HTTP errors | zero allowable |
| Host throttling | forbidden for valid observations |
| Client aggregate CPU | maximum 85% busy |
| Highest client single core | maximum 95% busy |
| Retry | `no-metric-dependent-retry` |
| Outliers | `retain-all-valid-runs` |
| Summary | `median-paired-delta` |
| HACC scope | `repeat-frozen-planner-subset`; not a full dataset |

## Qualification and bias resistance

**Before execution:** network-qualify checks link capabilities; network-evidence derives a compatible service envelope; scientific-corpus binds deterministic object identities; transport-security proves correct verified HTTP/3 behavior for both variants; telemetry qualification proves sensor/readiness availability. Only then does `workload-planner` calibrate offered load **against baseline alone**. `final-freeze` locks schedule, object hashes, source/runtime binaries and validity rules before NGI541 measurement.

**During execution:** each run is scheduled in advance, qualified host state is sampled, warm-up/readiness traffic is excluded, and invalid HTTP outcomes, thermal throttling or client saturation invalidate the observation. Raw attempt records are append-only; performance metrics may not be used to choose retries or exclude inconvenient data.

**During analysis:** matching is by condition and repetition. The within-pair relative delta is `(candidate / baseline − 1) × 100%`; lower DUT CPU seconds/GiB is beneficial, unlike higher application goodput. The distribution and direction of all paired observations must accompany median deltas. Do not treat secondary estimated energy as external power-meter evidence.

## Definitions and validity scope

- `application_goodput_mbps`: successfully delivered application data over the measured interval. It can remain constrained by the network even when CPU cost improves.
- `dut_process_cpu_seconds_per_gib`: server-process CPU cost normalized by delivered GiB; measures execution resource efficiency, not link speed.
- `dut_estimated_energy_j_per_gib`: same-host estimate derived from supported telemetry, reported as secondary evidence.
- Load-generator busy percentages: proof of measurement headroom, not server performance metrics.

Scientific workload profiles represent CLAS12 event-stream, LCLS frame and HACC multifile transfer shapes, not real collaboration archives. In particular, only a frozen HACC subset is executed. Results are scoped to recorded system architecture, topology, NIC, OS, software/patch revision and service envelope. The accepted local measurement is **not** a general high-speed fabric claim.

The normative scientific protocol is [`../benchmark/protocols/http3-paired-r6.5.4.5.json`](../benchmark/protocols/http3-paired-r6.5.4.5.json) with SHA-256 `99805dd378310ec539246e655d3f2a690036e4e50ac83c27c52765d1a50fb387`.

See [analysis](analysis.md), [execution lifecycle](experiment-lifecycle.md) and [experimental scope](experimental-scope.md).
