# NGI541 / CloudLab — M2 Scientific Telemetry and Attribution Protocol

**Document:** M2 Evidence Contract v0.2 (design draft, NOT a frozen scientific protocol)
**Research design:** A = NGINX HTTP/2 / TCP / OpenSSL; B = NGINX HTTP/3 / QUIC / OpenSSL; C = NGINX HTTP/3 / QUIC / NGI541 server-side substitution.
**Direction:** HTTP GET, server → client. NGI541 never installed or linked into the client.
**Status:** Design / requirements / evidence boundaries only. NOT an executed high-speed benchmark.
**Historical boundary:** Immutable R6.5.4.5 protocol SHA-256 `99805dd378310ec539246e655d3f2a690036e4e50ac83c27c52765d1a50fb387`.

## 1. Objective and what can be claimed

> How much of the high-speed QUIC/HTTP/3 efficiency gap is attributable to cryptographic execution, and under which workload and hardware conditions can an optimized crypto engine meaningfully reduce that gap?

Three claims must remain distinct:

1. **Observed total transport gap (A vs B):** whole-stack contrast H2/TCP/TLS versus H3/QUIC/TLS. Not a cryptographic-only effect.
2. **Observed intervention effect (B vs C):** primary controlled causal contrast within the H3 stack, with only server-side QUIC cryptographic execution substituted. An intervention effect is not identical to the entire contribution of crypto to the H2/H3 performance gap.
3. **Mechanistic attribution:** independently measured work in server packet protection, header protection, packet I/O, transport logic and memory; used to assess how the intervention acts and where remaining bottlenecks lie.

**Caveat:** Functional smoke A/B/C (HTTP 200, TLS 1.3, `TLS_AES_128_GCM_SHA256`, identical 32 KiB SHA-256) demonstrates interoperability/correctness, not high-speed scaling or real 1-RTT crypto invocation counts. Shared-library linkage of NGI541 in C is necessary but not proof that every applicable packet used NGI541. Explicit backend-invocation counters and fallback counters are needed.

## 2. Non-negotiable evidence principles

- Freeze experimental hardware, OS, kernel, NIC driver/firmware, source SHA-256, runtime configs, client, corpora, measurement windows and offload states **before** confirmatory results.
- No automatic retry of a failed scientific slot; retain attempts and exact validity causes; deviations need separately versioned methods.
- Keep **P: primary performance** (low-overhead), **C: crypto attribution** (instrumented), and **K: kernel/PMU attribution** (profiling) as separate data collections under matched conditions. Do not combine values as if acquired in the same run.
- No missing value is silently replaced by zero. Use `measured`, `unavailable`, `not_applicable`, or `invalid`; state a reason for the last three. This requires a **new** M2 schema version; the Stage 1 `abc_measurements.py` currently accepts only `measured`/`unavailable`.
- Distinguish payload bytes, QUIC AEAD plaintext bytes, QUIC ciphertext/tag bytes, UDP datagrams and physical NIC packets. QUIC packet, datagram, and NIC packet counts need not match because of coalescing, GSO/GRO and other encapsulation.
- Every telemetry field must encode `host_role`, `scope`, `collection_mode`, `source`, `unit`, `window_id`, `sampling_interval`, `available/state`, `error`, `overhead_calibration_id` where relevant.

## 3. Measurement modes

| Mode | Purpose | Collect | Exclude | Scientific claims |
|---|---|---|---|---|
| P — primary | System performance without meaningful perturbation | Monotonic start/end snapshots of process or cgroup CPU, host CPU cpuset, NIC and kernel counters; load generator completion/byte data; client headroom; independent validity proofs | Per-call logging, synchronous per-packet timestamps, full tracing, heavy PMU sampling | A/B/C goodput and CPU efficiency, balanced B/C effect |
| C — crypto | Packet crypto execution mechanism | Instrumented counts at common NGINX QUIC call sites; call input lengths, directions, epoch, backend, errors, key preparations/reuse; optional calibrated timings | Claims of unperturbed peak goodput | Per-operation costs, backend actually executed, possible fallback, cost allocation |
| K — kernel/PMU | Identify noncrypto bottlenecks | perf stat/record, hardware counters, softirq/IRQ, syscall sampling, ethtool/netdev, NUMA, scheduling, driver queue stats | Aggregating distinct windows or different event scopes | CPU microarchitectural and packet I/O hypotheses |

Before trusting P counters, compare P-monitoring enabled vs disabled under locked conditions and define an equivalence margin (candidate target ±1%, statistically justified). C/K overhead must be measured, never assumed zero; do not use C/K goodput as P goodput.

## 4. Mandatory data definitions

### 4.1 Application throughput and integrity

- `valid_application_payload_bytes`: unique successful application payload bytes in the **main window**, excluding protocol headers and all retransmissions; do not equate with NIC TX bytes. Note that h2load's existing stream-accounting patch is not proof of SHA-256 verification on every completed object. Design an explicit content-integrity method and measure its overhead; functional smoke hashes alone are not full-run payload proof.
- `main_window_seconds`: elapsed monotonic time of a precisely specified measurement window; client completions and CPU/NIC deltas must refer to compatible boundaries.
- `application_goodput_mbps = 8 * valid_application_payload_bytes / main_window_seconds / 1e6` (decimal Mbit/s). For sustained traffic, predeclare ramp, warm-up and window length.
- `completed_valid_objects`, `failed_requests`, `timed_out_requests`, `negotiated_protocol`, `tls_version`, `cipher`, `verified_peer`.
- For A: negotiated `h2`; B/C: `h3`; all: TLS 1.3 + AES-128-GCM policy unless new protocol revision.

### 4.2 CPU accounting

- `dut_process_cpu_seconds`: main-window delta of all applicable NGINX worker CPU user+system time. Include child worker lifecycle, process identity and restarts. Prefer dedicated NGINX cgroup `cpu.stat` when available; it measures cgroup tasks, not independent kernel softirq work; verify cgroup ownership and child coverage.
- `dut_process_cpu_seconds_per_gib = dut_process_cpu_seconds / (valid_application_payload_bytes / 2^30)`.
- `dut_host_cpu_active_seconds`: main-window non-idle execution time **on predeclared DUT CPU set**, from `/proc/stat`, with CPU accounting formula frozen and separately reporting iowait, steal, irq, softirq. Host value includes process CPU; never add it to process CPU.
- `dut_host_cpu_seconds_per_gib = dut_host_cpu_active_seconds / (valid_application_payload_bytes / 2^30)`. Label this **allocated CPU-set active time**, not energy or unique NGINX/kernel causality: unrelated background work and IRQ placement must be constrained and measured.
- `loadgen_total_busy_percent` and `loadgen_max_single_core_busy_percent`, with explicit allocated capacity denominators. Record loadgen throttling, process CPU, RAM and actual throughput. Same client binary and settings for B/C.
- Thermal/frequency/power-gating signals, CPU governor, cpuset, NUMA/IRQ affinity, SMT, turbo and migrations must be frozen or documented.

### 4.3 Cryptography (DUT)

**NGINX common semantic probe points for B/C** (from pinned NGINX 1.31.6 QUIC integration):

1. `ngx_quic_crypto_seal()`: 1 crypto seal invocation, successful/failed, AEAD plaintext input length, encryption level (Initial/Handshake/1-RTT), backend (`openssl`/`ngi541`), direction (`server_tx`).
2. `ngx_quic_crypto_open()`: 1 open invocation, successful/failed/auth-failed, ciphertext length excluding authentication tag, encryption level, backend, direction (`server_rx`).
3. `ngx_quic_crypto_hp()`: each header-protection operation, direction, encryption level, backend, success.
4. `ngx_quic_crypto_backend_init()` and corresponding key/HP creation and destruction: key generation/preparation events and active key reuse; distinguish TLS/QUIC key derivation from key preparation in the crypto engine.

For C, count actual calls to `ngi541_crypto_aead_encrypt_prepared`, `ngi541_crypto_aead_decrypt_prepared`, and the NGI541 AES-CTR prepared-key header-protection API. Include explicit **OpenSSL fallback counts** in C, so `C linked to NGI541` cannot masquerade as `C executed NGI541`. Both B and C receive semantically identical counters at the **same QUIC call-site boundaries** and same frozen instrumentation recipe. Attribute only 1-RTT data-plane operations to the principal sustained-data mechanism claim; count Initial/Handshake separately.

Report `{calls_success, calls_failure, input_bytes, backend, encryption_level, direction}` per operation. Packet-protection ciphertext adds a 16-byte tag; do not treat AEAD input bytes as NIC bytes. Header protection uses a sample and AES-CTR/related mask computation distinct from packet AEAD per RFC 9001.

**No fabricated SIMD batching:** If current NGINX calls prepared-key APIs packet by packet and does not form real multi-packet batches, report `batching=not_implemented_or_unobserved`, not a inferred SIMD batch size. Record actual CPU ISA implementation, not merely available CPU flags.

Crypto duration/cycles: prefer separate profiling/perf-based function attribution. Per-call clocks in hot paths can drastically disturb throughput. If used, calibrate timer cost, core migration and frequency effects; maintain a separate C profiling run. Verify native OpenSSL assembly/inlining leads to appropriate symbolization and comparable wrapper boundaries.

### 4.4 Packet I/O (DUT and loadgen)

- Dedicated experiment NIC: TX/RX bytes, packets, drops, error counters from `/sys/class/net/<iface>/statistics`, `ip -s -s link`, and driver `ethtool -S`. Record driver/firmware and **counter scope** (netdev or physical port, GSO/GRO aggregation). Snapshot before/after P window; never infer on-wire packets directly from UDP send calls.
- IPv4/TCP/UDP kernel protocol counters (`/proc/net/snmp`, `nstat`, `/proc/net/netstat`) with baseline deltas. These may be host-wide, not specific to an experiment interface; label scope.
- `quic_gso` state and UDP_SEGMENT availability; Linux `quic_gso` defaults to off in NGINX unless configured. Freeze in primary, explore enabled/disabled only in later predeclared sensitivity work.
- Syscall counts `sendmsg`, `sendmmsg`, `recvmsg`, `recvmmsg`, etc., collected separately in K via eBPF/perf trace with bounded overhead; avoid full strace for P.
- Per-CPU `/proc/softirqs`, `/proc/interrupts` and `perf` kernel samples (where possible), NAPI/softirq counters, RSS queue/IRQ placement; avoid attributing all NET_TX/NET_RX softirq to DUT without isolation checks.
- TCP retransmissions apply to A; QUIC loss/retransmission events apply to B/C and need QUIC-internal telemetry. Non-applicable fields are **not zero**.

## 5. Evidence hierarchy, causal interpretation and dual-load analysis

**Causality:** Only B/C, in a matched execution environment with the specified server crypto substitution, identifies its *system-level intervention effect*. To claim a crypto bottleneck, additionally show (i) DUT capacity limitation, (ii) substantive attributed crypto work/cost, (iii) correlated variation in packet/crypto load under controlled workload, and (iv) alternative ceilings ruled out or quantified.

Primary effects:

`delta_CPU_cost_pct = 100 * (CPU_seconds_per_GiB_C / CPU_seconds_per_GiB_B - 1)` (negative favors NGI541), at comparable valid-byte windows and predeclared traffic conditions.

`delta_goodput_pct = 100 * (goodput_C / goodput_B - 1)`, at matched offered workload. Estimate uncertainty with blocked paired comparisons, not with all time-series samples treated as independent trials.

H2/H3 gap:

`gap_closure = (goodput_C - goodput_B) / (goodput_A - goodput_B)` **only** when H2 goodput clearly exceeds H3 and the denominator is reliably resolved. **Never** call it the fraction of H2/H3 overhead caused by crypto.

Run **two scientific views**:

1. **Iso-workload / iso-goodput:** same offered request rate or delivered rate, below saturation, so differences in CPU/GiB are interpretable as per-unit cost. Document congestion/queue conditions.
2. **Capacity curve:** step up offered load until server saturation (provided client headroom and qualified network), then examine max goodput and bottleneck transition. Do not assume 100 GbE link implies 100 Gb/s application goodput.

C can reduce CPU cost without improving goodput if a different part of the system is limiting, and this is still a useful result. Separate queueing/latency from throughput saturation.

## 6. Validity gates and allocation controls

### Primary P: hard gates

- Exact version and hashes of source, patch, binary, linker environment, client, scientific corpus, OS, kernel and server/client configs. C's `NGI541` backend verified in C-mode 1-RTT evidence before issuing a claim about crypto substitution.
- Verified `h2`/`h3`, TLS 1.3, AES-128-GCM, peer certificate and response correctness; no HTTP failures in measurement window; scientific object-integrity validation with documented coverage and overhead.
- All bytes/CPU deltas use declared matching main-window boundaries; no warmup or cooldown leaks; no counter resets or PID reuse errors.
- Same B/C client binary and effective settings, same server code outside crypto patch, CPU affinity, worker count, response payloads, I/O parameters, offload policy.
- Client not saturated. Provisional baseline gate ≤85% aggregate client allocated CPU and ≤95% peak client core, until future protocol declares alternate gates; no unnoticed client throttling.
- No unexplained NIC drops/errors, problematic packet loss, link resets, or DUT throttling violating frozen gates.
- Experiment data link separate from CloudLab management network. No unexplained core/IRQ/NUMA migrations.
- Failed attempts append-only; no automatic re-run chosen by performance outcome.

### C and K: attribution quality gates

- Matched B/C operation semantics and backend evidence. Unobserved events are `unavailable`, never zero.
- Timing/sampling overhead calibrated (counter-only, sampled, timing-enabled) and labeled.
- Perf event scope (`pid`, `cgroup`, `CPU set`) and `time_enabled`/`time_running` ratio retained to detect PMU multiplexing. Explicitly do not claim full unbiased counts when multiplexing/scaling dominates.
- Kernel/NIC counters record device/driver scope and offload semantics. A/B/C protocol-inapplicable counters use `not_applicable`.
- All filenames and run status signed by SHA-256 checksums and preserved raw, whether PASS or FAIL.

## 7. Pilot vs confirmatory study

The 3 scientific workload classes × 3 concurrency conditions × 3 arms × 4 repetitions = **108 measurement slots** are a **pilot characterization**, not automatically a publication-grade confirmatory sample size. Preserve B/C matched pairs and balance order. Record failure/retry policy and dependence blocks.

Use pilot variance to predeclare: (a) primary endpoint hierarchy, (b) meaningful relative effect threshold, (c) statistical power / precision, (d) number of independent paired blocks, (e) multiple-comparison strategy for many conditions, and (f) mandatory hardware replication. The confirmatory population and schedule must be frozen **before** examining its results.

A/B contextual comparisons should control temporal drift by blocked scheduling. Differences among Intel and AMD are effect moderation experiments rather than raw cross-machine score competitions.

## 8. Mandatory evidence bundle

For every attempt, preserve:

- `attempt-manifest.json`: `study_revision`, `contract_revision`, arm, measurement mode P/C/K, condition, attempt ID, pair block, UTC timestamps, local monotonic start/end, validity status.
- `identity/`: raw `uname`, `/proc/cpuinfo`, `lscpu`, `lscpu -e`, `numactl -H`, `ethtool -i/-k/-l`, `ip addr`, `ip route`, CPU frequencies/governor/microcode, OS, NIC firmware, binaries/source hashes, linker dependencies, protocol/config/corpus SHA-256. Sanitize exposed node IDs and IPs for publication where necessary.
- `primary/`: raw loadgen output, completed requests/bytes, NGINX worker PID/cgroup identity, start/end process/cgroup `/proc/stat`, client CPU, NIC/UDP/TCP counters; resulting observation with units and provenance.
- `crypto/`: counts at NGINX common QUIC seal/open/hp sites; backend fallback; key creation; operation/byte histograms and epoch; compiler-inlining/symbol evidence, calibration.
- `kernel/`: raw `perf stat`/`perf record`, `ethtool -S`, `nstat`, `/proc/softirqs`, `/proc/interrupts`, syscalls and offload/IRQ placement; sampled overhead evidence.
- `validity/`: ALPN/TLS proof, integrity coverage, error/timeout/drop checks, client load, CPU throttling, collector availability, failed-attempt reasons.
- `SHA256SUMS` over all included artifacts, generator/analysis source revision, exact analysis command and environment.

## 9. Additive implementation order and definition of done

**M2.0 — Contract/schema:** New additive M2 schema (distinct from Stage 1 draft), metric registry and validators: exact unit/source/scope/window; `measured`/`unavailable`/`not_applicable`/`invalid`; no silent zeros; tests for forbidden assertions. Historical modules and R6.5.4.5 unchanged.

**M2.1 — Linux primary telemetry:** Linux snapshot/interval collector for DUT and client (process or cgroup CPU, cpuset host CPU, NIC per interface, TCP/UDP kernel data, affinity, governors); orchestrator-aligned windows, checks for resets, raw+normalized artifacts; fixture tests. Docker is for functional validation, **not bare-metal CPU/NIC performance evidence**.

**M2.2 — Crypto attribution:** Add conditional counters to new experimental NGINX B and C builds at **same QUIC call sites**. C tracks NGI541 invocations plus any OpenSSL fallback. B counts OpenSSL. Preserve an **uninstrumented primary binary**. Never silently patch the historically frozen binary/NGI541 source. Build and runtime hashes distinguish instrumented variants.

**M2.3 — Kernel attribution:** read-only hardware capability probe; perf statistic/sample collectors and optional eBPF/QUIC logging; no administrator settings or NIC offloads changed automatically. Availability constraints recorded as data.

**M2.4 — Cross-layer validity and calibration:** P collector perturbation study; C/K perturbation study; byte/packet accounting and time window alignment; B/C backend invocation proof; schema and integration tests; 3-arm functional smoke repeated after instrumentation changes.

**M2.5 — High-speed experimental freeze:** freeze novel protocol identity, exact hardware, matrix, confidence interval/power policy, exclusions, and evidence pipeline, only then execute CloudLab pilot/confirmatory runs.

**M2 is not complete** until all mandatory P signals and B/C backend evidence are produced on Linux and comprehensive error paths tested. Crypto/PMU measurements may remain optional for *primary throughput validity*, but a publication claim of crypto bottleneck attribution requires credible crypto/packet evidence.

## 10. Normative reference points

- QUIC security, packet/header protection: https://www.rfc-editor.org/rfc/rfc9001
- Linux network statistics and scope: https://docs.kernel.org/networking/statistics.html
- Linux TCP/UDP SNMP counters: https://docs.kernel.org/networking/snmp_counter.html
- Linux procfs fields: https://www.kernel.org/doc/html/latest/filesystems/proc.html
- cgroup v2 `cpu.stat`: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
- Linux perf multiplexing/time enabled/running: https://man7.org/linux/man-pages/man2/perf_event_open.2.html
- NGINX QUIC GSO: https://nginx.org/en/docs/http/ngx_http_v3_module.html
