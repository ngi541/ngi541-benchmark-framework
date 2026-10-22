# NGI541 — M2.0 + M2.1 Additive Implementation (2026-10-22)

**State:** experimental telemetry software / NOT a frozen confirmatory study protocol.

## Provenance and historical boundaries

This package adds new `abc_m2_*` Python modules, two dedicated schemas, one copy of the exact existing v0.2 metric registry (26 entries), an unmodified copy of the v0.2 scientific evidence protocol, and tests. It MUST NOT change the following:

- Historical R6.5.4.5 protocol, SHA-256 `99805dd378310ec539246e655d3f2a690036e4e50ac83c27c52765d1a50fb387`.
- Baseline A/B/C schedule: 9 workload/concurrency conditions; 3 arms; 4 preliminary repeats = 108 pilot slots; precommitted paired B/C order.
- Existing `abc_measurements.py`, v1 draft `abc-observation-draft.schema.json`, `abc_design.py`, compiled binaries, patch and historical benchmark.
- Scientific question and definitions of estimands; A↔B is total transport reference, B↔C is controlled crypto substitution intervention, attribution requires independent mechanisms.

Additive contract revision: `ngi541-abc-m2-0.2-additive-r1` (machine evidence schema v2). Retain old v1 validation semantics; NEVER auto-migrate historic observation records.

## Preserved / reserved metrics

The unchanged M2 v0.2 registry preserves all 26 metrics, all four states (`measured`, `unavailable`, `not_applicable`, `invalid`), and P/C/K modes. Metrics not yet collectible at M2.1 remain defined and are NOT silently downgraded or mapped to zero. Crypto 1-RTT calls/backends/fallback, PMU cycles/instructions, syscall sampling, QUIC loss and TCP retransmits remain in research scope. No C/K values are fabricated by P-mode.

## Supported capture (M2.1)

Read-only Linux snapshot, selected CPU indexes, one NIC, optional dedicated cgroup v2 (`cpu.stat`), all raw start/end sysfs NIC and `/proc/stat` counters, `/proc/net/snmp`, `/proc/net/netstat`, UTC timestamp and host-local monotonic before/after capture bracket. Record cgroup device/inode identity to guard against cgroup reuse and host boot ID. `derive` requires matching run ID, attempt, window, role, boot, hostname, kernel, tick frequency, CPU list, NIC, network namespace scope and optional cgroup identity. Reject negative counter deltas. Preserve raw protocol deltas rather than equate TCP/UDP to QUIC packets.

Measured M2.1 outputs: NIC byte/drop deltas for DUT; DUT host allocated-CPU active seconds as raw evidence (not CPU/GiB); optional cgroup CPU delta (raw, not CPU/GiB); client per-core mean CPU busy during the entire interval and client aggregate mean. The max of per-core interval means is preserved only as raw evidence. **`client_max_single_core_busy_percent` is explicitly `unavailable`**, since a maximum of per-core time averages is not the instantaneous per-core peak required for the 95% headroom gate; interval sampling will be added with orchestration. Also preserve TCP retransmitted *segments* for A when available; B/C `not_applicable` (QUIC-specific transport counter is not fabricated from TCP).

**Unqualified, consciously absent:** verified main-window application payload bytes, actual goodput, CPU seconds/GiB, simultaneous DUT/client-window alignment, 95% peak client-core gate, independent content integrity coverage, actual 1-RTT NGI541 invocation proof, hardware-NIC fidelity, IRQ/softirq source attribution, crypto cost attribution. Even if cgroup CPU usage is collected, normalization to GiB must wait for independent validated client data and synchronized window protocol. Such results are represented by `unavailable` with explanatory reason, never zero. Snapshot-derived intervals are not necessarily exactly the loadgen main phase because two reads have nonzero acquisition time. The observation status is always `evidence-only-not-qualified`.

## Causal interpretability / scientific guardrails

- Measurement P vs C vs K must remain separated; C/K tracing overhead calibrated before interpretation.
- cgroup v2 `usage_usec` includes cgroup processes/descendants; server cgroup must include *all* NGINX workers and no unrelated processes. Host per-core `/proc/stat` contains unrelated work unless DUT cores are isolated and topology is qualified. Do NOT add raw `cpu.stat` and raw host CPU values; they overlap.
- NIC `/sys/class/net` statistics are interface counters in the current network namespace, not proven physical wire bytes or QUIC packet counts. GSO/GRO, LRO, offloads and coalescing must be recorded in CloudLab environment evidence. `/proc/net` is network-namespace scope; no automatic process attribution. SNMP configuration/gauge fields (e.g., `Tcp.CurrEstab`) are reported as before/after rather than cumulative deltas; other negative counter deltas fail closed pending investigation.
- For CPU busy from `/proc/stat`, `guest`/`guest_nice` are excluded from summed total (already included in user/nice), `iowait` counts as non-busy, steal is separately counted in total. CPU active excludes steal.
- The collect-on-start/collect-on-end primary workflow requires a future orchestration barrier, explicit co-measured loadgen main-window proof, minimum/maximum sample-boundary timing uncertainty, server/client time offset estimates, and signed payload-integrity evidence.
- No automated retry of failed measurement slots or metric-dependent selection; every attempt has a new append-only artifact path.
- `Docker Desktop` LinuxKit functional snapshots verify only collector correctness; no hardware throughput, NIC, PMU or peer-reviewed claims from this environment.

## Execution

After installation, in repository root:

```sh
PYTHONPATH=benchmark python3 -m framework.abc_m2_cli registry
python3 -m unittest discover -s benchmark/framework/tests -p 'test_abc_m2.py' -v
python3 -m unittest discover -s benchmark/framework/tests -p 'test_*.py'
```

Linux (host-local, dedicated experimental CPUs, adapter `enp5s0f0`, orchestrator controls timing):

```sh
PYTHONPATH=benchmark python3 -m framework.abc_m2_cli capture \
  --run-id abc-0001 --attempt-id attempt-0001 --window-id main-001 \
  --host-role dut --phase start --cpus 4-7 --iface enp5s0f0 \
  --cgroup /sys/fs/cgroup/ngi541-dut --out /tmp/abc-0001-start.json
# Start load generator main window here; invoke end capture at its exit barrier.
PYTHONPATH=benchmark python3 -m framework.abc_m2_cli capture \
  --run-id abc-0001 --attempt-id attempt-0001 --window-id main-001 \
  --host-role dut --phase end --cpus 4-7 --iface enp5s0f0 \
  --cgroup /sys/fs/cgroup/ngi541-dut --out /tmp/abc-0001-end.json
PYTHONPATH=benchmark python3 -m framework.abc_m2_cli derive \
  --start /tmp/abc-0001-start.json --end /tmp/abc-0001-end.json \
  --arm B --out /tmp/abc-0001-delta.json
```

Use distinct real file paths, IDs and CPU allocations for each attempt/host. `derive` neither asserts client proof nor publishes CPU/GiB. `--out` refuses overwriting existing evidence.

## Definition of Done — bounded

- **M2.0 implementation complete:** schema, unchanged 26-metric registry, provenance/state enforcement, tests that reject silent zeros/units/modes/QUIC-TCP conflation and false scientific claims.
- **M2.1 implementation complete at collector level:** Linux read-only snapshot/delta, cgroup identity, CPU/NIC and kernel counters, test fixture failures, append-only evidence, Docker smoke; next on CloudLab is hardware/network topology and cross-host orchestration integration.
- **M2.1 scientific qualification NOT complete:** DUT/client coordinator-window synchronization, validated payload, CPU/GiB and client instantaneous peak headroom. Explicit gates remain pending rather than inferred.
- **M2.2–M2.5 NOT implemented by this package:** symmetric OpenSSL/NGI541 QUIC API instrumentation, cryptographic invocation/fallback counts, PMU/eBPF, overhead calibration and high-speed experiment freeze.
