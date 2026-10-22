# NGI541 M2.1.1 — Cross-host window *evidence* and h2load MAIN DATA accounting

**Status:** additive experimental implementation; NOT a frozen scientific-run protocol and NOT a publication-qualified measurement. Complements, but does not modify, M2.0/M2.1 contract `ngi541-abc-m2-0.2-additive-r1` and the 26-metric v0.2 registry.

## Scientific invariants retained

- Historical `benchmark/protocols/http3-paired-r6.5.4.5.json` SHA-256 `99805dd378310ec539246e655d3f2a690036e4e50ac83c27c52765d1a50fb387` remains unchanged.
- A = stock NGINX HTTP/2+TLS/TCP, B = stock NGINX HTTP/3/QUIC, C = NGI541-patched HTTP/3. Only controlled B/C isolates substitution. A/B is transport context, not a cryptographic causal attribution.
- Existing 26 metrics, four metric states, P/C/K roles and 9-condition × 3-arm × 4 preliminary-block design unchanged. No metric-dependent retries, no historical results migration or patch modification.
- Never mix controller and independent host monotonic timestamps. The controller sends a remote SSH request, receives a host event JSON, and stores **its own** pre-send/post-receive monotonic bracket. The host event lies within that controller bracket, subject to honest execution on the remote host. We use the span of both DUT/client receipt brackets as a *conservative upper bound* on possible cross-host event skew.
- The bound is **not NTP/PTP clock error** and is **not evidence that the h2load measurement phase began or ended at the marker**. SSH setup jitter may yield a large upper bound. SSH receipts from the same Linux boot on both roles are explicitly unqualified. A user-supplied threshold is marked provisional and not frozen.
- Same-host `enclosure` checks that start counter snapshot precedes its start marker, and end marker precedes its end snapshot. Since the actual counter sampling time is only known within the snapshot read bracket, it records conservative maximal pre/post padding. Even a successful enclosure is not proof of exact phase alignment.
- `h2load` JSON `measurements.traffic.data` from the **pinned main-phase stream-accounting patched h2load** is preserved as observed MAIN DATA bytes. These bytes are *not necessarily individually integrity-verified completed-object bytes*. The v0.2 `valid_application_payload_bytes`, goodput and CPU/GiB remain **unavailable**, never silently mapped from the raw DATA counter.
- Any status anomalies (including inflight responses, phase-boundary status mismatch, failed/errored/timeout requests) are recorded. The adapter does not apply the earlier frozen analysis's status-inference rules or retroactively reinterpret its results.
- If the expected pinned client binary SHA-256 is not supplied, the adapter records `client_identity_state=unverified`; if supplied, equality is mandatory. Source JSON is hashed; all CLI outputs are append-only and contain provenance. Preserve failed attempts and controller stderr separately; no outcome-dependent automatic retries.

## Delivered files

- `benchmark/framework/abc_m2_coordination.py` — Linux host local marker, controller SSH/local receipts, conservative skew bounds, Linux snapshot-enclosure check.
- `benchmark/framework/abc_m2_payload.py` — pinned h2load MAIN DATA accounting adapter and diagnostic flags.
- `benchmark/framework/abc_m2_bridge_cli.py` — read-only evidence CLI (`marker`, `remote-probe`, `local-probe`, `assess`, `enclosure`, `h2load`).
- `benchmark/framework/tests/test_abc_m2_bridge.py` — 20 additional positive/negative tests; all prior tests retained.
- `scripts/abc-m2-1-1-smoke.sh` — Linux-only two-logical-role test with real v2 counter captures. **Not two physical hosts; not throughput evidence**.

## Installation and regression validation

```bash
cd ~/Projects/NGI541/ngi541-benchmark-framework
bash ~/Downloads/ngi541_abc_m2_1_1/INSTALL.sh
python3 -m unittest discover -s benchmark/framework/tests -p 'test_*.py'
```

Run Linux Docker smoke on macOS, with **fresh** output directory:

```bash
cd ~/Projects/NGI541/ngi541-benchmark-framework
OUT="$HOME/Downloads/ngi541-abc-stage3/m2-bridge-smoke"
mkdir -p "$OUT"
docker run --rm --platform linux/amd64 \
  -e M2_BRIDGE_OUT=/out -v "$PWD:/repo:ro" -v "$OUT:/out" -w /repo \
  python:3.12-slim-bookworm bash scripts/abc-m2-1-1-smoke.sh
```

Expected: `PASS: M2.1.1 Linux clock/byte evidence functional smoke; NOT two-host synchronization` and `EVIDENCE: /out`. Check `coordination.json` has `quality=functional-local-only` and `qualified_primary_result=false`, and `payload.json` has `valid_application_payload_bytes.state=unavailable`.

## How to qualify on actual CloudLab hosts (next integration)

1. Pin Linux hosts, CPU allocation, interfaces, binaries/corpus and workload; install the same M2 modules on controller, DUT and loadgen.
2. For each scheduled run/attempt/window, collect DUT and loadgen M2.1 `capture(start)`, preserving host-specific monotonic snapshot brackets.
3. Use `remote-probe --edge start` for DUT and client **in parallel under one Linux controller boot**, saving both receipts. Connect these marker events to the **actual h2load MAIN-phase transition** (this hook is NOT provided in M2.1.1). Absent that connection, the assessment cannot qualify the scientific window.
4. Collect end receipts when h2load reports MAIN completion (a future explicit hook), then the two `capture(end)` snapshots. Compute same-host deltas and `enclosure` for both hosts. Check padding bounds against predeclared tolerances.
5. Save raw patched `h2load --output-file` result from the **same** attempt and run `h2load` adapter with pinned client binary SHA-256. Require separate full-completion and object-integrity evidence before promoting any data into `valid_application_payload_bytes`.
6. Assess the four controller receipts and preserve the maximum skew bound, source JSON hashes, raw SSH command outcomes, status/failure events and CPU/client-headroom gates. The assessment never auto-accepts an experiment.

Example for already-existing on-disk evidence:

```bash
PYTHONPATH=benchmark python3 -m framework.abc_m2_bridge_cli h2load \
  --raw-json /path/to/raw/h2load-result.json --arm B \
  --run-id run-0001 --attempt-id attempt-0001 --window-id main-0001 \
  --client-executable /path/to/pinned/nghttp2/bin/h2load \
  --expected-client-sha256 dcd0dfe45c76fd6afe249bfd8d2d0f1a01437d07ed56c31f349bc26ce2d65924 \
  --declared-main-seconds 20 \
  --out /path/to/new/evidence/h2load-main-data.json
```

`--declared-main-seconds` must be taken from the relevant pinned experiment, never guessed. Result rate is diagnostic, **not publication goodput**. Retain original patched `h2load` output untouched.

Controller SSH example (perform for start/end and both hosts with matching IDs; do not reuse filenames):

```bash
PYTHONPATH=benchmark python3 -m framework.abc_m2_bridge_cli remote-probe \
  --ssh-target user@dut --remote-repo /absolute/path/to/ngi541-benchmark-framework \
  --host-role dut --edge start --run-id run-0001 \
  --attempt-id attempt-0001 --window-id main-0001 \
  --out /path/to/new/evidence/start-dut-receipt.json
```

Existing SSH key and verified host keys are required; no password prompting or automatic retry. This is a *control-plane bracket*, **not** a time-synchronized workload boundary until loadgen phase hooks are integrated.

## Remaining hard gates — future M2.1.2/M2.2

1. Hook actual loadgen MAIN start/end to two-host DUT and client counter boundaries; measure/calibrate control overhead, enforce bounded inclusion/padding (or correct via interval samples with a documented error model). Avoid treating distinct start/end readings as coincident.
2. Implement independently validated completed-object byte accounting. Verify that partial/failed responses, h2load phase-boundary anomalies, duplicate stream bytes and payload-integrity failures cannot inflate `valid_application_payload_bytes`. Byte validity must be proven, not inferred from a successful functional smoke.
3. Sample per-core client peak over the MAIN interval; snapshots only provide window-average. The ≤95% peak gate is not currently demonstrable.
4. Establish dedicated DUT nginx-process cgroup, uncontaminated CPU allocation and network interface, NIC/IRQ scope and CloudLab bare-metal capabilities before computing normalized CPU/GiB.
5. Symmetric B/C instrumentation at identical QUIC AEAD seal/open/header-protection call sites in separate **attribution-only** builds. Prove 1-RTT NGI541 execution and fallback accounting. Never alter frozen binary or run C/K instrumentation as uncalibrated primary throughput.

**Definition of Done for this package:** additive/unchanged prior files; 20 new regression tests; full legacy test suite PASS; Linux local smoke PASS; source/output hashes; all absolute timing / valid-byte / qualified-result claims explicitly refused.
