# M2.1.2b — MAIN phase binding and validated payload evidence (r1)

**Status:** additive implementation of *offline evidence validation*, not completion of the hardware science or in-process loadgen instrumentation. The primary run remains **UNQUALIFIED**.

## Boundaries retained

- Frozen R6.5.4.5 JSON SHA-256: `99805dd378310ec539246e655d3f2a690036e4e50ac83c27c52765d1a50fb387`.
- R6.5.4.5 pinned h2load SHA-256 is unchanged and is **not** a stream-hashing client.
- Existing M2 v0.2 26 metrics and 4 states, and separate P/C/K modes, are untouched.
- B/C is server crypto substitution. A/B is cross-transport context, not causal crypto attribution.
- M2.1.2a environment identity and all previous M2 schemas are unchanged.

## Verified here

1. Hash of a **predeclared corpus manifest**; per-object immutable object IDs, expected byte length, expected SHA-256.
2. Separately supplied MAIN phase object with client binary SHA-256, boot ID, two host-local monotonic event times, run/attempt/window/arm, and no warmup inclusion.
3. Per-stream externally supplied completion ledger: unique stream ID, object ID, success, HTTP version, exact main-local started/completed bounds, per-response body file and length, declared SHA-256.
4. Recompute SHA-256 of every distinct response body file, compare to expected pinned corpus, reject any incomplete/failed/bad-status/incorrect-version/unknown-object/duplicate response/path traversal/symlink/size/hash anomaly.
5. Reconcile all verified file bytes to patched h2load MAIN-phase `measurements.traffic.data`, require no incomplete/failed/errored/timeouts, all response statuses 2xx and every request to be covered.
6. Optionally require MAIN times to be enclosed by actual **client-local** M2.1 counter snapshots on one unchanged Linux boot (this still permits pre/post contamination).
7. Optionally validate consistency with M2.1.1 controller coordination receipt, *never* comparing monotonic clocks from separate hosts.
8. All results are append-only via `abc_m2_cli.save_new` and remain evidence-only, including if all declared files match.

## Critical gaps before a qualified primary P-mode run

Pinned h2load patch `integration/patches/nghttp2-1.69.0/0001-h2load-main-phase-stream-accounting.patch` retains stream-origin accounting and counts MAIN DATA, but **does not emit per-stream byte hashes or MAIN phase transitions to an externally auditable receipt**. Therefore external `phase.json` / `ledger.json` are not, by themselves, proof that the data came from the actual h2load process. The present offline validator **never** sets `valid_application_payload_bytes` or `application_goodput_mbps` to `measured`. Their input reconciling totals are clearly labelled *diagnostic*, not publication outcomes.

To close this gap **without modifying historical binaries**:

1. Create a **new** pinned Linux loadgen experimental variant with audited in-process MAIN start/end emission and completed per-response accounting. Preserve the current 1.69.0 h2load binary (SHA-256 `dcd0dfe45c76fd6afe249bfd8d2d0f1a01437d07ed56c31f349bc26ce2d65924`) unchanged for historical comparison.
2. Instrument streaming incremental checksum / expected object identity, or design and validate an equivalent stronger verified completion method. Verify per-stream attribution during *actual MAIN* and no warmup leakage. Cost of hashing must be evaluated in **M2.4** as a possible client bottleneck. Consider separate P and attribution-validity workloads if overhead is material; do not silently equate sampled validations to fully validated bytes.
3. Document client ELF identity, instrumentation patch SHA-256, compiler/ISA, TLS provider; qualify HTTP/2+HTTP/3 cipher/ALPN, no NGI541 dependency.
4. Bind loadgen MAIN event source to client-local CPU capture; align DUT counters by independent controller-clock uncertainty and bound pre/post window overcount. If baseline-window padding is material, rework collector to repeated in-window counters or derive bounds rather than claim exact CPU/GiB.
5. Capture same-interval valid bytes and cgroup CPU for NGINX entire process family, isolate host cpuset, qualify client saturation and NIC/NUMA/IRQ + offloads, then perform M2.4 perturbation calibration.
6. Publication claims require independent acceptance of all environment, payload, window, crypto-path and performance gates. No automatic retry after metric-dependent invalidity.

## Real integration CLI (once in-process exporter exists)

```bash
export PYTHONPATH=benchmark
python3 -m framework.abc_m2_main_cli \
  --corpus-manifest /evidence/workload/corpus.json \
  --expected-corpus-sha256 '<predeclared-corpus-manifest-sha256>' \
  --phase /evidence/client/main-events.json \
  --completion-ledger /evidence/client/completions.json \
  --h2load-evidence /evidence/client/h2load-main.json \
  --response-dir /evidence/client/stream-bodies \
  --client-start /evidence/telemetry/client-start.json \
  --client-end /evidence/telemetry/client-end.json \
  --coordination /evidence/windows/coordination.json \
  --out /evidence/validity/main-reconciliation.json
```

The command re-hashes complete body files; storing every response has prohibitive I/O overhead at production throughput. This path is primarily a correctness/attribution qualification reference implementation; a scalable, measured-overhead-validated client stream hashing variant is still required.

## Reproducibility caveats

Do not treat a verified file as proof of origin in a particular network run. Do not infer authentication of phase markers merely from a `source` string in JSON. Do not bind two hosts by direct monotonic timestamp subtraction. Do not convert an incomplete run's body bytes to successful goodput. Do not upgrade snapshot window CPU delta to MAIN CPU cost without padding and isolation control.
