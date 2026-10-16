# Experiment orchestration, validation and analysis

The framework owns lifecycle transitions, provider-neutral request identity, data validation, deterministic run schedules, sealed provenance, append-only attempts, qualification gates and publication output validation. It uses Python's standard library for core operation.

## Two execution interfaces

**Generic experiment lifecycle:** `create → plan → prepare → seal → validate → execute → analyze → COMPLETE`. The `campaign` command can drive this state machine for a valid campaign definition while enforcing identical-definition resume and framework identity. `--deployment` binds `dut` and `loadgen` roles through a validated descriptor; non-local providers are fail-closed unless supported.

**Controlled HTTP/3 scientific pipeline:** qualification and freeze commands (`network-qualify`, `loadgen-runtime`, `network-evidence`, `scientific-corpus`, `transport-security`, `dual-host-telemetry`, `workload-planner`, `final-freeze`) precede `paired-execution`, then `results`. Current `paired-execution --config` uses the pinned reference execution config; this is not interchangeable with the generic `create --deployment` interface.

## Primary invariants

- `stock` = NGINX/OpenSSL baseline *server* path; `ngi541-direct` = NGI541-integrated server QUIC packet/header-protection path; same pinned HTTP/3 client.
- The workload planner observes **baseline only**; the accepted protocol freezes 4 repetitions per condition, balanced variant order and rotating condition order.
- A measured run fails on HTTP errors, detected throttling or violation of generator headroom (85% overall, 95% busiest core).
- No performance-metric-driven automatic retry or outlier selection; raw attempts remain append-only.
- Analysis selects the earliest structurally valid attempt and recomputes paired deltas; `results` independently checks publication identity and integrity.

## Commands and evidence

See the complete [stage-by-stage table and exact commands](../../docs/experiment-lifecycle.md). A minimal framework-only test requires no DUT:

```bash
python3 -m unittest discover -s benchmark/framework/tests -p 'test_*.py'
```

Inspect CLI argument contracts using:

```bash
./scripts/experiment.sh --help
./scripts/experiment.sh paired-execution --help
./scripts/experiment.sh results --help
```

See [schemas](schemas/README.md), [analysis](../../docs/analysis.md), [reproducibility](../../docs/reproducibility.md), and [the frozen protocol](../protocols/README.md).
