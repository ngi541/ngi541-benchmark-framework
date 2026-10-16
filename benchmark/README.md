# Benchmark layer

`benchmark/` contains the provider-independent experimental machinery used by NGI541 Benchmark Framework.

The benchmark layer defines **what is measured and how it is measured**. It does not own infrastructure allocation.

## Structure

```text
benchmark/
├── configs/
│   └── active executable definitions for the current implementation
├── framework/
│   ├── lifecycle orchestration
│   ├── qualification and validation
│   ├── telemetry
│   ├── workload planning
│   ├── paired execution
│   ├── deterministic analysis
│   ├── result publication
│   ├── schemas/
│   └── tests/
├── protocols/
│   └── provider-independent frozen scientific methodology
├── scientific-profiles/
│   └── deterministic scientific workload profiles
└── workloads/
    └── http3/
        └── application workload adapter
```

## Boundary

The scientific layer must not depend on:

- CloudLab allocation IDs;
- SSH host names;
- provider-specific machine names;
- local filesystem roots;
- hardware inventory that belongs to a concrete execution;
- manually chosen post-result tuning.

Provider and machine realization belongs to `environments/` and execution provenance.

## Methodology principles

A performance campaign should make explicit:

- workload object semantics;
- protocol and cipher suite;
- variants under comparison;
- condition ordering;
- repetition count;
- warm-up policy;
- measurement window;
- validity gates;
- primary and secondary metrics;
- pairing rules;
- retry policy;
- outlier policy.

The current controlled paired methodology plans load against `stock` only, freezes inputs before candidate execution, balances variant order, retains every valid observation, and prohibits metric-dependent retry and metric-dependent outlier deletion.

## Generated data

The following are generated research data and are intentionally not source-controlled:

```text
experiments/
qualifications/
corpora/
artifacts/
```

They contain execution-specific evidence and may be large.

## Entry points

Framework CLI:

```bash
./scripts/experiment.sh <command> ...
```

Framework tests:

```bash
python3 -m unittest discover \
  -s benchmark/framework/tests \
  -p 'test_*.py'
```

See:

- [`framework/README.md`](framework/README.md)
- [`protocols/README.md`](protocols/README.md)
- [`workloads/http3/README.md`](workloads/http3/README.md)
- [`../docs/benchmark-methodology.md`](../docs/benchmark-methodology.md)
- [`../docs/reproducibility.md`](../docs/reproducibility.md)
