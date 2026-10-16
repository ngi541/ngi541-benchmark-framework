# Benchmark framework

`benchmark/` contains the reusable, provider-neutral scientific benchmark
framework for NGI541 network-data-path evaluation.

## Canonical structure

```text
benchmark/
├── configs/                active executable configuration graph
├── framework/              execution, validation, analysis, and provenance
│   ├── schemas/            machine-readable contracts
│   └── tests/              framework regression tests
├── protocols/              deployment-independent scientific protocols
├── scientific-profiles/    workload/scientific-data profiles
└── workloads/
    └── http3/              HTTP/3 workload adapter
```

Generated experiment instances, qualification outputs, corpora, build trees,
and publication bundles are runtime data and are not source-controlled.

## Boundaries

Scientific protocol semantics must not encode a deployment provider, host name,
SSH target, CloudLab identifier, or machine-specific path.

Deployment descriptors define where a protocol is executed. The framework
records realized hardware/software state as execution provenance.

The active HTTP/3 paired methodology is defined in:

```text
benchmark/protocols/http3-paired-r6.5.4.5.json
```

The executable reference configuration remains under `benchmark/configs/`
until provider-specific execution inputs are fully represented by deployment
descriptors.

## Requirements

- correctness validation precedes performance interpretation;
- inputs and comparison policy are explicit;
- paired ordering is deterministic and auditable;
- raw measurements are immutable within an execution instance;
- analysis is deterministic from frozen inputs and raw measurements;
- provider identity is provenance, not scientific identity.

See:

- [`../docs/benchmark-methodology.md`](../docs/benchmark-methodology.md)
- [`../docs/reproducibility.md`](../docs/reproducibility.md)
- [`../docs/portability-contract.md`](../docs/portability-contract.md)
