# Experiment record and filesystem contract

The generated experiment is a **self-describing execution instance**. Current source-controlled schemas are in [`../benchmark/framework/schemas/`](../benchmark/framework/schemas/). The root-level contract distinguishes immutable scientific inputs and schedule, append-only measurements and mutable lifecycle state.

## Canonical instance layout

```text
experiments/<experiment-id>/
  config/request.json
  config/resolved.json
  manifest.json
  state.json
  environment/adapter.json
  environment/nodes/<node>/...
  provenance/sources.json
  provenance/dependencies.json
  provenance/build.json
  provenance/binaries.sha256
  provenance/runtime-bindings.json
  execution/schedule.json
  execution/workload/...
  raw/runs/run-XXXX/attempt-YY/measurement.json
  processed/...
  figures/...
  logs/framework.log
```

Specialized qualification and paired-execution subtrees may add stage-specific manifests, telemetry, measured client output and validity records. The layout above illustrates the generic experiment ABI, not a promise that every phase generates every optional file immediately.

## Artifact mutability

| Material | Rule |
| --- | --- |
| `config/request.json` | Immutable from creation |
| `config/resolved.json`, schedule | Frozen after planning / sealing |
| `manifest.json`, source/dependency/binary provenance | Immutable after sealing |
| `state.json` | Mutable lifecycle status with explicit failure state |
| `raw/runs/**` | Append-only attempt evidence; never overwrite earlier attempts |
| `processed/**`, `figures/**` | Deterministically regenerated from accepted raw inputs |
| Generated instance README | Explanatory derivative, not numerical authority |

## Stable run and pair identity

The schedule specifies the ordered conditions, variants and repetition numbers before execution. Every run has an ID such as `run-0001`; pairing is based on the condition/repetition identity, not adjacent timestamps selected after measurement. An invalid attempt must retain its failure reason; subsequent attempts never make earlier evidence disappear.

`measurement.json` captures server variant, request counters, elapsed main-window time, primary/secondary metrics, exit status and validity. The result compiler verifies the sample against the frozen schedule and result hash inventory.

## Provider boundary

The **scientific definition** contains variants, workloads, pairing and analysis policy; **deployment** contains concrete role-to-node/access bindings; **execution provenance** contains exact machine and binary facts. A path, public host name or allocation ID must not alter semantic scientific identity.

The current default experiment framework is Python-standard-library-based; the JSON Schema files are portable external contracts rather than required third-party runtime validators.

See [reproducibility](reproducibility.md), [lifecycle](experiment-lifecycle.md) and [schema index](../benchmark/framework/schemas/README.md).
