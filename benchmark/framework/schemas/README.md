# Experiment schemas

`benchmark/framework/schemas/` contains the machine-readable JSON Schema contracts used by NGI541 Benchmark Framework.

The schemas describe persistent experiment definitions and generated artifacts. They are part of the current framework contract, not a historical record of individual R5/R6 milestones.

Schemas use **JSON Schema Draft 2020-12**.

## Purpose

The schema layer makes experiment artifacts externally inspectable and independently validatable.

It documents contracts for:

- experiment lifecycle state and manifests;
- schedules and measurements;
- deployment descriptions;
- network qualification and evidence;
- deterministic scientific profiles and corpora;
- HTTP/3 transport-security qualification;
- dual-host telemetry;
- workload planning;
- final frozen experiment inputs;
- paired scientific execution;
- publication results and integrity records;
- provider-independent scientific protocol identity.

The Python framework intentionally does not require a third-party JSON Schema implementation at runtime. Core invariants are enforced directly in standard-library Python, while these schema files provide a portable machine-readable specification for development, CI, external tooling, and archived research artifacts.

## Identity boundary

Schemas distinguish three kinds of identity:

```text
scientific protocol
    provider-independent experiment semantics

deployment
    mapping of logical roles onto concrete infrastructure

execution instance
    realized binaries, hosts, timestamps, measurements, and evidence
```

Provider-specific fields such as CloudLab allocation identifiers, SSH targets, or concrete host names belong to deployment/execution provenance and must not silently become part of scientific experiment identity.

## Versioning

Persistent generated artifacts carry a schema version, for example:

```json
{
  "schema_version": 1
}
```

Backward-incompatible contract changes require a new schema version or a new schema contract. Existing frozen scientific artifacts are not rewritten in place.

## Common conventions

Timestamps use UTC RFC 3339 form:

```text
2026-10-16T01:18:12Z
```

Run IDs use:

```text
run-0001
```

Pair IDs use:

```text
pair-0001
```

Current benchmark variants include:

```text
stock
ngi541-direct
```

Workload-specific parameters and observations remain explicit structured objects rather than hidden framework state.

## Current schema inventory

- `campaign.schema.json`
- `corpus-manifest.schema.json`
- `coverage-manifest.schema.json`
- `deployment.schema.json`
- `dual-host-telemetry.schema.json`
- `final-freeze-manifest.schema.json`
- `final-freeze-state.schema.json`
- `final-freeze.schema.json`
- `loadgen-runtime.schema.json`
- `manifest.schema.json`
- `measurement.schema.json`
- `network-envelope.schema.json`
- `network-evidence.schema.json`
- `network-qualification.schema.json`
- `paired-execution-result.schema.json`
- `paired-scientific-execution.schema.json`
- `paired-scientific-protocol.schema.json`
- `publication-bundle.schema.json`
- `result-integrity.schema.json`
- `result-manifest.schema.json`
- `schedule.schema.json`
- `scientific-corpus.schema.json`
- `scientific-experiment-identity.schema.json`
- `scientific-profile.schema.json`
- `state.schema.json`
- `telemetry-sample.schema.json`
- `transport-security.schema.json`
- `workload-plan.schema.json`
- `workload-planner.schema.json`

## Validation

Framework tests validate the implementation against these contracts:

```bash
python3 -m unittest discover \
  -s benchmark/framework/tests \
  -p 'test_*.py'
```

The schemas complement those executable invariants; they do not replace them.
