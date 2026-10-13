# Experiment JSON schemas

This directory contains machine-readable JSON Schema definitions for the R5 experiment contract.

Schemas use JSON Schema Draft 2020-12.

Current schemas:

```text
manifest.schema.json
state.schema.json
schedule.schema.json
measurement.schema.json
```

The schemas are framework contracts, not historical descriptions of `c2.1-local-http3`.

## Runtime dependency policy

The R5 core framework must not require a third-party JSON Schema implementation at runtime.

Python 3 standard-library code will enforce core invariants directly.

These schema files exist to:

- document the contract precisely;
- support optional validation in development and CI;
- make generated artifacts externally understandable;
- allow downstream users to validate experiments with standard JSON Schema tooling.

## Versioning

Each generated artifact contains:

```json
{
  "schema_version": 1
}
```

Backward-incompatible schema changes require a new integer schema version.

## Common conventions

Timestamps use UTC RFC 3339:

```text
2026-10-09T21:45:12Z
```

Run IDs use:

```text
run-0001
```

Pair IDs use:

```text
pair-0001
```

Canonical variants include:

```text
stock
ngi541-direct
ngi541-provider
```

Workload-specific parameters and observations remain extensible JSON objects.

- `scientific-profile.schema.json` — versioned, environment-independent scientific workload profile contract used from R6.5.3 onward.
- `network-evidence.schema.json` — R6.5.3c resolver policy for selecting compatible R6.5.1 observations.
- `network-envelope.schema.json` — deterministic normalized network service-envelope artifact consumed by later transport planning.
- `scientific-corpus.schema.json` — R6.5.3d deterministic corpus-generation definition.
- `corpus-manifest.schema.json` — normalized indexed-stream or finite-object-set corpus manifest.
- `coverage-manifest.schema.json` — deterministic execution coverage selection for a frozen corpus.
- `transport-security.schema.json` — R6.5.3e remote HTTP/3/TLS functional security qualification contract for stock and NGI541 scientific-object transport.

- `dual-host-telemetry.schema.json` — R6.5.3f dual-host telemetry qualification definition.
- `telemetry-sample.schema.json` — normalized per-host telemetry sample contract.

## R6.5.3g workload planning

- `workload-planner.schema.json` defines the stock-only calibration policy.
- `workload-plan.schema.json` describes the immutable derived plan consumed by later paired campaigns.

The planner may tune only the stock NGINX path. NGI541 is prohibited from rate,
concurrency, worker, coverage or target selection.
