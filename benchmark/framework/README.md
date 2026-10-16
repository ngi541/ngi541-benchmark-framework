# Experiment framework

`benchmark/framework/` implements the reproducible experiment lifecycle used by NGI541 Benchmark Framework.

It is intentionally implemented with the Python standard library so that experiment orchestration and deterministic analysis do not depend on a large scientific-Python software environment.

## Lifecycle

The generic lifecycle is:

```text
create
  |
  v
plan
  |
  v
prepare
  |
  v
seal
  |
  v
validate
  |
  v
execute
  |
  v
validate
  |
  v
analyze
  |
  v
COMPLETE
```

Specialized qualification commands build the evidence required by controlled scientific campaigns before paired execution is allowed.

## CLI

All commands are exposed through:

```bash
./scripts/experiment.sh
```

Core lifecycle commands include:

```text
create
plan
prepare
seal
execute
analyze
status
validate
campaign
```

Current scientific qualification/execution commands include:

```text
network-qualify
loadgen-runtime
network-evidence
scientific-corpus
transport-security
dual-host-telemetry
workload-planner
final-freeze
paired-execution
results
```

Use the command help for the current argument contract:

```bash
./scripts/experiment.sh --help
./scripts/experiment.sh <command> --help
```

## Portable experiment creation

A portable experiment binds logical roles through a deployment descriptor:

```bash
./scripts/experiment.sh create \
  --deployment environments/local/single-host.json \
  --workload http3 \
  --variant stock \
  --variant ngi541-direct \
  --repetitions 2 \
  --comparison-mode paired-balanced
```

Provider identity is deployment metadata. It is excluded from scientific experiment identity.

## Controlled paired execution

The accepted local reference execution is defined by:

```text
benchmark/configs/r6.5.4.5-pi-mac-paired-scientific-execution.json
```

Its scientific methodology projects to:

```text
benchmark/protocols/http3-paired-r6.5.4.5.json
```

The paired execution contract includes:

- `stock` as baseline;
- `ngi541-direct` as candidate;
- balanced within-condition pairing;
- rotating condition order;
- four paired repetitions per condition;
- predeclared validity gates;
- no metric-dependent automatic retry;
- retain-all-valid-runs outlier policy.

## Qualification chain

Before final paired execution, the current reference pipeline validates:

```text
network path
    ->
load-generator runtime
    ->
network evidence
    ->
scientific corpus
    ->
HTTP/3/TLS security contract
    ->
dual-host telemetry
    ->
stock-only workload plan
    ->
final frozen manifest
    ->
paired execution
```

A failure in a prerequisite gate prevents a later phase from silently proceeding with incomplete evidence.

## Analysis contract

Analysis consumes the frozen schedule and append-only raw measurements. It does not rerun the workload.

Attempt selection is metric-independent: the first structurally valid execution attempt for a scheduled run is selected. Later attempts are not substituted because they produce a more favorable metric.

Current paired primary metrics are:

```text
application_goodput_mbps
dut_process_cpu_seconds_per_gib
```

Current secondary metrics include:

```text
dut_estimated_energy_j_per_gib
loadgen_max_total_cpu_busy_percent
loadgen_max_single_core_busy_percent
```

The controlled paired summary statistic is the median paired delta within the predeclared condition structure.

## Publication

A completed paired execution can be transformed into a read-only publication artifact:

```bash
./scripts/experiment.sh results \
  --experiment <paired-execution-directory>
```

Publication generation independently checks execution identity, frozen inputs, raw/processed consistency, paired-analysis recomputation, validity evidence, and artifact hashes.

Generated publication data belongs under `artifacts/results/` and is not tracked by Git.

## Tests

Run the framework suite with:

```bash
python3 -m unittest discover \
  -s benchmark/framework/tests \
  -p 'test_*.py'
```

The tests cover lifecycle invariants, schemas, deployment identity, HTTP/3 execution, network qualification, scientific corpus behavior, transport security, telemetry, workload planning, frozen protocol semantics, paired execution, deterministic analysis, and result integrity.
