# Execution lifecycle and qualification evidence

A scientific result is the final product of a **gated evidence chain**, not the output of a single bandwidth command. The framework exposes two related interfaces: a generic versioned lifecycle for portable request definitions and a specialized, pinned two-host HTTP/3 qualification/paired-execution pipeline.

## 1. Generic experiment lifecycle

```text
create → plan → prepare → seal → validate → execute → validate → analyze → COMPLETE
```

| Transition | Preconditions | Persisted contract |
| --- | --- | --- |
| `create` | Valid workload and variant set; valid deployment or environment selector | `config/request.json`, initialized `state.json` |
| `plan` | Preparing state; resolved workload/config | `config/resolved.json`, `execution/schedule.json` with ordered paired runs |
| `prepare` | Planned schedule, accessible software/hosts | Node inventories, source/build/binary provenance, runtime bindings and preflight evidence |
| `seal` | Complete provenance; passing generic/workload preflight | Immutable `manifest.json`, state READY |
| `validate` | Manifest and required artifact integrity | Structural and hash checks; abort on invalid state |
| `execute` | Sealed schedule and runnable environment | Append-only attempts under `raw/runs/` |
| `analyze` | Structurally accepted run measurements | Recomputed paired statistics, CSV/JSON and deterministic figures |
| `COMPLETE` | Analysis and final integrity checks pass | Reproducible result with explicit claim boundary |

The `campaign --config <campaign-definition.json>` entry point can drive and resume the lifecycle for **a real campaign definition**; a qualification JSON from `benchmark/configs/` is not a generic campaign definition. Generic portable smoke tests can use `create --deployment` followed by `plan` without preparing hardware.

## 2. Frozen two-host HTTP/3 reference campaign

The executable commands below are the **actual active reference definitions**. Their Pi/Mac names express the currently realized DUT/client topology. They are not universal cloud-provider scripts. Each stage fails closed when required upstream evidence is invalid or missing. The accepted methodology is still provider-independent in `benchmark/protocols/http3-paired-r6.5.4.5.json`.

### `network-qualify`

**Action:** Checks DUT↔load-generator reachability and link capacity using ping/iperf3; optional `--bootstrap` provisions required iperf3 tooling.

**Output / gate:** Network qualification records; prevents application measurements from being interpreted without a measured transport envelope.

```bash
./scripts/experiment.sh network-qualify \
  --config benchmark/configs/r6.5.1-pi-mac-network.json \
  --bootstrap
```

### `loadgen-runtime`

**Action:** Provisions the pinned HTTP/3 load-generator toolchain and validates versions, executable capabilities, patch/source SHA-256 and runtime identity; `--bootstrap` may install missing build prerequisites.

**Output / gate:** Qualified client runtime; excludes unsupported or unpinned generator behavior.

```bash
./scripts/experiment.sh loadgen-runtime \
  --config benchmark/configs/r6.5.4.2-pi-http3-loadgen.json \
  --bootstrap
```

### `network-evidence`

**Action:** Resolves qualified client and DUT link evidence and constructs a compatible service-capacity envelope.

**Output / gate:** Derived network envelope and compatibility evidence; constrains valid load planning.

```bash
./scripts/experiment.sh network-evidence \
  --config benchmark/configs/r6.5.3c-pi-mac-network-evidence.json
```

### `scientific-corpus`

**Action:** Materializes deterministic scientific-object coverage from the versioned CLAS12, LCLS and HACC-inspired profiles.

**Output / gate:** Corpus manifest and object hashes; both server variants receive exactly the same requested objects.

```bash
./scripts/experiment.sh scientific-corpus \
  --config benchmark/configs/r6.5.3d-scientific-corpus.json
```

### `transport-security`

**Action:** Runs HTTP/3/TLS 1.3 interoperability and scientific-object integrity checks for both server variants, including the required cipher suite and peer-verification policy.

**Output / gate:** Security/functional qualification; invalid transports never advance to performance comparisons.

```bash
./scripts/experiment.sh transport-security \
  --config benchmark/configs/r6.5.4.2-pi-mac-http3-security.json
```

### `dual-host-telemetry`

**Action:** Qualifies supported host sensors, sampling, readiness and thermal/throttling status across the DUT and remote load generator.

**Output / gate:** Capability and telemetry contracts; avoids blind measurement under invalid host conditions.

```bash
./scripts/experiment.sh dual-host-telemetry \
  --config benchmark/configs/r6.5.4.2-pi-mac-dual-host-telemetry.json
```

### `workload-planner`

**Action:** Selects a feasible request/concurrency workload using only the baseline NGINX/OpenSSL path and the qualified network envelope.

**Output / gate:** Frozen workload plan; NGI541 results cannot influence load selection.

```bash
./scripts/experiment.sh workload-planner \
  --config benchmark/configs/r6.5.4.2-pi-mac-stock-workload-planner.json
```

### `final-freeze`

**Action:** Checks upstream qualification identities and freezes schedule, input/corpus references, runtime artifact SHA-256 and validity policy.

**Output / gate:** Frozen manifest; subsequent execution cannot silently redefine the comparison.

```bash
./scripts/experiment.sh final-freeze \
  --config benchmark/configs/r6.5.4.2-pi-mac-final-freeze.json
```

### `paired-execution`

**Action:** Executes baseline and candidate as separate balanced within-condition runs; collects client measurements and both-host telemetry; rejects invalid attempts without favorable-result retries.

**Output / gate:** Append-only raw attempts, paired records and analyzed experiment state.

```bash
./scripts/experiment.sh paired-execution \
  --config benchmark/configs/r6.5.4.5-pi-mac-paired-scientific-execution.json
```

### `results`: independent publication validation

**Action:** validate a `COMPLETE` paired-execution directory; recompute and cross-check the frozen manifest, raw/processed identity, paired analysis and publication inventory before producing immutable archive-style outputs.

**Output:** a publication bundle under ignored `artifacts/results/`, including machine-readable results, figures, provenance and integrity manifests. A failed validation must not be described as a completed publication.

```bash
./scripts/experiment.sh results \
  --experiment /absolute/path/to/complete-paired-execution
```

## 3. Retry, stop and resume semantics

Unsuccessful attempts remain in append-only evidence; no **metric-dependent automatic retry** is allowed. A failed validity gate is not an invitation to rerun until a favorable sample appears. Inspect the frozen condition, affected run, host/network telemetry and explicit failure cause before deciding on a documented operational continuation.

An incomplete or invalid experiment must not be presented as a `COMPLETE` accepted campaign. Results from a different host, workload or binary revision have distinct execution provenance even when the scientific protocol bytes are identical.

## 4. Reproduce framework behavior without performance claims

```bash
./scripts/experiment.sh create \
  --deployment environments/local/single-host.json \
  --workload http3 \
  --variant stock \
  --variant ngi541-direct \
  --repetitions 2 \
  --comparison-mode paired-balanced

./scripts/experiment.sh plan <experiment-id>
./scripts/experiment.sh status <experiment-id>
```

This exercise produces a valid planned schedule and lifecycle artifacts; it does **not** build, run or qualify the actual two-host NGINX experiment.

See [experiment schema](experiment-schema.md), [analysis contract](analysis.md), [network topology](topology.md) and [reproducibility](reproducibility.md).
