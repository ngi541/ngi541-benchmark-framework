# NGI541 Benchmark Framework

[![CI](https://github.com/ngi541/ngi541-benchmark-framework/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ngi541/ngi541-benchmark-framework/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![NGI541](https://img.shields.io/badge/NGI541-0.1.1-blue)](https://github.com/ngi541/ngi541)

**NGI541 Benchmark Framework is a reproducibility-first experimental framework for evaluating cryptographic execution inside real network data paths.**

The current reference workload integrates the [NGI541](https://github.com/ngi541/ngi541) cryptographic execution engine into NGINX QUIC/HTTP/3 and compares it with the stock cryptographic path under controlled, paired conditions.

This repository is not the NGI541 cryptographic library itself. It provides the **experimental methodology, workload integration, qualification gates, execution lifecycle, telemetry, analysis, and publication tooling** used to evaluate NGI541 in end-to-end networking workloads.

> [!IMPORTANT]
> This project is independent of ESnet, the U.S. Department of Energy, CloudLab, and the National Science Foundation. References to those infrastructures describe scientific motivation or intended experimental environments and do not imply affiliation, endorsement, or deployment on those systems.

## Why this framework exists

High-performance scientific computing increasingly depends on moving large data sets between instruments, laboratories, edge systems, analysis facilities, GPU clusters, and HPC centers.

The [ESnet Science DMZ](https://fasterdata.es.net/science-dmz/) model and its dedicated [Data Transfer Node](https://www.es.net/science-engagement/technical-and-consulting-services/data-transfer-nodes/) architecture provide an important external context for this work: scientific data movement requires both high throughput and security mechanisms that do not become the dominant data-path bottleneck.

NGI541 explores a narrower systems question:

> **Can a performance-oriented cryptographic execution engine reduce the CPU cost of authenticated encryption in real network data paths while preserving protocol correctness, transport behavior, and application-level throughput?**

The benchmark framework exists to make that question testable with controlled and independently inspectable evidence.

## What the framework measures

The current implemented path is:

```text
scientific workload
        |
        v
HTTP/3 over QUIC
        |
        v
NGINX
   |             |
   | stock       | ngi541-direct
   v             v
OpenSSL       NGI541
QUIC crypto   QUIC packet protection
   |             |
   +------ paired execution ------+
                  |
                  v
     application goodput
     CPU cost per delivered GiB
     estimated energy per GiB
     load-generator headroom
     validity / telemetry evidence
```

For AES-based QUIC cipher suites, the `ngi541-direct` variant routes QUIC packet protection through NGI541 while NGINX/OpenSSL continue to provide the surrounding TLS 1.3, certificate, and protocol machinery.

The framework is designed to evaluate the **system effect of cryptographic execution inside an application network path**, rather than only isolated primitive throughput.

## Scientific controls

The framework does not treat one benchmark number as sufficient evidence. The current methodology includes explicit controls intended to reduce experimenter and selection bias:

- **provider-independent scientific protocol** separated from deployment details;
- **deterministic scientific workload definitions**;
- **network qualification before application benchmarking**;
- **transport-security qualification before performance measurement**;
- **dual-host telemetry and validity gates**;
- **workload planning against the stock variant only**;
- **frozen workload and artifact identities before paired execution**;
- **balanced paired scheduling** between `stock` and `ngi541-direct`;
- **predeclared primary and secondary metrics**;
- **no candidate-driven adaptive tuning**;
- **no metric-dependent automatic retry**;
- **no metric-dependent outlier deletion**;
- **append-only raw execution evidence**;
- **SHA-256 identity for frozen inputs and generated result artifacts**;
- **deterministic analysis from preserved measurements**.

These controls improve reproducibility and resistance to common benchmark biases. They do **not** make a benchmark universally representative: every performance claim remains scoped to the hardware, topology, software revisions, protocol, workload, and validity envelope recorded by the experiment.

## Current scientific protocol

The current provider-independent protocol is:

```text
benchmark/protocols/http3-paired-r6.5.4.5.json
```

Canonical SHA-256:

```text
99805dd378310ec539246e655d3f2a690036e4e50ac83c27c52765d1a50fb387
```

It freezes the accepted paired HTTP/3 methodology while excluding provider-specific host names, SSH targets, allocation identifiers, and hardware inventory.

The corresponding controlled execution compares:

```text
stock
vs.
ngi541-direct
```

using balanced within-condition pairs and four paired repetitions per frozen condition.

## Scientific workload profiles

The current framework contains deterministic workload profiles modeled from published characteristics of three data-intensive scientific use cases:

- CLAS12 event-stream style objects;
- LCLS detector-frame style objects;
- HACC multifile-dataset style objects.

These are **deterministic benchmark representations**, not copies of experiment data and not claims of official validation by the originating scientific collaborations.

The workload layer is intended to preserve relevant transfer characteristics while keeping experiment inputs reproducible and content-addressable.

## Current scope and claim boundary

The framework currently provides:

- NGINX QUIC/HTTP/3 integration for NGI541;
- pinned integration dependencies;
- network-path qualification;
- deterministic scientific corpus generation;
- HTTP/3/TLS transport qualification;
- host telemetry and readiness checks;
- stock-only workload calibration;
- final input freeze;
- controlled paired execution;
- deterministic statistical analysis;
- publication artifact generation;
- provider-neutral deployment descriptors.

The accepted local development campaign established that the methodology and execution pipeline work end to end. Its network path was intentionally limited and is **not used to claim high-speed datacenter, Science DMZ, ESnet, or HPC performance**.

The next research phase is dedicated high-speed bare-metal evaluation.

## Next target: CloudLab

[CloudLab](https://www.cloudlab.us/) is the next intended execution provider because it offers researcher-controlled bare-metal systems and network topology suitable for reproducible systems experiments.

The planned next phase is to add a CloudLab deployment adapter without changing scientific methodology merely because the provider changes.

The target progression is:

```text
CloudLab account/project access
        |
        v
provider adapter + reproducible profile
        |
        v
dedicated loadgen <-> DUT topology
        |
        v
CPU / NUMA / NIC / frequency qualification
        |
        v
high-speed network ceiling characterization
        |
        v
frozen HTTP/3 paired campaign
        |
        v
cross-platform Intel / AMD / Arm analysis
```

CloudLab support is a **roadmap target**, not a current capability.

## Repository structure

```text
.
├── benchmark/
│   ├── configs/               active executable definitions
│   ├── framework/             experiment lifecycle and analysis engine
│   ├── protocols/             provider-independent scientific protocols
│   ├── scientific-profiles/   deterministic scientific workload profiles
│   └── workloads/http3/       HTTP/3 workload adapter
├── docs/                      methodology and architecture documentation
├── environments/              deployment descriptors and provider boundary
├── integration/
│   ├── patches/               pinned NGINX / nghttp2 integration patches
│   ├── tests/                 integration-specific regression tests
│   └── versions/              pinned dependency revisions
└── scripts/                   build, test, dependency, and experiment entry points
```

Generated experiments, scientific corpora, qualification outputs, build trees, and publication bundles are intentionally excluded from source control.

## Quick start: validate the framework

The framework core uses the Python standard library.

```bash
git clone https://github.com/ngi541/ngi541-benchmark-framework.git
cd ngi541-benchmark-framework

python3 -m unittest discover \
  -s benchmark/framework/tests \
  -p 'test_*.py'
```

A successful run ends with:

```text
OK
```

Validate Python syntax and the frozen protocol identity:

```bash
python3 -m compileall -q benchmark

shasum -a 256 \
  benchmark/protocols/http3-paired-r6.5.4.5.json
```

Expected protocol SHA-256:

```text
99805dd378310ec539246e655d3f2a690036e4e50ac83c27c52765d1a50fb387
```

## Quick start: exercise the portable lifecycle

Create a provider-neutral local smoke experiment:

```bash
./scripts/experiment.sh create \
  --deployment environments/local/single-host.json \
  --workload http3 \
  --variant stock \
  --variant ngi541-direct \
  --repetitions 2 \
  --comparison-mode paired-balanced
```

The first output line is the generated experiment ID.

Plan it:

```bash
./scripts/experiment.sh plan <experiment-id>
```

Inspect lifecycle state:

```bash
./scripts/experiment.sh status <experiment-id>
```

This smoke path validates experiment creation and planning. It is not a publication-grade performance campaign.

## Build and validate the NGINX integration

NGI541 is an external installed dependency. Build and install the matching NGI541 revision first from:

```text
https://github.com/ngi541/ngi541
```

Then, in this repository:

```bash
./scripts/fetch-deps.sh

export NGI541_PREFIX=/absolute/path/to/ngi541/install

./scripts/build.sh
./scripts/test.sh
```

The functional test gate verifies targeted HTTP/3/QUIC behavior and the pinned NGINX regression set. Functional correctness is a prerequisite for performance experimentation; it is not itself a performance claim.

## Reproduce the full controlled local methodology

The frozen local reference campaign requires the corresponding DUT/load-generator topology, SSH access, required system tools, and NGI541/NGINX runtime artifacts.

The framework stages are intentionally explicit:

```bash
./scripts/experiment.sh network-qualify \
  --config benchmark/configs/r6.5.1-pi-mac-network.json \
  --bootstrap

./scripts/experiment.sh loadgen-runtime \
  --config benchmark/configs/r6.5.4.2-pi-http3-loadgen.json \
  --bootstrap

./scripts/experiment.sh network-evidence \
  --config benchmark/configs/r6.5.3c-pi-mac-network-evidence.json

./scripts/experiment.sh scientific-corpus \
  --config benchmark/configs/r6.5.3d-scientific-corpus.json

./scripts/experiment.sh transport-security \
  --config benchmark/configs/r6.5.4.2-pi-mac-http3-security.json

./scripts/experiment.sh dual-host-telemetry \
  --config benchmark/configs/r6.5.4.2-pi-mac-dual-host-telemetry.json

./scripts/experiment.sh workload-planner \
  --config benchmark/configs/r6.5.4.2-pi-mac-stock-workload-planner.json

./scripts/experiment.sh final-freeze \
  --config benchmark/configs/r6.5.4.2-pi-mac-final-freeze.json

./scripts/experiment.sh paired-execution \
  --config benchmark/configs/r6.5.4.5-pi-mac-paired-scientific-execution.json
```

After a paired execution reaches `COMPLETE`, generate the read-only publication artifact:

```bash
./scripts/experiment.sh results \
  --experiment <paired-execution-directory>
```

The publication command independently validates the frozen campaign, raw/processed identity, paired analysis, lifecycle evidence, and artifact inventory before exporting results.

## Reproducibility model

The framework separates three identities:

```text
Scientific protocol
    what is measured and how results are interpreted

Deployment
    where the experiment runs and how logical roles map to machines

Execution instance
    the concrete realization with exact binaries, hosts, timestamps,
    measurements, telemetry, and generated evidence
```

Changing a provider should not silently change scientific semantics.

See:

- [`docs/benchmark-methodology.md`](docs/benchmark-methodology.md)
- [`docs/reproducibility.md`](docs/reproducibility.md)
- [`docs/experimental-scope.md`](docs/experimental-scope.md)
- [`docs/portability-contract.md`](docs/portability-contract.md)
- [`docs/analysis.md`](docs/analysis.md)

## Relationship to NGI541

The cryptographic engine is maintained separately:

- NGI541 engine: <https://github.com/ngi541/ngi541>
- project website: <https://ngi541.org>

This separation is intentional. The benchmark framework may build, integrate, execute, and evaluate an NGI541 revision, but the framework repository is not the production cryptographic library.

## License

NGI541 Benchmark Framework is licensed under the [Apache License 2.0](LICENSE).
