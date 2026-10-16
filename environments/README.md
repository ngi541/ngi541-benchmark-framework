# Execution environments

The `environments/` directory contains adapters used to obtain and prepare execution environments for NGI541 experiments.

Environment code is deliberately separated from benchmark methodology.

A benchmark workload should not need to know whether it is running locally, on manually allocated bare metal, or on CloudLab.

The intended structure is:

```text
environments/
├── common/
├── local/
├── baremetal/
└── cloudlab/
```

Directories should be introduced together with real implementation rather than as empty placeholders.

## `common/`

Shared host preparation and environment discovery used by more than one environment adapter.

Typical responsibilities include:

- dependency checks;
- system inventory collection;
- CPU topology discovery;
- ISA capability discovery;
- common server/client preparation;
- PMU availability checks;
- environment metadata capture.

## `local/`

Single-host development and preliminary evaluation.

The historical C2.1 HTTP/3 measurements belong to this environment class.

Local execution is useful for integration development and early performance signals, but it cannot provide the isolation required for canonical multi-node performance characterization.

## `baremetal/`

Preparation of manually allocated dedicated systems.

This adapter is intended for environments where machines already exist and NGI541 does not control infrastructure allocation.

## `cloudlab/`

CloudLab-specific provisioning and topology description.

The CloudLab profile belongs here rather than in `benchmark/` because CloudLab provides execution resources; it does not define benchmark semantics.

## Boundary

Environment adapters may configure operating-system and hardware execution conditions, including:

```text
CPU affinity
NUMA placement
frequency/governor policy
IRQ placement
network interfaces
system dependencies
performance-counter access
```

They must not silently change benchmark workload parameters or statistical analysis rules.

Every experiment must record the environment adapter and the resulting system inventory in its provenance.

See:

- [`../docs/topology.md`](../docs/topology.md)
- [`../docs/reproducibility.md`](../docs/reproducibility.md)

## Portable deployment descriptor

Post-R6.5.4.5 portability work uses a machine-readable deployment contract in addition to adapter documentation.

The first descriptor is:

```text
environments/local/single-host.json
```

It assigns the canonical roles `dut` and `loadgen` to one local node. The provider (`local`) is deployment metadata and is intentionally excluded from scientific experiment identity.

Future CloudLab or manually allocated bare-metal adapters must realize the same role contract rather than introducing provider names into benchmark identity.

## Runtime support

The portable deployment contract is now wired into the generic experiment lifecycle. `local-single-host` is the first realized provider. CloudLab and manually allocated bare metal must implement the same `dut` / `loadgen` role contract; provider-specific allocation data must remain deployment provenance.
