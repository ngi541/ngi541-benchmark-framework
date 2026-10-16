# Deployment environments

`environments/` contains deployment descriptions for realizing benchmark roles on concrete infrastructure.

Scientific methodology and infrastructure realization are deliberately separate.

A benchmark protocol should not need to know whether its logical `dut` and `loadgen` roles run on a developer machine, manually allocated bare metal, or CloudLab.

## Deployment contract

A deployment descriptor maps logical roles to nodes and records provider-specific realization data.

Provider-specific data may include:

- host identity;
- SSH connection information;
- network interfaces;
- CPU topology;
- NUMA placement;
- frequency/governor policy;
- IRQ placement;
- NIC capabilities;
- operating-system details;
- performance-counter availability.

These details are execution provenance. They must not silently modify scientific workload semantics or analysis rules.

## Current implementation

The currently realized portable descriptor is:

```text
environments/local/single-host.json
```

It maps both `dut` and `loadgen` to one local node and is intended for framework development, smoke testing, and preliminary evaluation.

## CloudLab target

CloudLab is the next planned provider adapter.

The intended CloudLab implementation will map the same logical roles onto dedicated bare-metal nodes while capturing provider-specific allocation and hardware information only as deployment provenance.

The target is to support reproducible high-speed experiments with explicit control of:

```text
CPU topology
NUMA placement
frequency policy
NIC selection
interrupt placement
network topology
host readiness
```

CloudLab support must not create CloudLab-specific scientific identities.

## Rule

If moving an experiment from one provider to another changes only infrastructure realization, the scientific protocol should remain the same.

If the move requires changing workload semantics, measurement rules, validity rules, metrics, pairing, or analysis, that is a scientific protocol revision rather than a deployment change.
