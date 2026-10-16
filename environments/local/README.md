# Local deployment

The local deployment is the minimal provider implementation used for framework development and smoke validation.

Canonical descriptor:

```text
environments/local/single-host.json
```

It maps both logical roles to one machine:

```text
node: local
roles:
  - dut
  - loadgen
```

## Intended use

Use the local descriptor for:

- CLI and lifecycle development;
- schema and deployment validation;
- functional workload checks;
- low-cost reproduction of framework behavior;
- preliminary performance exploration.

Create a local portable experiment with:

```bash
./scripts/experiment.sh create \
  --deployment environments/local/single-host.json \
  --workload http3 \
  --variant stock \
  --variant ngi541-direct \
  --repetitions 2 \
  --comparison-mode paired-balanced
```

Then plan it:

```bash
./scripts/experiment.sh plan <experiment-id>
```

## Claim boundary

A single-host deployment shares CPU, memory, and operating-system resources between load generation and the DUT.

It is therefore **not equivalent to a dedicated client/server topology** and should not be used to generalize high-speed end-to-end performance claims.

Publication-grade high-speed characterization should use dedicated nodes with explicit network and host qualification.
