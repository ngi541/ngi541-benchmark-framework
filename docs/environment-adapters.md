# Deployment adapters and normalized host evidence

## Core responsibility

A deployment adapter maps the logical roles `dut` and `loadgen` onto reachable nodes and produces normalized environment/provenance records. It may collect CPU model/ISA, frequency policy, NUMA topology, OS, memory, NIC and transport interface facts. It must **not** select the workload, reinterpret scientific metrics, change the A/B order or discard measurements.

The generic CLI accepts a versioned `--deployment` descriptor. A provider selector and an access method are distinct concepts: a provider name is descriptive metadata, while access might be local or SSH. Host names, SSH targets, public IP addresses and local paths never form the provider-independent scientific experiment identity.

## Currently implemented generic descriptor

[`../environments/local/single-host.json`](../environments/local/single-host.json) assigns both roles to a local machine for lifecycle/schedule smoke validation. This is not a two-host performance qualification.

```bash
./scripts/experiment.sh create \
  --deployment environments/local/single-host.json \
  --workload http3 \
  --variant stock --variant ngi541-direct \
  --repetitions 2 --comparison-mode paired-balanced
```

`create` validates the descriptor and records the scientific request. `plan <experiment-id>` generates paired run order without invoking the DUT or running HTTP traffic.

## Separately qualified two-host reference

The implemented controlled paired HTTP/3 command set additionally contains **pinned DUT/client execution definitions**. It checks reachability and link envelope, HTTP/3 client toolchain identity, scientific corpus hashes, transport security, sensor readiness, baseline-only planning and final freeze. These are environment-specific operational definitions under `benchmark/configs/`; they are **not** proof that every provider-neutral deployment descriptor is executable by the current specialized runner.

## Contract for any realized deployment

For every actual execution, retain machine inventory, source/runtime SHA-256, network service envelope and qualification diagnostics. Missing required controls must invalidate the experiment, not trigger hidden defaults. Hardware changes create new execution provenance, though the frozen scientific protocol can remain the same.

See [topology](topology.md), [portability](portability-contract.md) and [reproducibility](reproducibility.md).
