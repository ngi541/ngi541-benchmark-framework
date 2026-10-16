# Benchmark topologies and measurement isolation

![Controlled HTTP/3 paired comparison](assets/framework-overview.svg)

## Dedicated client / server measurement topology

The implemented frozen reference campaign uses separate **load-generator** and **NGINX DUT** roles. The client sends the same deterministic objects via a qualified network to one server role. The server is configured as baseline or NGI541 candidate on separate paired runs. No two candidates serve traffic concurrently. Both hosts emit qualification and runtime telemetry; network/host validity is part of acceptance.

Required controls include negotiated network capacity, traffic/request correctness, CPU topology, frequency and thermal throttling state, relevant NIC configuration, DUT server-process CPU accounting and load-generator CPU saturation limits. The accepted local campaign has a limited service envelope; apparent goodput equivalence does not establish that crypto improvements vanish on an unconstrained fabric.

## Local one-host smoke topology

[`../environments/local/single-host.json`](../environments/local/single-host.json) places `dut` and `loadgen` on the same host for lifecycle/schedule validation. It shares CPU, interrupts and networking, so it is **not equivalent to the qualified two-host scientific reference** and should not be used to assert dedicated-network performance.

## Provider-independent identity

Scientific inputs and balanced pairing belong to the protocol. Mapping `dut` and `loadgen` to SSH targets, NUMA nodes and network interfaces belongs to deployment and provenance. Different deployment does not authorize a changed acceptance rule without a new protocol revision.

See [portability contract](portability-contract.md), [environment adapters](environment-adapters.md), and [reproducibility](reproducibility.md).
