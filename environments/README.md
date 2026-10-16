# Deployment identity and role bindings

The provider-neutral experiment request assigns canonical roles `dut` and `loadgen` to concrete machine nodes via a deployment descriptor. Deployment does **not** choose scientific workloads, order variants or interpret results.

The descriptor records provider and access mechanism; the realized run separately records OS, CPU/ISA, NUMA, NIC, frequency/throttling state, runtime SHA-256, network envelope and telemetry. Those values are indispensable for interpreting results but are excluded from the **scientific protocol identity**.

The local reference descriptor is [`local/single-host.json`](local/single-host.json). It supports generic lifecycle smoke and is not equivalent to a qualified two-host scientific campaign. Only implemented providers should be accepted; unavailable provider adapters must fail closed.

```bash
./scripts/experiment.sh create \
  --deployment environments/local/single-host.json \
  --workload http3 --variant stock --variant ngi541-direct \
  --repetitions 2 --comparison-mode paired-balanced
```

See [deployment adapters](../docs/environment-adapters.md) and [portability contract](../docs/portability-contract.md).
