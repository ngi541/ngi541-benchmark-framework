# Local single-host descriptor

[`single-host.json`](single-host.json) maps `dut` and `loadgen` to one local machine for experiment-definition and scheduling smoke tests. This implementation is **not** a substitute for a separately qualified DUT and client. Shared CPU scheduling, thermal state and loopback data movement prevent uncontrolled extrapolation.

```bash
./scripts/experiment.sh create \
  --deployment environments/local/single-host.json \
  --workload http3 --variant stock --variant ngi541-direct \
  --repetitions 2 --comparison-mode paired-balanced
```

Use the printed experiment ID in `./scripts/experiment.sh plan <experiment-id>` to generate the planned schedule. Neither command builds NGINX or measures application throughput. For controlled two-host qualification see [execution lifecycle](../../docs/experiment-lifecycle.md) and [topologies](../../docs/topology.md).
