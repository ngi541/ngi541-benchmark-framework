# Environment adapters

Environment adapters translate execution resources into the common R5 experiment ABI.

They do not define benchmark semantics. Workload semantics remain under the benchmark/workload layer.

## Contract

Every adapter must produce:

```text
environment/
├── adapter.json
└── nodes/
    └── <node-name>/
        ├── system.json
        ├── cpu.json
        ├── memory.json
        └── network.json
```

The adapter must normalize platform-specific discovery into these records.

Experiment consumers should not need to parse `sysctl`, `/proc/cpuinfo`, `lscpu`, CloudLab metadata, or provider-specific formats directly.

## Local adapter

R5.3 implements the first adapter:

```text
environment = local
topology = T0
```

The single local host has two roles:

```text
load-generator
dut
```

The local adapter supports macOS and Linux discovery using Python standard-library orchestration plus operating-system utilities where available.

Missing optional system information is represented as `null` or an empty collection rather than causing the experiment to fail.

## Bare-metal adapter

The future bare-metal adapter will map manually allocated machines into the same normalized node model.

A typical topology is:

```text
client:
  load-generator

server:
  dut
```

The benchmark framework must not require a different experiment schema for this topology.

## CloudLab adapter

CloudLab is an environment/provisioning adapter, not a benchmark implementation.

After CloudLab resources are allocated and reachable, the adapter must emit the same normalized node records and the same lifecycle boundary as local or manually allocated bare metal.

A typical HTTP/3 topology is:

```text
client:
  load-generator

server:
  dut
```

A reverse-proxy topology may use:

```text
client:
  load-generator

proxy:
  dut

origin:
  upstream
```

## Adapter invariants

An environment adapter must not:

- redefine experiment directory layout;
- choose A/B scheduling policy;
- interpret benchmark results;
- accept evidence claims;
- discard raw measurements.

Its responsibility ends at resource preparation, normalized inventory, and topology description.

## Portability transition after R6.5.4.5

The historical R5 adapter output and historical experiment directories remain immutable.

New portability work standardizes semantic node roles as:

```text
dut
loadgen
```

Provider and access are separate concepts:

```text
provider: local | baremetal | cloudlab | ...
access.mode: local | ssh
```

The initial machine-readable descriptor is `environments/local/single-host.json`.

Portability P1 introduces this contract without rewiring the historical `environment = local` execution path. Runtime migration is performed separately so that historical campaigns and publication evidence remain reproducible.
