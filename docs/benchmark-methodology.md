# Benchmark methodology

NGI541 performance evaluation separates cryptographic execution effects from protocol, operating-system, scheduler, and network effects as far as the available environment permits.

No performance result is considered meaningful without a corresponding correctness baseline.

## Measurement levels

NGI541 evaluation uses two complementary measurement levels.

### Primitive level

Primitive benchmarks isolate cryptographic execution.

Relevant measurements include:

```text
operations per second
bytes per second
cycles per operation
cycles per byte
instructions per operation
instructions per byte
```

Primitive evaluation should distinguish, where applicable:

```text
key preparation
steady-state prepared execution
encrypt
decrypt
authentication failure
```

The purpose of primitive evaluation is to measure the execution backend independently from protocol segmentation, socket processing, scheduler behavior, and network-stack effects.

### Protocol and system level

Protocol workloads evaluate NGI541 inside a real network data path.

Initial and planned workload classes include:

```text
HTTP/3 over QUIC
TLS 1.3 over TCP
TLS reverse proxy
long-lived TLS connections
small-message and high-concurrency workloads
```

Protocol payload size must not be confused with individual cryptographic operation size.

For example, a large HTTP/3 response may be protected as multiple QUIC packets and therefore many smaller AEAD operations.

## Correctness gate

Before performance data is accepted, the implementation under test must pass the relevant functional and regression validation.

Performance measurements from a configuration that fails correctness validation are invalid.

## Comparison model

When comparing NGI541 with a baseline, implementations should use equivalent protocol versions, source dependencies, workload configuration, and execution environment wherever possible.

Future campaigns should use paired and balanced comparison order.

A typical pair may use:

```text
baseline → NGI541
```

while the next pair reverses the order:

```text
NGI541 → baseline
```

Alternatively, a reproducible randomized order may be used when the seed is recorded.

This reduces systematic bias from temperature, CPU frequency state, background activity, and run order.

## Warm-up

Warm-up is separate from the measured interval.

The warm-up policy must be explicit and must not contribute to the reported measurement.

Warm-up should exercise the same relevant protocol and cryptographic paths as the measured workload.

## Repetition

A benchmark campaign must contain repeated measurements.

Single-run performance numbers are diagnostic only and are not sufficient for canonical project claims.

Raw results from every completed run are preserved.

## Statistics

The primary summary statistic for throughput comparisons is the median.

Where paired A/B runs are available, paired relative deltas should also be reported.

Dispersion should be reported using an appropriate statistic such as:

- coefficient of variation;
- interquartile range;
- confidence intervals.

Geometric means may be used for normalized multi-workload summaries, but must not replace per-workload results.

Outliers are preserved in raw data.

An outlier may be excluded from a derived statistic only if the exclusion rule is explicit, justified, and reproducible.

## Workload dimensions

The benchmark framework is expected to support a matrix including:

```text
payload size
connection concurrency
worker count
protocol
cipher suite
integration mode
traffic direction
connection lifetime
hardware architecture
```

A useful starting payload set for dedicated-system experiments is:

```text
256 B
1 KiB
4 KiB
16 KiB
64 KiB
```

A useful initial connection set is:

```text
1
8
16
32
64
```

Worker counts may include:

```text
1
2
4
8
```

subject to available CPU topology.

These are framework defaults rather than mandatory values for every campaign.

## Connection lifetime

Steady-state and connection-establishment workloads must be treated separately.

NGI541 primarily targets symmetric cryptographic execution in established network data paths.

A short-lived TLS workload may be dominated by handshake, certificate, and key-agreement costs outside NGI541's current execution scope.

## Traffic direction

Where relevant, experiments should distinguish:

- primarily server-to-client transfer;
- primarily client-to-server transfer;
- bidirectional traffic;
- independent downstream and upstream traffic in proxy scenarios.

This distinction is important because encryption and decryption paths may exercise different execution patterns.

## System measurements

Where supported by the environment, protocol-level evaluation should collect:

```text
throughput
CPU utilization
cycles
instructions
cache behavior
branch behavior
worker/core scaling efficiency
```

Latency distributions such as p50, p95, and p99 should only be reported when the measurement tool and topology provide a valid latency measurement.

## Hardware performance counters

PMU measurements are environment-specific and must record the counter set and collection mechanism.

Derived metrics must identify the raw counters from which they were computed.

See also:

- [`reproducibility.md`](reproducibility.md)
- [`topology.md`](topology.md)
- [`experimental-scope.md`](experimental-scope.md)
