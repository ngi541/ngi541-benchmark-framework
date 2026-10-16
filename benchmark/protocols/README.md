# Frozen provider-independent protocol

[`http3-paired-r6.5.4.5.json`](http3-paired-r6.5.4.5.json) defines the scientific methodology independently of where it is executed. Its frozen SHA-256 is:

```text
99805dd378310ec539246e655d3f2a690036e4e50ac83c27c52765d1a50fb387
```

## Exact R6.5.4.5 contract

- Four repetitions per frozen condition, `paired-balanced`, rotating condition order and balanced by condition/round variant order.
- Strict main measurement window; 1.0-second telemetry sampling and 5-second thermal guard interval.
- No HTTP failures; no throttling; max generator aggregate CPU busy 85%, max busiest core 95%.
- Retry policy `no-metric-dependent-retry`, outlier policy `retain-all-valid-runs`.
- Primary metrics `application_goodput_mbps`, `dut_process_cpu_seconds_per_gib`.
- Secondary metrics `dut_estimated_energy_j_per_gib`, `loadgen_max_total_cpu_busy_percent`, `loadgen_max_single_core_busy_percent`.
- `median-paired-delta` within condition and repetition; HACC uses a frozen planner subset, **not** a full dataset.

The protocol does **not** contain host addresses, allocation IDs or SSH targets. A change to scientific semantics requires a new version; environment adaptation alone does not. Verify the bytes:

```bash
shasum -a 256 benchmark/protocols/http3-paired-r6.5.4.5.json
```

See [portability](../../docs/portability-contract.md) and [methodology](../../docs/benchmark-methodology.md).
