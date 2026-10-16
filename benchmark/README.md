# Benchmark definitions and implementation

The benchmark layer holds the **active executable definitions** and the standard-library Python orchestration/analysis implementation. It does not claim that every available machine is a qualified DUT.

| Directory | Contract |
| --- | --- |
| `configs/` | Versioned execution/qualification definitions; currently includes Pi/Mac-specific reference bindings |
| `framework/` | CLI, execution lifecycle, preflight, telemetry, validity, analysis, results validation |
| `framework/schemas/` | JSON Schema files describing experiment/evidence records |
| `protocols/` | Immutable provider-independent methodology (current: `http3-paired-r6.5.4.5.json`) |
| `scientific-profiles/` | CLAS12/LCLS/HACC-inspired deterministic shape definitions |
| `workloads/http3/` | NGINX/HTTP/3 workload adapter and per-run measurements |

The primary comparison is **baseline OpenSSL/NGINX server path** versus **NGI541-integrated QUIC server crypto path**, internally identified as `stock` and `ngi541-direct`. The client and scientific object stream are held constant. Four frozen paired repetitions per condition are specified by the accepted protocol; CLI smoke examples may use two repetitions to validate only scheduling.

```bash
python3 -m unittest discover -s benchmark/framework/tests -p 'test_*.py'
./scripts/experiment.sh --help
```

Source-owned definitions are not runtime data. Execution instances live in ignored `experiments/`; qualification results and materialized corpus/publication bundles live in ignored `qualifications/`, `corpora/` and `artifacts/`. See [framework contract](framework/README.md), [protocols](protocols/README.md) and [methodology](../docs/benchmark-methodology.md).
