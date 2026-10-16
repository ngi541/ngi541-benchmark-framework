# Scientific definition, deployment and execution identity

Portability is a **contract separation**, not a claim that every network provider is supported by the current scientific runner.

| Layer | Defines | Must not define |
| --- | --- | --- |
| Scientific protocol | Workload semantics, variants, repetitions, paired schedule, validity gates, primary/secondary metrics, analysis | Host addresses, SSH credentials, specific physical NIC or allocation IDs |
| Deployment | Logical `dut` / `loadgen` role mapping, provider and access mechanism, runtime path targets | Pair ordering, statistical acceptance rules or workload tuning |
| Execution instance | Actual host/CPU/NIC details, software hashes, qualification evidence, measurements, attempts, timestamps | Mutations of an already frozen protocol |

`benchmark/framework/experiment_identity.py` computes the semantic identity, and `benchmark/framework/deployment.py` validates the deployment descriptor. The accepted HTTP/3 methodology is [`../benchmark/protocols/http3-paired-r6.5.4.5.json`](../benchmark/protocols/http3-paired-r6.5.4.5.json), with SHA-256 `99805dd378310ec539246e655d3f2a690036e4e50ac83c27c52765d1a50fb387`.

## Runtime contract boundary

The generic `create --deployment` lifecycle supports the implemented provider adapter and records semantic identity independently from host bindings. The accepted `paired-execution --config` command remains tied to a separate, concrete frozen execution definition with upstream network/host evidence. Provider neutrality of the *protocol* does not imply universal execution portability.

## Preservation

The Git repository tracks source code and active definitions. `experiments/`, `qualifications/`, `corpora/`, `artifacts/`, downloaded source and build products remain ignored. Archival research bundles must preserve complete raw data plus their own hashes; Git history/tags retain obsolete implementation history without resurrecting legacy layouts in current `main`.

See [environment adapters](environment-adapters.md), [experiment schema](experiment-schema.md), [reproducibility](reproducibility.md).
