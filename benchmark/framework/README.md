# Experiment framework core

The R5 framework provides a portable, standard-library-only lifecycle for reproducible NGI541 network-data-path experiments.

## Implemented through R5.5

Current commands are:

```text
create
plan
prepare
seal
execute
analyze
status
validate
```

R5.4 added the first measured workload adapter: NGINX HTTP/3.
R5.5 adds deterministic analysis and closes the lifecycle:

```text
CREATED
  ↓
PREPARING
  ↓ plan / prepare / seal
READY
  ↓ execute
RUNNING
  ↓ all scheduled runs have a valid measurement
ANALYZING
  ↓ analyze
COMPLETE
```

## Analysis contract

`analyze` consumes the frozen schedule plus append-only raw `measurement.json` files. It does not run the workload again.

Attempt selection is metric-independent:

```text
for each scheduled run_id:
    sort attempts by attempt number
    select the first attempt with execution.valid == true
```

A later valid attempt is never substituted because it has a better metric. If the first valid attempt is structurally malformed, analysis fails rather than falling forward to a later attempt.

The primary metric for the current HTTP/3 adapter is `requests_per_second`.

Generated artifacts:

```text
processed/selection.json
processed/runs.csv
processed/summary.csv
processed/pairs.csv
processed/statistics.json
processed/analysis-provenance.json
processed/README.md
processed/artifacts.sha256
figures/requests-per-second.svg
figures/paired-delta.svg
```

Per-variant summaries contain `n`, mean, median, min, max, sample standard deviation, and coefficient of variation. Sample standard deviation and CV are null for `n < 2`.

For `paired-balanced` experiments with exactly two variants, the first variant in the sealed resolved configuration is the baseline and the second is the candidate. Pair delta is:

```text
(candidate / baseline - 1) * 100
```

Paired output includes per-pair delta, wins/losses/ties, mean and median paired delta, and geometric-mean ratio when every ratio is positive.

All analysis output is generated with the Python standard library. SVG files are dependency-free and deterministic. `processed/artifacts.sha256` protects the generated result set, and COMPLETE validation rechecks those hashes.

## HTTP/3 example

Create a smoke experiment:

```bash
./scripts/experiment.sh create \
  --workload http3 \
  --environment local \
  --variant stock \
  --variant ngi541-direct \
  --repetitions 1 \
  --param 'payload_bytes=[16384]' \
  --param 'workers=[1]' \
  --param 'clients=[2]' \
  --param 'requests_per_client=100' \
  --param 'warmup_requests_per_client=5'
```

After `plan`, `prepare`, `seal`, and `execute`, successful execution ends in `ANALYZING`.

Complete it with:

```bash
./scripts/experiment.sh analyze <experiment-id>
./scripts/experiment.sh validate <experiment-id>
```

A successful analysis ends in `COMPLETE`.

## Runtime artifact rule

Variant runtime paths are provided only during preparation. The sealed experiment stores relative artifact locations and SHA-256 identities. Execution re-verifies hashes before copying those artifacts into an ephemeral per-attempt runtime directory.

## Dependencies

Core framework and R5.5 analysis:

```text
Python 3 standard library
Git
```

HTTP/3 execution additionally requires:

```text
NGINX with --with-http_v3_module
curl with --http3-only, --tls13-ciphers, and --out-null
OpenSSL-compatible certificate generation command
```

No NumPy, pandas, matplotlib, PyYAML, or JSON-Schema runtime package is required.

## R5.6 config-driven campaign orchestration

A versioned campaign definition can drive the complete experiment lifecycle:

```bash
./scripts/experiment.sh campaign \
  --config benchmark/configs/c2.2-local-http3.json
```

The command creates or resumes the matching experiment and advances only through legal lifecycle transitions: plan, prepare, seal, validate, execute, validate, analyze. The campaign definition is snapshotted into `config/campaign.json` and identified by a canonical SHA-256.

Explicit `experiment.conditions` are ordered exact conditions and are not expanded as a Cartesian matrix. See `docs/campaigns.md`.

## R6.2 measurement controls

Config-driven campaigns may opt into `experiment.scheduling` and
`experiment.measurement_control`.

`condition_order=rotating-rounds` executes explicit conditions in deterministic
repetition rounds. `variant_order=balanced-by-condition-round` keeps AB/BA
balanced per condition while offsetting A/B order across conditions in the same
round.

When host-state control is enabled, execution records normalized temperature,
thermal/throttling state, power source and CPU pressure. R6.2.1 does not use a
framework-wide temperature or CPU-busy threshold: CPU readiness is derived from
a per-execution consecutive-static-ready idle calibration (which waits through
transient thermal/power constraints up to its timeout), and a variant starts only after the configured
number of consecutive acceptable samples. On Darwin, required temperature uses
one persistent privileged `powermetrics` sampler for the execution session, so
long campaigns do not depend on sudo credential-cache lifetime.

`runtime.stage_artifacts_once` removes the previous O(runs × binary-size)
runtime duplication. `runtime.cleanup_attempt_runtime` removes transient runtime
directories after raw evidence has been persisted.
