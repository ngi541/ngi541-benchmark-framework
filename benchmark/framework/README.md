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

## R6.5.1 network qualification

R6.5.1 introduces a framework-integrated pre-HTTP/3 network qualification:

```bash
./scripts/experiment.sh network-qualify \
  --config benchmark/configs/r6.5.1-pi-mac-network.json \
  --bootstrap
```

The command auto-discovers the local route/interface/address used to reach the
remote data endpoint, inventories the remote Linux interface over SSH, then
runs bidirectional ping, TCP iperf3 and UDP iperf3 sweeps. Raw command records,
normalized results and SHA-256 artifact inventory are stored under
`qualifications/network/<qualification-id>/`.

`iperf3` is used only to characterize the network path. QUIC/HTTP/3 traffic is
introduced in later R6.5 stages and is not run concurrently with iperf3.

## Remote HTTP/3 load-generator runtime

R6.5.2 adds `loadgen-runtime`, which provisions a pinned curl + OpenSSL + ngtcp2 + nghttp3 stack on a Linux SSH peer without replacing the system curl. Source archives are SHA-256 pinned and a matching runtime is reused by semantic definition hash.

```bash
./scripts/experiment.sh loadgen-runtime \
  --config benchmark/configs/r6.5.2-pi-http3-loadgen.json \
  --bootstrap
```


## R6.5.3b h2load runtime

`loadgen-runtime` supports `curl-h2load-http3-ngtcp2` in addition to the R6.5.2 curl-only definition. The h2load qualification gate requires HTTP/3, JSON output, timing-script and RPS capabilities while preserving explicit connection and stream controls for the future transport planner.

## R6.5.3c network evidence and deterministic envelope

R6.5.3c resolves a strict, immutable evidence set from completed R6.5.1
network qualifications and derives a conservative DUT-to-loadgen service
envelope:

```bash
./scripts/experiment.sh network-evidence \
  --config benchmark/configs/r6.5.3c-pi-mac-network-evidence.json
```

The resolver requires at least three observations from one strict path
fingerprint.  It never combines different topology classifications, endpoint
addresses, interfaces, link identity/capability or HTTP/3 response directions.
The newest compatible topology group is used, and the latest configured number
of observations from that group is frozen into the evidence set.

If the current topology has too few observations and `auto_collect_missing` is
true, the resolver runs the referenced R6.5.1 qualification until the required
count is reached.  Missing observations collected in one resolver invocation
reuse one SSH ControlMaster session, so password authentication is requested
once rather than once per observation.

A UDP point is safe only when both conditions hold:

```text
observed loss <= configured maximum loss
achieved throughput / requested throughput >= configured minimum ratio
```

The deterministic envelope is:

```text
tcp_floor = min(best directional TCP throughput per selected observation)
udp_floor = min(safe directional UDP achieved throughput per selected observation)
service_envelope = min(tcp_floor, udp_floor)
```

An unfavorable selected observation is never dropped because of its metric. If
one selected observation has no UDP point satisfying the policy, derivation
fails instead of silently replacing that observation with a more favorable run.

The machine-readable result is stored at:

```text
qualifications/network-evidence/<evidence-id>/processed/network-envelope.json
```

Given the same frozen observations and policy, `network-envelope.json` is
byte-semantically deterministic and carries its own semantic SHA-256. The
result is an empirically qualified path envelope, not a claim of reserved or
guaranteed bandwidth.

## R6.5.3d deterministic scientific corpus

R6.5.3d turns the immutable R6.5.3a scientific profiles into deterministic
corpus manifests without making execution parameters part of scientific
semantics:

```bash
./scripts/experiment.sh scientific-corpus \
  --config benchmark/configs/r6.5.3d-scientific-corpus.json
```

CLAS12 and LCLS are lazy indexed streams whose per-object bytes are generated
from stable SplitMix64 recipes. HACC is a finite 19,260-object logical corpus;
its synthetic per-object sizes satisfy the published histogram, exact logical
byte total and published extrema. The full 4.4 TB dataset is not materialized.

HACC coverage is first-class and deterministic: `full`,
`deterministic-stratified`, and `time-window`. Coverage selection changes only
which logical objects are exercised; it never changes scientific object
semantics. Results are content-addressed under `corpora/scientific/` and are
reused only after artifact-integrity validation.

## R6.5.3e transport security qualification

R6.5.3e binds the frozen R6.5.3c network evidence, R6.5.3b remote HTTP/3
runtime, and R6.5.3d scientific corpus into a non-performance remote transport
gate:

```bash
./scripts/experiment.sh transport-security \
  --config benchmark/configs/r6.5.3e-pi-mac-http3-security.json
```

The gate runs both `stock` and `ngi541-direct` NGINX variants, requires HTTP/3
only, TLS 1.3, `TLS_AES_128_GCM_SHA256`, verified peer identity through an
ephemeral test CA, and disabled 0-RTT.  Pinned remote curl verifies certificate,
HTTP version, response size and scientific-object SHA-256.  Pinned HTTP/3
h2load is additionally exercised once per variant as a functional QUIC path
probe.  R6.5.3e makes no performance claim and performs no adaptive tuning.

## R6.5.3f dual-host telemetry qualification

R6.5.3f validates the normalized telemetry providers that will be used by the
stock-only workload planner and later paired campaigns:

```bash
./scripts/experiment.sh dual-host-telemetry \
  --config benchmark/configs/r6.5.3f-pi-mac-dual-host-telemetry.json
```

The Darwin DUT provider records system load, a process-tree CPU/RSS snapshot,
interface counters, temperature/thermal context, average frequency when exposed,
and an optional `powermetrics` package-power estimate. Package power is explicitly
an estimated same-host paired metric; it is never treated as calibrated wall power
or compared across machines.

The Linux load-generator provider records total and per-core CPU utilization,
per-core frequency, temperature, Raspberry Pi firmware throttling state, process
CPU/RSS, interface counters and UDP input errors. Raspberry Pi total watts are
reported unavailable unless a future external current/power sensor provider is
configured; voltage alone is never converted into watts.

### R6.5.3g stock-only workload planning

`workload-planner` resolves the frozen R6.5.3b–f evidence, runs adaptive
concurrency/rate calibration against **stock only**, enforces load-generator and
DUT telemetry headroom, and freezes `processed/workload-plan.json`. Candidate
NGI541 code is prohibited from participating in planning.

## R6.5.3h lifecycle / resume / final freeze

`final-freeze` validates the complete R6.5.3 evidence chain and emits an
immutable `processed/final-manifest.json` for R6.5.4:

```bash
./scripts/experiment.sh final-freeze \
  --config benchmark/configs/r6.5.3h-pi-mac-final-freeze.json
```

The command persists the frozen R6.5.3 lifecycle, can resume a FAILED freeze
from its last completed phase, and never re-resolves artifact identities after
`INPUTS_FROZEN`.  The final manifest pins the workload-plan SHA, both variant
binary/library hashes, all prerequisite evidence IDs/hashes, and prohibits
adaptive replanning, candidate-variant tuning, metric-dependent retry and
metric-dependent outlier deletion in R6.5.4.

## R6.5.4.1 paired scientific execution

`paired-execution` consumes the complete R6.5.3h freeze and executes the frozen 12-condition workload plan for `stock` and `ngi541-direct` with four balanced paired repetitions per condition. No adaptive replanning, metric-dependent retry, or metric-dependent outlier deletion is permitted.

Measurement protocol revision `r6.5.4.1` explicitly raises and preflights the NGINX per-connection request cap, accounts scientific bytes only in the h2load main measurement phase, and uses a nonblocking DUT sampler with exact-window CPU/estimated-energy integration. The initial R6.5.4 partial campaign is retained as aborted evidence and is never resumed into R6.5.4.1.

## Scientific result publication

A COMPLETE paired scientific execution can be transformed into a deterministic,
read-only publication artifact:

```bash
./scripts/experiment.sh results \
  --experiment experiments/r6.5.4/<paired-execution-id>
```

`results` never modifies the source experiment. It independently verifies the
frozen campaign structure, raw/processed run identity, paired-analysis
recomputation, measurement validity, lifecycle evidence, final-freeze linkage
and immutable artifact inventory.

Generated publication artifacts live below `artifacts/results/` and are not
tracked by Git. The canonical root contract is `manifest.yaml`; compact results
and the full evidence dependency closure are exported as deterministic
`results.tar.gz` and `evidence.tar.gz` archives.


Publication figures use the predeclared condition-level median paired delta (four paired repetitions per condition) rather than an unlabeled pair-index scatter. The x-axis is percentage change versus stock, `0%` is explicitly marked as no difference, positive values favor `ngi541-direct`, and every condition reports its NGI541-direct pair-win count. All 48 valid pair-level values remain available in `tables/pair-results.csv`; no outlier deletion is performed.

The scientific result ID is stable for the accepted frozen execution. A separate `publication/bundle.json` gives the concrete exported package a content-addressed identity derived from the exact generator commit and archive checksums.


For publication figures, delta sign semantics are metric-aware. Goodput uses `(ngi541-direct - stock) / stock`, so positive means higher goodput. CPU cost per delivered GiB and estimated energy per delivered GiB use `(stock - ngi541-direct) / stock`, so positive means lower resource cost for `ngi541-direct`, while negative means higher resource cost. The generated SVG axis labels and subtitles state this explicitly.

## Portable experiment creation

New provider-independent experiments can use a deployment definition:

```bash
./scripts/experiment.sh create \\
  --workload http3 \\
  --deployment environments/local/single-host.json \\
  --variant stock \\
  --variant ngi541-direct \\
  --repetitions 2
```

The scientific identity excludes deployment provider, host names, SSH targets, hardware inventory, and aliases. The historical `--environment` form remains supported for frozen campaigns.
