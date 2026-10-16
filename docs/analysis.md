# Deterministic measurement analysis and paired inference

## Inputs and selection

The analysis reads only sealed `config/resolved.json`, frozen `execution/schedule.json` and retained raw attempts under `raw/runs/<run-id>/attempt-*/measurement.json`. It does **not** re-execute NGINX, reselect load or query live hardware. The first structurally valid attempt in increasing attempt order is selected; later attempts cannot replace it because their performance values are more favorable. Malformed first-valid attempt data fails analysis rather than silently switching samples.

The selected run table preserves schedule identity, exact condition, pair/repetition, variant and measurement-window quantities. `processed/selection.json` exposes selected and ignored attempts. Inputs are append-only after execution.

## Primary / secondary metrics

| Metric | Priority | Direction of improvement |
| --- | --- | --- |
| `application_goodput_mbps` | Primary | Higher; may be network-ceiling limited |
| `dut_process_cpu_seconds_per_gib` | Primary | Lower |
| `dut_estimated_energy_j_per_gib` | Secondary, estimated | Lower; not direct joule-meter measurement |
| `loadgen_max_total_cpu_busy_percent` | Secondary diagnostic | Lower is more headroom |
| `loadgen_max_single_core_busy_percent` | Secondary diagnostic | Lower is more headroom |

## Pairing and interpretation

The accepted protocol pairs baseline OpenSSL/NGINX and NGI541-integrated NGINX **within the same frozen condition and repetition**. Each paired relative percentage is:

```text
ratio = candidate_measurement / baseline_measurement
delta_percent = (ratio - 1) × 100
```

For goodput, positive deltas favor the candidate. For CPU seconds/GiB, **negative deltas favor the candidate**. Summary uses the **median paired delta**, preserving condition-level variation, wins/losses/ties and dispersion. Four repetitions per condition are frozen. Do not substitute independent group means for pairwise analysis.

For general framework analysis, deterministic CSV/JSON include per-variant n/mean/median/min/max, sample standard deviation and coefficient of variation where valid; generated SVG figures are derived presentation artifacts. The normalized numeric outputs are authoritative.

## Integrity

Analysis provenance records the framework revision. Output hash manifests permit byte-level revalidation. Reprocessing identical sealed inputs with the same implementation should reproduce the same processed values and deterministic plots. Publication `results --experiment` independently checks the completed chain and exports under `artifacts/results/`.

## Evidence scope

The local accepted campaign previously reported about 8.216% lower DUT CPU seconds/GiB, a favorable result in 44/48 valid pairs, near-zero goodput delta and ~0.248% lower *estimated* energy/GiB. These are **local, bandwidth-limited** observations pending publicly archived artifact linking—not general hardware or HPC claims. Publish the raw/processed artifact and verified DOI before promoting them as externally independently reproduced findings.

See [methodology](benchmark-methodology.md) and [reproducibility](reproducibility.md).
