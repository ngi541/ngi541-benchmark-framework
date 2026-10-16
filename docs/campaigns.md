# Config-driven campaigns

The `campaign` command drives a versioned experiment definition through the
framework lifecycle without bypassing any validation or provenance step.

```bash
./scripts/experiment.sh campaign \
  --config <campaign-config.json>
```

A campaign definition is a research artifact. It contains the fixed workload
parameters, explicit ordered conditions, repetitions, comparison mode, runtime
artifact identities, and source requirements required by that campaign.

## Lifecycle

The orchestrator advances only through legal lifecycle transitions:

```text
create
  -> plan
  -> prepare
  -> seal
  -> validate
  -> execute
  -> validate
  -> analyze
  -> COMPLETE
```

The campaign command does not replace the underlying lifecycle artifacts. It
only determines the next valid stage.

## Resume semantics

The normalized campaign definition is hashed with SHA-256 and snapshotted as
`config/campaign.json` inside the generated experiment instance.

Re-running the same campaign definition follows these rules:

- exactly one incomplete match: resume it;
- an exact COMPLETE match: validate it and return without creating a duplicate;
- multiple incomplete matches: fail and require `--experiment-id`;
- same campaign name with a different definition: fail to prevent silent drift;
- `--new`: intentionally create a distinct execution instance.

Examples:

```bash
# Start or automatically resume.
./scripts/experiment.sh campaign \
  --config <campaign-config.json>

# Resume one exact experiment explicitly.
./scripts/experiment.sh campaign \
  --config <campaign-config.json> \
  --experiment-id <experiment-id>

# Intentionally create another instance.
./scripts/experiment.sh campaign \
  --config <campaign-config.json> \
  --new
```

A run failure is not automatically retried inside the same invocation.
Failed attempts remain append-only execution evidence. A later explicit resume
continues according to the frozen schedule and validity rules.

## Framework identity after sealing

For an active sealed campaign, resume is refused when the current framework
identity differs from the identity sealed into the experiment manifest. This
prevents execution or analysis from silently continuing with a different
framework implementation.

## Explicit conditions

`experiment.conditions` is an ordered list of exact workload conditions, not a
Cartesian product. Fixed parameters live in `experiment.parameters`. A
parameter name must not appear in both places.

This distinction is important for controlled paired experiments because the
condition set is part of the frozen scientific definition.

## Runtime identity

Every configured executable or shared library has an expected SHA-256.
Preparation and resumed execution verify those identities before use, and the
realized identities are recorded in provenance.

## Scheduling and measurement control

Campaign definitions may include deterministic scheduling and host-readiness
controls, including:

```json
{
  "scheduling": {
    "condition_order": "rotating-rounds",
    "variant_order": "balanced-by-condition-round"
  }
}
```

Measurement-control fields may define host telemetry/readiness, idle
calibration, runtime artifact staging/cleanup, and analysis warning thresholds.

These controls are part of the normalized campaign definition. Changing them
changes the campaign identity and therefore cannot silently resume a different
frozen experiment.
