# Config-driven experiment campaigns

A `campaign` is a **specific normalized experiment definition** that may drive the generic framework state machine from creation through preparation, sealing, measured execution, deterministic analysis and final validation. The campaign interface is **not interchangeable** with an individual scientific qualification definition.

## Entry point

```bash
./scripts/experiment.sh campaign \
  --config /path/to/valid-campaign-definition.json
```

The campaign file must conform to the framework's campaign definition contract, with workload parameters, explicit conditions, comparison policy, source/runtime identities and any applicable host measurement controls. The `benchmark/configs/r6.5.4.5-pi-mac-paired-scientific-execution.json` file belongs to **`paired-execution --config`**, not to `campaign`.

## State transitions and artifacts

`create` persists request identity → `plan` persists the complete schedule → `prepare` inventories/validates sources, binaries and hosts → `seal` freezes provenance and experiment manifest → `execute` collects append-only attempts → `analyze` deterministically selects structurally valid attempts and generates paired results → `COMPLETE` is validated, not simply asserted.

## Resume and change detection

- A matching incomplete campaign can resume through the next legal stage.
- A matching complete campaign is independently validated rather than regenerated.
- More than one compatible incomplete instance requires an explicit `--experiment-id`.
- Same campaign name with incompatible definition cannot silently resume.
- `--new` intentionally allocates another instance of the accepted definition.
- Once sealed, the framework implementation identity is checked on resume to prevent analysis or execution by silently changed code.

An execution failure is not automatically retried on the basis of low goodput or high CPU cost. Operational failures and all attempts remain observable.

## Scientific claim policy

A generic campaign may have a different workload or repetition count. Only a campaign that *satisfies the accepted frozen HTTP/3 protocol* can support claims under R6.5.4.5. The generic two-repetition local CLI example is a smoke test, not a substitute for the four-pair controlled scientific execution.

See [lifecycle](experiment-lifecycle.md), [experiment schema](experiment-schema.md) and [analysis](analysis.md).
