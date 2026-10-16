# Portability contract

NGI541 benchmark semantics and deployment identity are separate contracts.

## Scientific definition

The scientific definition contains only experiment semantics:

- workload and variants;
- parameters and conditions;
- comparison and scheduling policy;
- measurement controls;
- validity rules;
- analysis policy.

Scientific identity must exclude:

- provider names;
- machine names;
- SSH targets;
- CloudLab identifiers;
- local absolute paths;
- hardware inventory.

`benchmark/framework/experiment_identity.py` computes the provider-independent
scientific identity.

## Deployment

A deployment binds the canonical roles:

```text
dut
loadgen
```

to concrete nodes and access methods.

Provider is deployment metadata. Hardware, operating-system, network, runtime,
and toolchain details become execution provenance.

`benchmark/framework/deployment.py` validates this boundary.

## Execution instance

An execution instance is a concrete realization of a scientific definition on
a deployment.

Generated experiment directories, qualification outputs, deterministic corpus
materializations, and publication bundles are runtime/research data. They are
not part of the source repository.

## Canonical protocol

The accepted paired HTTP/3 scientific methodology is:

```text
benchmark/protocols/http3-paired-r6.5.4.5.json
```

It is provider-neutral and contains no host binding.

The source repository keeps only code and active definitions required to
reproduce the methodology. Superseded milestone snapshots, compatibility
layouts, and historical local experiment trees are intentionally not retained
on `main`; Git history and release tags provide repository history.
