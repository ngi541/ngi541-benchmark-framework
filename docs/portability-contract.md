# Portability contract

This document defines the post-R6.5.4.5 portability boundary for future NGI541 experiments.

The R6.5.4.5 execution and publication artifacts remain immutable. Historical paths containing `pi`, `mac`, `local`, or other host/provider names are provenance and are not renamed.

## Separation of identities

Future experiment infrastructure separates three different concepts.

### Scientific definition

The scientific definition contains benchmark semantics:

- workload;
- variants;
- parameters;
- explicit conditions;
- comparison policy;
- scheduling policy;
- measurement-control policy.

Its identity excludes:

- deployment provider;
- host names;
- SSH targets;
- CloudLab identifiers;
- hardware inventory;
- aliases.

`benchmark/framework/experiment_identity.py` provides a deterministic scientific projection, SHA-256 identity, and host-neutral definition ID.

### Deployment

A deployment describes where and how a scientific definition is executed.

The canonical roles are:

```text
dut
loadgen
```

A deployment assigns each role exactly once to a node. The same node may hold both roles for single-host development.

Provider is deployment metadata. Examples include `local`, `baremetal`, and `cloudlab`. Access mode is separate from provider and currently supports `local` and `ssh`.

`benchmark/framework/deployment.py` validates the deployment contract.

### Execution instance

An execution instance is one concrete run of a scientific definition on a realized deployment.

Execution provenance must retain the full deployment definition and hardware/software inventory. It must not promote provider or host names into the scientific definition identity.

## P1 scope

Portability P1 is deliberately additive.

It adds:

- the provider-independent scientific identity contract;
- the portable deployment contract;
- a canonical local single-host deployment descriptor;
- tests that freeze the identity/deployment boundary.

P1 does not change:

- historical R6.5.4.5 configs;
- historical experiment/result identifiers;
- the existing legacy `--environment` execution path;
- accepted R6.5.4.5 evidence;
- publication artifacts.

Runtime wiring of the new deployment contract is a later milestone. That migration must preserve compatibility with historical experiment directories while ensuring new canonical executions do not encode provider names in scientific identity.

## P2 runtime wiring

Portable generic experiments may now be created with `--deployment <definition.json>` instead of the legacy `--environment` selector. The resulting experiment ID uses the provider-independent scientific identity hash rather than an environment/provider slug.

The legacy `--environment` path remains supported without changing historical experiment IDs. P2 realizes the canonical local single-host deployment. Non-local providers fail closed until a real adapter exists.

The accepted R6.5.4.5 methodology is also projected into `benchmark/protocols/http3-paired-r6.5.4.5.json`, which contains measurement and analysis semantics but no deployment binding. Historical R6.5.4.5 configs remain unchanged provenance.
