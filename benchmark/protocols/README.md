# Scientific protocols

`benchmark/protocols/` contains frozen, provider-independent scientific methodology definitions.

A protocol defines the semantics required to decide whether two executions represent the same scientific experiment. It describes **what is measured**, not where the experiment happens.

## Protocol boundary

A scientific protocol may define:

- variants;
- workload semantics;
- comparison mode;
- condition ordering;
- repetitions;
- measurement windows;
- validity requirements;
- primary and secondary metrics;
- pairing rules;
- retry policy;
- outlier policy.

It must not encode:

- CloudLab allocation IDs;
- provider-specific host names;
- SSH targets;
- machine serial numbers;
- local filesystem paths;
- concrete hardware inventory.

Those belong to deployment and execution provenance.

## Current canonical protocol

```text
http3-paired-r6.5.4.5.json
```

SHA-256:

```text
99805dd378310ec539246e655d3f2a690036e4e50ac83c27c52765d1a50fb387
```

Verify it with:

```bash
shasum -a 256 \
  benchmark/protocols/http3-paired-r6.5.4.5.json
```

## Immutability

An accepted protocol is not edited in place after it has been used to identify a scientific result.

A semantic methodology change requires a new protocol revision.

Deployment portability alone does not require a new scientific protocol when the methodology and claim semantics remain unchanged.
