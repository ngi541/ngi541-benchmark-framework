# Local environment adapter

The local environment adapter is implemented by:

```text
benchmark/framework/environment.py
```

It maps one physical host to the R5 `T0` topology:

```text
host:
  roles:
    - load-generator
    - dut
```

This environment is useful for:

- framework development;
- functional validation;
- exploratory performance work;
- low-cost reproduction.

It is not equivalent to a dedicated client/server benchmark topology.

For publication-grade end-to-end performance characterization, prefer dedicated nodes where load generation and the DUT do not share CPU resources.

## Portable descriptor

`single-host.json` is the canonical local deployment descriptor. It assigns both `dut` and `loadgen` to the same local node for development and preliminary evaluation.
