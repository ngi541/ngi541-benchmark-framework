# Scientific protocols

This directory contains provider-independent benchmark methodology definitions.

A protocol defines measurement and analysis semantics. It must not contain deployment providers, host names, allocation identifiers, SSH targets, or hardware inventory.

Historical R6.5.x configs under `benchmark/configs/` remain immutable provenance. New executions bind a scientific protocol to a deployment separately.

`http3-paired-r6.5.4.5.json` is the canonical provider-independent projection of the accepted R6.5.4.5 paired HTTP/3 methodology.
