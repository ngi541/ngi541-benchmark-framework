# NGI541 CloudLab — Consolidated B2 Source-Only Bootstrap Contract

Date: 2026-10-23. Source basis: user-provided 191-file audit snapshot with HEAD
`e03e7f5d690af6aa4e9d401d070232f048095b8e` and untracked B2.

## Objective and boundaries

Generate deterministic node-specific **source-build** archives on the
orchestrator. Do **not** build NGINX or curl on the orchestrator; do **not**
clone the benchmark framework on either DUT. The server bootstrap clones only
the pinned NGI541 implementation, then uses the bundled `abc-linux-build.sh`
plus pinned versions and NGINX patch. The client bootstrap uses a separate
native HTTP2+HTTP3 recipe and the bundled pinned nghttp2 patch.

B2 is **offline packaging only**: it never transfers files over SSH, installs
packages, executes source builds or measures performance. B3 will authenticate
the archive SHA from `bootstrap-index.json` **before extraction** and implement
preflight of source-build dependencies, verified binaries, logs, and A/B/C
functional qualification. This is independent of 10GbE/100GbE topology.

## Current node profiles

`benchmark/configs/abc-cloudlab-bootstrap-nodes.json` declares `node_id`,
`communication_role`, and `stack_profile`. No NIC names, addresses, CPU counts
or link-speed constraints are part of this build descriptor. Multiple nodes
with the same communication role are supported by the packager. New stack
profiles can be registered in the B2 renderer independently of the generic B1
packager.

## Identity and verification

- `build.lock.json` lists SHA-256 for **every** actual bundled input except
  the lock itself. It includes the bootstrap, pinned definitions, patches,
  build script and standalone verifier.
- `bundle.manifest.json` binds all files including the lock to node/profile.
- `bootstrap-index.json` binds each node to its archive SHA-256 and manifest
  digest. B3 must authenticate this expected digest on the remote node prior
  to **any** extraction or execution. The in-bundle verifier is supplementary.
- `recipe_identity` comes from pinned inputs, bootstrap template, render
  generator source and profile contract, **not** the user-supplied revision.
- `framework_commit`, SHA-256 of generator source, and Git tracked/clean flags
  are recorded independently. Publication eligibility is false for untracked
  or modified inputs; a local proof of packaging is not a scientific release.
- Binary build receipts, ELF linkage and compiler/environment identities are
  measured on the DUT and are **not claimed** by B2.
- Packaging occurs in a private staging directory. Archives are validated
  before a final directory rename. Existing output paths are never
  intentionally overwritten. Single-writer invocation is the supported mode.

## Regression preservation

Historical `render_build_script(definition)` defaults to the legacy profile.
The R6.5.4.2 script generated from the pinned definition retains SHA-256:

`63b419bc234841037357b5ca7c68182676e50b3a2e9b6d7f4945447ae3fb9475`

New `profile='cloudlab-http2-http3'` builds nghttp2/h2load **before** curl,
configures curl with `--with-nghttp2`, `--with-nghttp3`, and `--with-ngtcp2`,
and enforces HTTP2+HTTP3 and nghttp2 linkage. Historical R6.5.4.5
protocol/configuration and source patch files are not modified.

## Quick check

```bash
PYTHONPATH=benchmark python3 -m unittest \
  framework.tests.test_cloudlab_artifacts \
  framework.tests.test_cloudlab_bootstrap_b2 \
  framework.tests.test_loadgen_runtime -v

ROOT=$(mktemp -d /tmp/ngi541-b2-check.XXXXXX)
python3 scripts/abc-cloudlab-package-b2.py \
  --revision b2-local-check \
  --output "$ROOT/bundles"
python3 -m json.tool "$ROOT/bundles/bootstrap-index.json"
```

The parent directory exists; the child `bundles` does not, preventing
accidental reuse of a failed publication. Keep historical evidence; do not
`rm -rf` an output after failed generation without inspecting it first.

## Next boundary — B3

Retain the working Source V3 preflight and A/B/C functional gates. Replace
only its obsolete remote source-delivery/build segment; do not refactor M2
measurement at the same time. Implement independent per-DUT prerequisites,
remote expected-archive digest verification, safe extraction, native build,
CPU/memory job caps and ELF receipts. A/B/C functional PASS is required before
native Clemson r6615 100GbE scientific Mode I/Mode II work. VPP/VCL D/E are
a separate post-qualification branch.
