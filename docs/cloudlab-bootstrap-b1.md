# CloudLab bootstrap B1 — packaging foundation

This change is **additive only**. `benchmark/framework/cloudlab_artifacts.py` provides the package creation API and CLI. It is not yet connected to the `abc-cloudlab-run.py` execution flow.

Run unit tests from the repository root:

```bash
PYTHONPATH=benchmark python3 -m unittest framework.tests.test_cloudlab_artifacts -v
python3 -m py_compile benchmark/framework/cloudlab_artifacts.py
```

The packager requires a plan JSON with `schema_version: 1`, `revision`, and a `nodes` array. Each node has `node_id`, `communication_role`, `stack_profile`, and a `files` dictionary mapping archive-relative names to **plan-directory-relative** source paths. Each node must map `bootstrap.sh` and `build.lock.json`. The lock JSON requires `schema_version: 1` and a matching `stack_profile`.

Example role-specific files: `bootstrap.sh`, `build.lock.json`, and `patches/nginx.patch` (server) or `patches/nghttp2.patch` (client). These are **inputs that must be generated in B2**; they are not provided by B1.

Example CLI:

```bash
PYTHONPATH=benchmark python3 -m framework.cloudlab_artifacts --plan /absolute/path/plan.json --output /absolute/path/empty-output-dir
```

B1 outputs `ngi541-cloudlab-<role>-bootstrap-<revision>.tar.gz` and `bootstrap-index.json`. The generated tarballs are deterministic for identical plan and input bytes. The index records SHA-256 and node metadata. The packager does not transfer or execute artifacts. Remote verification, safe extraction, source builds and runtime gates are B2/B3 tasks.

Terminology: both `node0` and `node1` are DUTs; `server` and `client` are communication roles, not node categories. Stack profiles are replaceable (e.g. `nginx-ngi541`, `http-loadgen`, `vpp-dpdk`).
