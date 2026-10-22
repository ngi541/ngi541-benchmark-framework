# NGI541 M2.1.2a — Environment Identity & Reproducibility Gate

**Revision:** `ngi541-abc-m2.1.2a-environment-r1` · 2026-10-22
**Scope:** additive research draft; does not replace M2 v0.2 or frozen R6.5.4.5.
**Implemented:** read-only Linux environment inventory, provenance, 11 DoD groups, same-host drift, B/C exact exception approval, incomplete/unverified reporting.
**Not implemented:** physical-host attestation, in-window stability/thermal/frequency sampling, independent crypto ISA execution-path proof, cross-host clock synchronization, M2.1.2b validated payload, fully qualified P/C/K results.

## 1. Scientific boundaries

- A: stock NGINX HTTP/2; B: stock NGINX HTTP/3; C: NGI541-integrated NGINX HTTP/3. B/C is an intervention at the **server's QUIC cryptographic execution path**, not an all-purpose cross-protocol decomposition.
- **M2 v0.2 metric registry retains all 26 performance/attribution metrics and their four states.** This package adds an **environment identity schema**; none of those metrics are replaced or silently zero-filled.
- Environment snapshots are **evidence**, not completed primary experimental runs. They are explicitly `qualified_primary_result=false` on every path, including if the reported identity fields are complete.
- Docker and VM inventory cannot certify NIC firmware, physical PCIe path, host-level IRQ placement, CPU topology/NUMA or stability under hardware load. Linux container can see host kernel while sysfs/netns and process/cgroup contexts differ.
- Operator-supplied asset control values are recorded with provenance `operator-declared` and **do not automatically prove** the runtime state. Environment completeness reports these in `unverified_declarations`.
- A field with `state=measured` can legitimately have `false`, `0`, or `[]`; unknown values are `unavailable` with `value=null` and a reason. An unsupported query is **not** evidence of a disabled feature.
- Some sysfs/ethtool/PMU fields are driver-/hardware-specific. Command failures are captured with their source, and do not silently turn into zeros.

## 2. Coverage of original 11-item DoD

| Group | Collected here | Still requires physical CloudLab qualification |
|---|---|---|
| CPU | `/proc/cpuinfo`: vendor, family, model, stepping, microcode consistency, AES/VAES/AVX flags | Mixed CPUs, actual ISA **dispatch** via M2.2 tracing/disassembly; flags are capability, not execution |
| CPU topology | `lscpu`, effective cpuset/affinity, online CPUs, NUMA node count | Physical socket/core/SMT/NUMA vs hypervisor exposure, IRQ NUMA locality |
| CPU execution | cpufreq policies, governor, Turbo/boost, affinity | Main-window frequency/thermal/throttling traces; BIOS controls; worker/IRQ separation |
| Memory | `/proc/meminfo`, NUMA nodes, `numactl --show` as diagnostic | **DUT** NUMA placement and page cache policy; collector's process NUMA ≠ NGINX process NUMA |
| NIC | PCI vendor/device/sysfs, `lspci`, driver/firmware/speed from ethtool, PCIe link | Dedicated CloudLab experiment NIC not management NIC; full firmware/PHY/link verification |
| Packet I/O | MTU, `ethtool -k/-l/-x`, per-NIC MSI-X IRQ effective affinity, socket sysctls, declared `quic_gso` | Interpret offload availability vs enabled state; RSS/IRQ queue isolation; verify NGINX GSO config |
| OS | kernel, distro, boot ID, sysctls, interrupts hash, BIOS string when readable, virtualization | Kernel boot args/image/mitigations, IRQ balancing and deployment provenance |
| NGINX | SHA-256 of binary/config/patch; revision, build flags, and exact NGI541 ELF dependency from `ldd` | Audit B/C patch-only difference, worker affinity/config/cipher and ALPN at runtime |
| Crypto | Source archive hash, OpenSSL linkage mode, optional shared-lib hash, NGI541 `.so` SHA and revisions | Execution dispatch/actual 1-RTT calls and fallbacks are M2.2; static NGINX/OpenSSL need source+binary provenance |
| Client | Binary SHA-256, `--version`, dynamic engine link check, declared provider/protocol capabilities | Actual `h2`/`h3`/TLS peer verification in functional tests; same binary+settings B/C |
| Workload | SHA-256 of corpus and deterministic schedule manifests; declared object IDs/profile/cache | Validated completions in M2.1.2b and actual cache-state control |

**Important:** ethtool offload states describe driver-advertised capabilities/configuration, not guaranteed physical wire packet boundaries. `scaling_cur_freq` is a sample, not a frequency stability test. IRQ association is limited to `/sys/class/net/IF/device/msi_irqs` and is unavailable if the kernel/driver does not expose reliable mapping.

### OpenSSL static linking

NGINX may compile the pinned OpenSSL source into its own executable instead of depending on `libssl.so`. In that case, there may be **no independent runtime OpenSSL `.so`** to hash. The inventory marks the shared-library hash `not_applicable` when `nginx -V` plus `ldd` indicate static/embedded linkage. Record the **exact OpenSSL source archive SHA-256, NGINX binary hash, NGINX configure flags, and build receipt** instead. This is still **not evidence of actual per-operation crypto implementation selection**.

### A/B vs C

For stock A/B, NGINX patch and NGI541 library/revision are explicitly `not_applicable`. For C, their exact file hashes/revisions must be available. `nginx.configure_flags` can differ between B and C because of the defined NGI541 compile/link flags; the comparison cannot automatically ignore all flags.

## 3. CLI and operator asset manifest

Package includes `benchmark/protocols/abc-m2-environment-assets-example.json`. **Copy it and fill actual absolute Linux paths** (never provide bare placeholder names), plus profile, object IDs, runtime config and control values. For physical CloudLab nodes, use the actual local binaries, source tarballs and runtime config. `openssl_source_archive` should reference the pinned OpenSSL source tarball or other exact source artifact; `client_binary` should identify the actual `h2load` executable.

Do not paste private signing keys, SSH credentials, hostname secrets or certificate private keys into asset JSON. Paths to such files must not be supplied; hash only nonsecret NGINX config/approved binary/source/corpus artifacts. Review environment raw evidence (MAC addresses, hostnames, PCI identifiers) before public release.

```bash
cd ~/Projects/NGI541/ngi541-benchmark-framework
export PYTHONPATH=benchmark

# On each Linux host, with that host's actual experiment interface:
python3 -m framework.abc_m2_environment_cli capture \
  --role dut --arm B --interface <experiment-interface> \
  --run-id pilot-001 --attempt-id pilot-001-attempt-01 \
  --assets /absolute/path/dut-b-assets.json \
  --out /new/evidence/dut-b-environment.json

python3 -m framework.abc_m2_environment_cli assess \
  --evidence /new/evidence/dut-b-environment.json \
  --out /new/evidence/dut-b-assessment.json
```

For client, use `--role client --arm B`; for candidate, `--role dut --arm C`. Preserve each output append-only and hash via CLI output SHA-256.

### Drift

Compare same arm and role before/after a run or a batch:

```bash
python3 -m framework.abc_m2_environment_cli compare \
  --before /evidence/dut-b-before.json \
  --after /evidence/dut-b-after.json \
  --mode same-role --out /evidence/dut-b-drift.json
```

B/C paired comparison is **ordered B→C** on the same physical DUT/boot, and independently B→C on the same client:

```bash
python3 -m framework.abc_m2_environment_cli compare \
  --before /evidence/dut-b.json --after /evidence/dut-c.json \
  --mode bc-pair --approved-differences /evidence/reviewed-bc-differences.json \
  --out /evidence/dut-bc-comparison.json
```

`reviewed-bc-differences.json` must contain **explicit exact values** for only predeclared variant fields (`nginx.binary_sha256`, `nginx.patch_sha256`, `nginx.configure_flags`, `nginx.source_revision`, `nginx.ngi541_dynamic_dependency`, `crypto.ngi541_binary_sha256`, `crypto.ngi541_revision`, `crypto.dispatch_isa_path`). For a measured-to-measured difference:

```json
{
  "nginx.binary_sha256": {
    "before": "EXACT_SHA256_OF_B",
    "after": "EXACT_SHA256_OF_C"
  }
}
```

For an anticipated stock `not_applicable` → candidate `measured` field, use a precise state-bearing exception:

```json
{
  "crypto.ngi541_binary_sha256": {
    "before": {"state": "not_applicable", "value": null},
    "after": {"state": "measured", "value": "EXACT_SHA256_OF_C_ENGINE"}
  }
}
```

These are **illustrative schemas**, not evidence. Do **not** approve actual mismatches by copying unreviewed values automatically; every exception must be justified by the known crypto-only patch delta. Mismatched CPU/corpus/NIC/kernel/MTU/governor is **never** auto-exempted. A reboot changes the boot identity and requires a new block/baseline.

Drift results:

- `fail`: unexpected measured identity/configuration difference or a changed boot ID.
- `unqualified`: required comparison fields are unavailable/unverified; it is **not a PASS**.
- `identity-match-only`: compared *available* controlled fields match, but physical-science qualification is **still false**; dynamic run gates and asset reviews remain necessary.

A comparison across DUT and client is invalid; compare the same host role. Current schema is evidence-only; the complete freeze/attestation gate requires CloudLab data.

## 4. Release and science gates

- M2.1.2a unit tests including missing data, exact hash, role, stock-vs-candidate, schema states, drift, boot ID and append-only writes.
- Functional smoke on Linux, with source repository read-only, separate evidence volume.
- Before CloudLab science: obtain complete inventory on **both physical nodes**, validate outside-container host and physical experiment network, verify CPU/NIC and frequency/NUMA policies, audit B/C expected differences, and repeat before/after run for drift.
- M2.1.2b will link real h2load MAIN phase and independently validated application bytes before allowing CPU/GiB/goodput qualification.
- M2.2 will separately verify AES-GCM/CTR prepared-key invocation, OpenSSL fallback and actual hardware ISA path; simply showing VAES flags or linking libngi541 is insufficient.
- P/C/K collection remain separate, with measurement perturbation calibrated in M2.4. Frozen R6.5.4.5 SHA-256 stays `99805dd378310ec539246e655d3f2a690036e4e50ac83c27c52765d1a50fb387`.

Linux reference: https://docs.kernel.org/admin-guide/pm/cpufreq.html , https://man7.org/linux/man-pages/man8/ethtool.8.html .
