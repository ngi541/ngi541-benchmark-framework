# M1/M2 A–B–C additive design draft

**State: design contract only. NOT an executable high-speed experiment.**

Research question: How much of the high-speed QUIC/HTTP/3 efficiency gap is attributable to cryptographic execution, and under which workload and hardware conditions can an optimized crypto engine meaningfully reduce that gap?

The A/B/C labels are not a new version of the frozen R6.5.4.5 paired campaign. A: HTTP/2 + OpenSSL; B: HTTP/3 + OpenSSL; C: HTTP/3 + server-only NGI541. Client crypto is unchanged in B/C. All use server-to-client GET direction. A and B/C differ in transport, TLS framing, and supported offloads. A↔B is a system comparison; B↔C is the causal server crypto intervention.

## Source-derived gaps (HEAD: 2230bf24091f31a022806f22a84a626154783e8e)

- `scripts/build.sh` has `--with-http_v3_module` but no `--with-http_v2_module`; both Linux NGINX binaries require HTTP/2 and HTTP/3 capabilities pinned and verified. Do not change historical build binaries in place.
- `framework.transport_security.nginx_config` has only `listen ... quic` and `http3 on`; new A-only renderer in `abc_transport.py` generates TLSv1.3/TCP/HTTP2.
- `framework.workload_planner._build_h2load_command` unconditionally sets `--h3`; new builder selects A via removal of that flag, leaving B/C identical.
- `_parse_scientific_h2load_result` depends on patched main-phase DATA counter. **The patch's current code touches both generic `h2load.cc` and `h2load_http3_session.cc`; validate h2 phase-byte accounting dynamically before claiming comparability.**
- `framework.paired_execution` is protocol-locked to `r6.5.4.5`, HTTP3-specific UDP readiness, and Darwin telemetry. Do not add A to it or change frozen outputs.
- `framework.results` is fixed to 12 × 4 × 2 historical runs; requires a new analysis/publication pipeline rather than changing legacy constants.
- Mac `*.dylib` hashes from historic config are **not** CloudLab Linux `*.so` binary manifests.

## What this patch implements

- `abc_design.py`: exact 9-condition draft, balanced 108-run schedule, provider-independent semantic hash, fail-closed invariants.
- `abc_transport.py`: isolated HTTP/2 NGINX config, h2/h3 `h2load` command selection, HTTP-version/TLS probe helpers.
- `abc_measurements.py`: phase-specific sample validation and explicit measured/unavailable provenance; zero is not unavailable.
- Additive schemas and draft design JSON; tests. No existing tracked files are changed.

## What this patch deliberately does NOT implement

- CloudLab experiment provision, Linux builds, Linux host-wide CPU, per-function crypto cycles, packet I/O/PMU collectors, actual h2load H2 accounting qualification, A/B/C runtime orchestration, statistical inference, or evidence publication.
- The draft's fixed stream levels 4/16/64 require loadgen feasibility checks. Four repetitions are a design baseline, **not** a statistical power calculation.
- `curl --http2` alone is not evidence of HTTP/2: verify negotiated `%{http_version}` exactly equals `2` and independent server/runtime cipher provenance. `curl --http3-only` likewise requires `3`.
- `abc_measurements` validates the envelope but cannot establish truthful physical collection. Run time alignment, exact object SHA, packet capture/ALPN proof, and full host CPU semantics are required before claim validity.

## Next implementation batches

**M1-runtime:** independent Linux build with both NGINX modules, pinned checksums, exactly one server side crypto change B↔C; verify h2/h3 and patched h2load DATA accounting, kernel offloads, same corpus identity, resource feasibility and protocol selection. Implement new Linux runner; use B/C adjacent scheduling from design draft.

**M2-collectors:** Linux host-wide CPU seconds at a consistent accounting boundary (avoid double counting process+host), separate minimal-instrumentation performance runs and crypto/packet attribution runs; emit missing counters as `unavailable + reason`. Pin PMU event definitions and runtime/driver versions.

**M2-validity/inference:** fail-closed loadgen CPU per-core gate, zero HTTP failures, exact object hash, TLS cipher + negotiated protocol, no throttling, measured time-window alignment and NIC drops policy; compute within-condition paired B/C estimates and unpaired protocol A/B/C comparisons with uncertainty.

**Frozen protocol:** `benchmark/protocols/http3-paired-r6.5.4.5.json` and historical files are unmodified. R6.5.4.5 SHA-256 stays `99805dd378310ec539246e655d3f2a690036e4e50ac83c27c52765d1a50fb387`.
