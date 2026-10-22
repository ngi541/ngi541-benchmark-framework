# NGI541 A/B/C M1 Linux runtime — Stage 2 (additive)

Design draft `abc-high-speed-design-draft.json` is **not** an executable scientific protocol. Stage 2 adds reproducible Linux build recipes and a conservative functional smoke harness, not a CloudLab benchmark runner. The R6.5.4.5 files and historical results remain untouched.

## Build parity

- A and B use the **same stock NGINX binary**, configured for TLS1.3 with HTTP/2 and HTTP/3 modules.
- C uses **the same pinned NGINX 1.31.6 and OpenSSL 3.5.9 sources** with the pinned NGI541 integration patch, built independently.
- Only C is compiled with `NGX_QUIC_NGI541=1`, and only C links `libngi541_engine.so`.
- A is HTTP/2/TCP/OpenSSL record encryption; B is HTTP/3/QUIC/OpenSSL QUIC packet protection; C is HTTP/3/QUIC/NGI541 packet/header protection. This does NOT imply equivalent transport I/O cost between A and B.
- NGINX builds use pinned and checksum-verified upstream source tarballs; the NGI541 0.1.1 library must be separately installed from the pinned revision. The build recipe records its library SHA but cannot establish its git provenance; record NGI541 build manifest separately.

## No hardware needed: inspect build recipe on Mac

```bash
cd ~/Projects/NGI541/ngi541-benchmark-framework
bash scripts/abc-linux-build.sh --plan
python3 -m unittest discover -s benchmark/framework/tests -p 'test_*.py'
```

## Later, on qualified Linux DUT (not Mac)

Install prerequisites (OS/package-manager specific): C compiler, make, Perl, patch, curl, tar, sha256sum, zlib, PCRE2 development headers and libraries, appropriate platform libraries. Install NGI541 0.1.1 from pinned commit `f783e4cf99aa20d68b64cc893a60c257c02898e6` in an absolute prefix, including `libngi541_engine.so` and public headers. Then run:

```bash
export NGI541_PREFIX=/absolute/path/to/pinned/ngi541/install
export PCRE2_PREFIX=/usr
export ABC_BUILD_JOBS=4
bash scripts/abc-linux-build.sh --build
```

Check `work/abc-linux/{stock,ngi541-direct}/build-receipt.json` and `build/abc-linux/{stock,ngi541-direct}/sbin/nginx`. This recipe intentionally fails if previous output directories exist; never delete historic experiment data to force a build. The recipe has **not yet been validated against a real Linux target**.

## Functional verification (on Linux loadgen with a live NGINX server)

Before measurement: establish correct TLS 1.3 certificate chain and DNS/SNI, make scientific objects available in both servers' root directories, and ensure identical response bytes, cipher policy, and NGINX configuration except for protocol/crypto. **No `--insecure` or `-k`.** In separate fresh output directories for each arm, run:

```bash
PYTHONPATH=benchmark python3 -m framework.abc_smoke \
  --arm A \
  --curl-binary /absolute/pinned/curl \
  --server-name ngi541-dut.local \
  --address <DUT-EXPERIMENT-IP> --port 4433 \
  --ca-file /path/to/CA.pem \
  --object-path clas12-event.bin \
  --expected-file /path/to/expected/clas12-event.bin \
  --output-dir /tmp/abc-smoke-A-001
```

Run analogous calls for B and C. The new smoke tool checks protocol version (h2 fallback to HTTP/1.1 is **rejected**), HTTP 200, peer verification, exact byte count, SHA-256 identity, and client linkage absence of NGI541. It records negotiated TLS cipher only if unambiguously visible in curl's verbose output. If unavailable, it is **not assumed verified**; a separate handshake proof is still required before performance qualification. The tool does not launch NGINX or `h2load`, nor does it claim production performance.

## Remaining blocking milestones

1. Qualified pinned Linux NGI541 library build and source/build receipt.
2. Server configuration renderer for real on-disk certificates and scientific corpus; matching A/B/C process lifecycle; NGINX startup and teardown.
3. Real client build, verified HTTP/2 and HTTP/3 capability, pinned client identical for B/C; actual negotiated cipher proof.
4. Linux CPU host/process accounting, crypto counters, packet I/O, attribution/perf collectors, and observability gates.
5. CloudLab two-node qualification, hardware selection, and only then frozen high-speed execution protocol.
