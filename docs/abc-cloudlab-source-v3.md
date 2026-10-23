# CloudLab source-build contract v3

- `nodes.server/client`: management SSH destinations, identities delivered only via `--ssh-key`.
- `inputs.server_build`: version pin file consumed by repository `abc-linux-build.sh` after pinned NGI541 library installation.
- `inputs.client_build`: existing source SHA + patch definition, no hard-coded pi/CloudLab target reused.
- `inputs.corpus`: pinned scientific corpus definition, validated here, **not** yet exercised by this functional smoke.
- `connection_smoke`: true runs ping + bidirectional iperf3; false omits iperf3 but retains SSH, inventory, route and ping gates.

SSH-host allocation is the only routine edit. Network routes/IP/NIC/port/prefix computed by the runner. Frozen historical R6.5.4.5 files are not modified.

Security: only HTTPS/Git source checkout, SHA gates and explicit Git commit; sudo only for Ubuntu build dependencies; no private keys, certificates private keys or release-upgrade commands stored in JSON.

Scientific qualification: v3 PASS means A/B/C connectivity, verified TLS, cipher and 32KiB payload integrity. It is **not** the R6.5.4.5 local paired protocol, not a high-speed benchmark and not publication-grade evidence.
