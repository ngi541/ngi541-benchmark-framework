#!/usr/bin/env bash
# Functional Linux collector smoke only. Must be executed in Linux; no benchmark conclusions.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$(uname -s)" == "Linux" ]] || { echo 'ERROR: Linux required'; exit 1; }
OUT="${M2_SMOKE_OUT:-$(mktemp -d)}"
[[ -d "$OUT" ]] || { echo "ERROR: output directory missing: $OUT"; exit 1; }
CPU="$(python3 -c 'import os;print(min(os.sched_getaffinity(0)))')"
IFACE="${M2_SMOKE_IFACE:-lo}"
RUN="m2-functional-probe"
ID="smoke-$(date +%s)-$$"
cd "$ROOT"
export PYTHONPATH="$ROOT/benchmark${PYTHONPATH:+:$PYTHONPATH}"
python3 -m framework.abc_m2_cli registry
python3 -m framework.abc_m2_cli capture --run-id "$RUN" --attempt-id "$ID" \
 --window-id functional-only --host-role dut --phase start --cpus "$CPU" \
 --iface "$IFACE" --out "$OUT/start.json"
sleep 2
python3 -m framework.abc_m2_cli capture --run-id "$RUN" --attempt-id "$ID" \
 --window-id functional-only --host-role dut --phase end --cpus "$CPU" \
 --iface "$IFACE" --out "$OUT/end.json"
python3 -m framework.abc_m2_cli derive --start "$OUT/start.json" \
 --end "$OUT/end.json" --arm B --out "$OUT/delta.json"
python3 -m framework.abc_m2_cli validate --observation "$OUT/delta.json"
python3 - "$OUT/delta.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x['qualification_status']=='evidence-only-not-qualified'
assert x['metrics']['dut_host_cpu_seconds_per_gib']['state']=='unavailable'
assert x['metrics']['tcp_retransmits']['state']=='not_applicable'
print('PASS: M2.0 + M2.1 Linux collector functional smoke (no performance qualification)')
PY
printf 'EVIDENCE: %s\n' "$OUT"
