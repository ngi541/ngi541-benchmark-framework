#!/usr/bin/env bash
# One-host, two-role clock/byte evidence smoke; NOT cross-host or qualified performance.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$(uname -s)" == Linux ]] || { echo 'FAIL: Linux runtime required'; exit 1; }
OUT="${M2_BRIDGE_OUT:?provide new writable output directory}"
[[ -d "$OUT" ]] || { echo 'FAIL: output directory does not exist'; exit 1; }
export PYTHONPATH="$ROOT/benchmark${PYTHONPATH:+:$PYTHONPATH}"
ID="m2-bridge-smoke-$(date +%s)-$$"
RUN='functional-not-performance'
CLI=(python3 -m framework.abc_m2_bridge_cli)
CPU="$(python3 -c 'import os;print(min(os.sched_getaffinity(0)))')"
for role in dut client; do
  python3 -m framework.abc_m2_cli capture --run-id "$RUN" --attempt-id "$ID" \
    --window-id demo-main --host-role "$role" --phase start \
    --cpus "$CPU" --iface lo --out "$OUT/counter-start-$role.json"
done
for role in dut client; do
  "${CLI[@]}" local-probe --run-id "$RUN" --attempt-id "$ID" --window-id demo-main \
    --host-role "$role" --edge start --out "$OUT/start-$role.json"
done
sleep 0.1
for role in dut client; do
  "${CLI[@]}" local-probe --run-id "$RUN" --attempt-id "$ID" --window-id demo-main \
    --host-role "$role" --edge end --out "$OUT/end-$role.json"
done
for role in dut client; do
  python3 -m framework.abc_m2_cli capture --run-id "$RUN" --attempt-id "$ID" \
    --window-id demo-main --host-role "$role" --phase end \
    --cpus "$CPU" --iface lo --out "$OUT/counter-end-$role.json"
  python3 -m framework.abc_m2_cli derive --start "$OUT/counter-start-$role.json" \
    --end "$OUT/counter-end-$role.json" --arm B --out "$OUT/counter-delta-$role.json"
  python3 - "$OUT/start-$role.json" "$OUT/end-$role.json" \
   "$OUT/start-marker-$role.json" "$OUT/end-marker-$role.json" <<'PYMARK'
import json,sys
from pathlib import Path
start,end=(json.loads(Path(p).read_text()) for p in sys.argv[1:3])
for receipt,out in zip((start,end),sys.argv[3:]):
    Path(out).write_text(json.dumps(receipt['host_marker'],sort_keys=True,indent=2)+'\n')
PYMARK
  "${CLI[@]}" enclosure --start-snapshot "$OUT/counter-start-$role.json" \
    --end-snapshot "$OUT/counter-end-$role.json" \
    --start-marker "$OUT/start-marker-$role.json" \
    --end-marker "$OUT/end-marker-$role.json" \
    --out "$OUT/enclosure-$role.json"
done
"${CLI[@]}" assess --start-dut "$OUT/start-dut.json" \
  --start-client "$OUT/start-client.json" --end-dut "$OUT/end-dut.json" \
  --end-client "$OUT/end-client.json" --max-boundary-ms 500 --out "$OUT/coordination.json"
python3 - "$OUT/sample-h2load.json" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);p.open('x').write(json.dumps({'measurements':{'requests':{
    'started':1,'done':1,'succeeded':1,'failed':0,'errored':0,'timeout':0},
    'status_codes':{'2xx':1,'3xx':0,'4xx':0,'5xx':0},
    'traffic':{'data':32768,'total':32900}}},sort_keys=True)+'\n')
PY
"${CLI[@]}" h2load --raw-json "$OUT/sample-h2load.json" --arm B \
  --run-id "$RUN" --attempt-id "$ID" --window-id demo-main \
  --declared-main-seconds 2 --out "$OUT/payload.json"
python3 - "$OUT/coordination.json" "$OUT/payload.json" <<'PY'
import json,sys
coord,payload=(json.load(open(s)) for s in sys.argv[1:])
assert coord['quality']=='functional-local-only'
assert coord['qualified_primary_result'] is False
assert coord['loadgen_main_phase_bound'] is False
assert payload['main_phase_data_bytes_reported']==32768
assert payload['valid_application_payload_bytes']['state']=='unavailable'
assert payload['qualified_primary_result'] is False
print('PASS: M2.1.1 Linux clock/byte evidence functional smoke; NOT two-host synchronization')
PY
printf 'EVIDENCE: %s\n' "$OUT"
