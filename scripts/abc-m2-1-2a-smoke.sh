#!/usr/bin/env bash
# Functional-only smoke: Docker container is never qualified as bare metal.
set -euo pipefail
: "${M2_ENV_OUT:?Set output directory using -v and M2_ENV_OUT}"
[[ -d "$M2_ENV_OUT" ]] || { echo 'FAIL: output dir missing' >&2; exit 2; }
export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}$PWD/benchmark"
ASSETS="$M2_ENV_OUT/assets.json"
# No fabricated corpus or configuration hashes in functional-only smoke.
python3 - "$ASSETS" <<'PY'
import json,sys
with open(sys.argv[1],'x') as f:
    json.dump({'profile_id':'functional-smoke-not-scientific','cache_policy':'unverified',
               'object_identifiers':['synthetic-placeholder']},f)
PY
for role in dut client; do
  python3 -m framework.abc_m2_environment_cli capture \
    --arm B --role "$role" --interface lo --run-id smoke-functional \
    --attempt-id smoke-1 --assets "$ASSETS" \
    --out "$M2_ENV_OUT/$role.json"
  python3 -m framework.abc_m2_environment_cli assess \
    --evidence "$M2_ENV_OUT/$role.json" --out "$M2_ENV_OUT/$role-assessment.json"
done
python3 -m framework.abc_m2_environment_cli compare \
  --before "$M2_ENV_OUT/dut.json" --after "$M2_ENV_OUT/dut.json" \
  --mode same-role --out "$M2_ENV_OUT/drift.json"
python3 - "$M2_ENV_OUT" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
for role in ('dut','client'):
 a=json.loads((p/f'{role}-assessment.json').read_text())
 assert a['bare_metal_qualified'] is False
 assert a['status']=='incomplete-not-qualified'
 obj=json.loads((p/f'{role}.json').read_text())
 assert len(obj['categories'])==11
 assert obj['context']['environment_class'] in ('container','unverified')
assert json.loads((p/'drift.json').read_text())['qualified_primary_result'] is False
print('PASS: M2.1.2a 11-category Linux evidence + fail-closed qualification')
print('NOTE: Docker inventory != bare-metal CloudLab hardware identity')
PY
