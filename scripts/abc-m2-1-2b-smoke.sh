#!/usr/bin/env bash
# Deterministic schema/offline evidence smoke, not a genuine h2load MAIN execution.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${M2_MAIN_OUT:?M2_MAIN_OUT must point to new writable evidence directory}"
[[ -d "$OUT" && "$(uname -s)" == Linux ]] || { echo 'FAIL: Linux/output directory required'; exit 1; }
export PYTHONPATH="$ROOT/benchmark${PYTHONPATH:+:$PYTHONPATH}"
python3 - "$OUT" <<'PY'
from pathlib import Path
import hashlib,json,sys
from framework.abc_m2_payload import extract_h2load_evidence
from framework.abc_m2_main_validity import REVISION
p=Path(sys.argv[1]);d=p/'responses';d.mkdir(exist_ok=False)
contents=b'M2.1.2b deliberately synthetic offline stream fixture'*100
file=d/'s1.bin';file.write_bytes(contents)
hash_=hashlib.sha256(contents).hexdigest();client=hashlib.sha256(b'NOT AN H2LOAD EXECUTABLE').hexdigest()
corpus={'kind':'abc-m2-corpus-manifest-v1','objects':[{'object_id':'obj1','size_bytes':len(contents),'sha256':hash_}]}
corpus_raw=(json.dumps(corpus,sort_keys=True)+'\n').encode();(p/'corpus.json').write_bytes(corpus_raw)
ids={'run_id':'synthetic-test','attempt_id':'synthetic-attempt','window_id':'synthetic-main'}
phase={'revision':REVISION,'kind':'main-phase-boundary-evidence',**ids,'arm':'B','source':'external-wrapper',
  'client_sha256':client,'boot_id':'synthetic-boot','warmup_traffic_included':False,
  'main_start_monotonic_ns':1000000,'main_end_monotonic_ns':2001000000}
ledger={'revision':REVISION,'kind':'stream-completion-ledger',**ids,'arm':'B','client_sha256':client,
 'boot_id':'synthetic-boot','streams':[{'stream_id':'s1','object_id':'obj1','status_code':200,
 'complete':True,'integrity_checked':True,'http_version':'3','started_monotonic_ns':1000100,
 'completed_monotonic_ns':2000900000,'response_file':'s1.bin','received_bytes':len(contents),'sha256':hash_}]}
raw=json.dumps({'measurements':{'requests':{'started':1,'done':1,'succeeded':1,'failed':0,'errored':0,'timeout':0},
    'status_codes':{'2xx':1,'3xx':0,'4xx':0,'5xx':0},'traffic':{'data':len(contents),'total':len(contents)+40}}}).encode()
h2load=extract_h2load_evidence(source=raw,arm='B',**ids,
    expected_client_sha256=client,actual_client_sha256=client)
for key,v in [('phase',phase),('ledger',ledger),('h2load',h2load)]:
    (p/(key+'.json')).write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
(p/'corpus.sha256').write_text(hashlib.sha256(corpus_raw).hexdigest()+'\n')
print('PASS: synthetic fixture generated (NOT from h2load)')
PY
CORPUS_SHA="$(cat "$OUT/corpus.sha256")"
python3 -m framework.abc_m2_main_cli \
 --corpus-manifest "$OUT/corpus.json" --expected-corpus-sha256 "$CORPUS_SHA" \
 --phase "$OUT/phase.json" --completion-ledger "$OUT/ledger.json" \
 --h2load-evidence "$OUT/h2load.json" --response-dir "$OUT/responses" \
 --out "$OUT/reconciliation.json"
python3 - "$OUT/reconciliation.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert r['integrity_verified_file_count']==1
assert r['qualified_primary_result'] is False
assert r['client_phase_origin_attested'] is False
assert r['ledger_to_h2load_execution_attested'] is False
assert r['valid_application_payload_bytes']['state']=='unavailable'
assert r['application_goodput_mbps']['state']=='unavailable'
print('PASS: M2.1.2b offline integrity/aggregation gate; NOT a real MAIN or primary result')
PY
printf 'EVIDENCE: %s\n' "$OUT"
