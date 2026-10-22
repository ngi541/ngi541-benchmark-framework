"""M2.1.2b fail-closed MAIN/stream evidence reconciliation, draft r1.

This module does NOT manufacture h2load in-process phase events or per-response
hashes. Inputs supplied by an operator or external tool remain UNATTESTED until
an audited, pinned client exporter and controller binding are provided.

All timestamps for phase and client-local snapshots are from the SAME Linux
host boot; cross-host monotonic values are deliberately never compared.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from framework.abc_m2_contract import fail_if
from framework.abc_m2_coordination import validate_receipt
from framework.abc_m2_payload import PAYLOAD_REVISION

REVISION = 'ngi541-abc-m2.1.2b-main-evidence-r1'
SHA = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[A-Za-z0-9_.:-]{1,128}\Z')


def _id(v: Any, name: str) -> None:
    fail_if(not isinstance(v, str) or ID.fullmatch(v) is None, f'invalid {name}')


def _ns(v: Any, name: str) -> None:
    fail_if(type(v) is not int or v < 0, f'invalid monotonic timestamp {name}')


def _sha(v: Any, name: str) -> None:
    fail_if(not isinstance(v,str) or SHA.fullmatch(v) is None, f'invalid {name} SHA256')


def _assert_same_ids(*records: dict) -> None:
    for name in ('run_id','attempt_id','window_id'):
        if not all(isinstance(r,dict) for r in records):
            raise ValueError('M2.1.2b requires JSON objects')
        values = [r.get(name) for r in records]
        _id(values[0],name)
        fail_if(len(set(values)) != 1, f'M2.1.2b provenance mismatch: {name}')


def read_corpus(*, source: bytes, expected_sha256: str) -> dict[str, dict]:
    """Parse exact SHA-pinned corpus object manifest; no run-generated substitution."""
    _sha(expected_sha256,'expected corpus')
    fail_if(hashlib.sha256(source).hexdigest() != expected_sha256,
            'corpus manifest SHA256 mismatch')
    try:
        doc = json.loads(source)
    except ValueError as exc:
        raise ValueError('corpus manifest is not JSON') from exc
    fail_if(not isinstance(doc,dict) or doc.get('kind') != 'abc-m2-corpus-manifest-v1',
            'unknown corpus manifest type')
    objects = doc.get('objects')
    fail_if(not isinstance(objects,list) or not objects, 'empty corpus objects')
    result: dict[str,dict] = {}
    for x in objects:
        fail_if(not isinstance(x,dict), 'object record required')
        obj=x.get('object_id');_id(obj,'object_id')
        _sha(x.get('sha256'),'object')
        size=x.get('size_bytes')
        fail_if(type(size) is not int or size <= 0, 'invalid expected object size')
        fail_if(obj in result, 'duplicate corpus object_id')
        result[obj]={'sha256':x['sha256'],'size_bytes':size}
    return result


def validate_phase(phase: dict, *, run_id: str, attempt_id: str,
                   window_id: str, arm: str, client_sha256: str) -> dict:
    fail_if(not isinstance(phase,dict) or phase.get('revision') != REVISION or
            phase.get('kind') != 'main-phase-boundary-evidence', 'invalid MAIN phase evidence')
    _assert_same_ids(phase,dict(run_id=run_id,attempt_id=attempt_id,window_id=window_id))
    fail_if(phase.get('arm') != arm, 'MAIN arm mismatch')
    _sha(client_sha256,'expected client');_sha(phase.get('client_sha256'),'phase client')
    fail_if(phase['client_sha256'] != client_sha256, 'MAIN client binary identity mismatch')
    _id(phase.get('boot_id'),'phase boot_id')
    first,last=phase.get('main_start_monotonic_ns'),phase.get('main_end_monotonic_ns')
    _ns(first,'main-start');_ns(last,'main-end')
    fail_if(last <= first, 'MAIN phase duration invalid')
    fail_if(phase.get('warmup_traffic_included') is not False, 'MAIN includes warmup traffic')
    fail_if(phase.get('source') not in ('external-wrapper','h2load-in-process'),
            'unsupported MAIN boundary provenance')
    # Merely writing source=h2load-in-process in a JSON file is not authentication.
    return {'seconds':(last-first)/1e9, 'client_boot_id':phase['boot_id'],
            'source':phase['source'], 'origin_attested':False,
            'unattested_reason': 'client binary lacks independently verified main-phase event emitter and binding'}


def verify_stream_ledger(*, ledger: dict, response_dir: Path,
                         corpus: dict[str, dict], phase: dict,
                         h2load: dict) -> dict:
    _assert_same_ids(ledger,phase,h2load)
    fail_if(ledger.get('revision') != REVISION or ledger.get('kind') != 'stream-completion-ledger',
            'unknown stream ledger revision')
    fail_if(ledger.get('arm') != phase['arm'] or ledger.get('arm') != h2load['arm'],
            'arm provenance mismatch')
    fail_if(ledger.get('client_sha256') != phase['client_sha256'],
            'stream ledger client identity mismatch')
    fail_if(ledger.get('boot_id') != phase['boot_id'], 'ledger and MAIN boot mismatch')
    fail_if(h2load.get('revision') != PAYLOAD_REVISION or
            h2load.get('kind') != 'h2load-main-phase-data-evidence',
            'requires M2.1.1 h2load evidence')
    fail_if(h2load.get('client_identity_state') != 'pinned-match' or
            h2load.get('client_sha256') != phase['client_sha256'],
            'h2load client identity unpinned')
    fail_if(h2load.get('diagnostic_flags') != [], 'h2load validity flags must be empty')
    req=h2load['request_counters']; codes=h2load['status_codes']
    fail_if(any(type(req.get(k)) is not int or req[k] < 0 for k in
                ('started','done','succeeded','failed','errored','timeout')),
            'malformed h2load counters')
    fail_if(not (req['started'] == req['done'] == req['succeeded'] > 0 and
                 req['failed'] == req['errored'] == req['timeout'] == 0),
            'h2load includes failed, incomplete, or zero successful requests')
    fail_if(codes.get('2xx') != req['succeeded'] or any(codes.get(k) != 0 for k in ('3xx','4xx','5xx')),
            'non-2xx or ambiguous h2load response codes')
    streams=ledger.get('streams')
    fail_if(not isinstance(streams,list) or not streams, 'empty stream completion ledger')
    fail_if(len(streams) != req['succeeded'], 'per-stream count disagrees with h2load successes')
    fail_if(not response_dir.is_dir(), 'response evidence directory absent')
    root=response_dir.resolve(strict=True)
    ids=set(); paths=set(); total=0; digests=[]
    main_start=phase['main_start_monotonic_ns']
    main_end=phase['main_end_monotonic_ns']
    expected_proto={'A':'2','B':'3','C':'3'}[phase['arm']]
    for s in streams:
        fail_if(not isinstance(s,dict), 'bad completion record')
        sid=s.get('stream_id');_id(sid,'stream_id')
        fail_if(sid in ids, 'duplicate stream_id');ids.add(sid)
        obj=s.get('object_id');_id(obj,'object_id')
        fail_if(obj not in corpus, 'unknown corpus object')
        fail_if(s.get('status_code') != 200 or s.get('complete') is not True or
                s.get('integrity_checked') is not True, 'stream status/integrity insufficient')
        fail_if(s.get('http_version') != expected_proto,
                'stream HTTP version incorrect for arm')
        _ns(s.get('started_monotonic_ns'),'stream-start')
        _ns(s.get('completed_monotonic_ns'),'stream-complete')
        fail_if(not (main_start <= s['started_monotonic_ns'] <
                     s['completed_monotonic_ns'] <= main_end),
                'stream started or completed outside MAIN')
        rel=s.get('response_file')
        fail_if(not isinstance(rel,str) or not rel or rel.startswith('/') or '\\' in rel,
                'unsafe response evidence path')
        pp=Path(rel)
        fail_if('..' in pp.parts or any(not component or component == '.' for component in rel.split('/')),
                'response evidence path traversal')
        fail_if(rel in paths, 'response evidence path reused');paths.add(rel)
        path=root / pp
        fail_if(path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root),
                'response file missing, symlinked, or escapes root')
        payload=path.read_bytes()
        reference=corpus[obj]
        fail_if(len(payload) != reference['size_bytes'] or
                s.get('received_bytes') != len(payload), 'stream body length mismatch')
        digest=hashlib.sha256(payload).hexdigest()
        fail_if(digest != reference['sha256'] or s.get('sha256') != digest,
                'stream SHA256 mismatch against pinned corpus')
        total += len(payload)
        digests.append({'stream_id':sid,'object_id':obj,'sha256':digest,
                        'response_file':rel,'bytes':len(payload)})
    fail_if(total != h2load['main_phase_data_bytes_reported'],
            'h2load MAIN DATA bytes do not reconcile with verified streams')
    return {'verified_response_files':len(streams),'verified_body_bytes':total,
            'response_proof':'file-rehash-vs-pinned-corpus',
            'stream_evidence_source':'externally supplied ledger, not authenticated to pinned h2load process',
            'file_digest_receipts':digests}


def evaluate(*, corpus_source: bytes, expected_corpus_sha256: str,
             ledger: dict, phase: dict, h2load: dict, response_dir: Path,
             client_start_snapshot: dict | None = None,
             client_end_snapshot: dict | None = None,
             controller_coordination: dict | None = None) -> dict:
    """Strict offline audit, never promotes an outcome to publication qualification."""
    _assert_same_ids(ledger,phase,h2load)
    arm=phase.get('arm')
    fail_if(arm not in ('A','B','C'), 'invalid arm')
    corpus=read_corpus(source=corpus_source, expected_sha256=expected_corpus_sha256)
    window=validate_phase(phase,run_id=phase['run_id'],attempt_id=phase['attempt_id'],
                           window_id=phase['window_id'],arm=arm,
                           client_sha256=phase['client_sha256'])
    verified=verify_stream_ledger(ledger=ledger,response_dir=response_dir,
                                 corpus=corpus,phase=phase,h2load=h2load)
    enclosure='not-supplied'
    if (client_start_snapshot is None) != (client_end_snapshot is None):
        raise ValueError('client counter snapshots must be supplied as a pair')
    if client_start_snapshot is not None:
        a,b=client_start_snapshot,client_end_snapshot
        _assert_same_ids(phase,a,b)
        fail_if(a.get('host_role')!='client' or b.get('host_role')!='client' or
                a.get('phase')!='start' or b.get('phase')!='end',
                'client snapshots role/phase mismatch')
        fail_if(phase['boot_id'] != a.get('identity',{}).get('boot_id') or
                phase['boot_id'] != b.get('identity',{}).get('boot_id'),
                'client snapshot vs MAIN boot changed')
        fail_if(not (a['capture']['monotonic_ns_after'] <= phase['main_start_monotonic_ns'] <
                     phase['main_end_monotonic_ns'] <= b['capture']['monotonic_ns_before']),
                'client counter snapshots fail to enclose entire MAIN')
        enclosure='client-snapshots-enclose-main-with-unknown-overcount'
    quality='not-supplied'
    if controller_coordination is not None:
        _assert_same_ids(controller_coordination,phase)
        quality=controller_coordination.get('quality')
        fail_if(quality not in ('within-provisional-threshold','exceeds-provisional-threshold',
                               'functional-local-only','same-linux-kernel-unqualified'),
                'invalid controller coordination result')
        fail_if(controller_coordination.get('loadgen_main_phase_bound') is not False,
                'M2.1.1 coordination must remain honest about MAIN origin')
    # Every result remains evidence-only. Files can be re-hashed, but provenance to
    # the executing pinned h2load and counter timing is not yet independently proved.
    return {'revision':REVISION,'schema_version':1,
            'kind':'m2-main-payload-reconciliation',
            **{k:phase[k] for k in ('run_id','attempt_id','window_id','arm')},
            'source_sha256':{'corpus':expected_corpus_sha256,
                             'phase':hashlib.sha256(json.dumps(phase,sort_keys=True).encode()).hexdigest(),
                             'ledger':hashlib.sha256(json.dumps(ledger,sort_keys=True).encode()).hexdigest()},
            'main_duration_seconds_diagnostic':window['seconds'],
            'h2load_main_data_bytes':h2load['main_phase_data_bytes_reported'],
            'integrity_verified_file_bytes':verified['verified_body_bytes'],
            'integrity_verified_file_count':verified['verified_response_files'],
            'goodput_mbps_diagnostic':8*verified['verified_body_bytes']/window['seconds']/1e6,
            'client_counter_enclosure':enclosure,'controller_coordination':quality,
            'client_phase_origin_attested':False,
            'ledger_to_h2load_execution_attested':False,
            'valid_application_payload_bytes':{'state':'unavailable','value':None,
                'reason':'per-file hashes validated, but completion ledger not yet bound to audited pinned loadgen execution'},
            'application_goodput_mbps':{'state':'unavailable','value':None,
                'reason':'MAIN event origin and DUT/client counter alignment not independently attested'},
            'dut_process_cpu_seconds_per_gib':{'state':'unavailable','value':None,
                'reason':'no exact DUT MAIN CPU attribution nor attested valid bytes'},
            'dut_host_cpu_seconds_per_gib':{'state':'unavailable','value':None,
                'reason':'no exact DUT MAIN CPU attribution nor attested valid bytes'},
            'qualification_status':'evidence-only-not-qualified',
            'qualified_primary_result':False,
            'pending_gates':['audited-in-process-h2load-main-boundaries',
                'audited-in-process-stream-completion-integrity-provenance',
                'bounded-DUT-and-client-main-window-CPU-attribution',
                'bare-metal-environment-and-traffic-isolation',
                'measurement-overhead-calibration']}
