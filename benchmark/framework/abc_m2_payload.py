"""M2.1.1 exact-source h2load MAIN DATA evidence, NOT validated payload goodput.

h2load patched measurements.traffic.data counts MAIN-phase DATA bytes. It does
not individually validate every delivered object checksum or prove those bytes
all belong to completed successful requests. Keep this distinct from the
registry's valid_application_payload_bytes until later proof exists.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from framework.abc_m2_contract import fail_if

PAYLOAD_REVISION = 'ngi541-abc-m2.1.1-h2load-evidence-r1'


def _count(obj: dict, key: str, *, default: int | None = None) -> int:
    raw = obj.get(key, default)
    fail_if(type(raw) is not int or raw < 0, f'h2load {key}: nonnegative integer required')
    return raw


def extract_h2load_evidence(*, source: bytes, arm: str,
                            run_id: str, attempt_id: str, window_id: str,
                            expected_client_sha256: str | None = None,
                            actual_client_sha256: str | None = None,
                            declared_main_seconds: float | None = None) -> dict:
    fail_if(type(arm) is not str or arm not in ('A', 'B', 'C'), 'invalid arm')
    fail_if(any(not isinstance(x,str) or not x for x in (run_id,attempt_id,window_id)),
            'missing attempt identity')
    try:
        x = json.loads(source)
        meas = x['measurements']
        req = meas['requests']
        codes = meas['status_codes']
        traffic = meas['traffic']
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError('h2load result lacks required measurement structure') from exc
    fail_if(not all(isinstance(v,dict) for v in (meas,req,codes,traffic)),
            'h2load measurement fields must be objects')
    data = _count(traffic,'data')
    total = _count(traffic,'total')
    started = _count(req,'started')
    done = _count(req,'done')
    succeeded = _count(req,'succeeded')
    failed = _count(req,'failed')
    errored = _count(req,'errored')
    timeout = _count(req,'timeout',default=0)
    status = {k:_count(codes,k,default=0) for k in ('2xx','3xx','4xx','5xx')}
    flags = []
    if total < data: flags.append('traffic_total_less_than_data')
    if done > started: flags.append('done_greater_than_started')
    if succeeded > done: flags.append('success_greater_than_done')
    if any((failed,errored,timeout)): flags.append('request_failure_reported')
    if status['4xx'] or status['5xx']: flags.append('http_error_status')
    if status['3xx']: flags.append('http_redirect_requires_workload_policy')
    if sum(status.values()) != succeeded:
        flags.append('status_and_success_count_disagree_possible_phase_boundary')
    if started > done:
        flags.append('inflight_at_cutoff')
    if declared_main_seconds is not None:
        fail_if(type(declared_main_seconds) not in (float,int) or
                not (0 < declared_main_seconds < 1e10), 'invalid declared MAIN duration')
    if expected_client_sha256 is not None:
        fail_if(not isinstance(actual_client_sha256,str) or
                actual_client_sha256 != expected_client_sha256,
                'client executable SHA256 mismatch')
    return {'schema_version':1,'revision':PAYLOAD_REVISION,
            'kind':'h2load-main-phase-data-evidence','run_id':run_id,
            'attempt_id':attempt_id,'window_id':window_id,'arm':arm,
            'source_sha256':hashlib.sha256(source).hexdigest(),
            'client_sha256':actual_client_sha256,
            'client_identity_state': ('pinned-match' if expected_client_sha256 is not None
                                      else 'unverified'),
            'scientific_byte_accounting':'h2load-main-phase-body-bytes',
            'main_phase_data_bytes_reported':data,
            'traffic_total_bytes_reported':total,
            'request_counters':dict(started=started,done=done,succeeded=succeeded,
                                    failed=failed,errored=errored,timeout=timeout),
            'status_codes':status,
            'diagnostic_flags':flags,
            'declared_main_seconds':declared_main_seconds,
            'reported_data_rate_mbps_diagnostic':
                8*data/declared_main_seconds/1e6 if declared_main_seconds is not None else None,
            'integrity_coverage':'not-demonstrated-by-h2load-counters',
            'valid_application_payload_bytes':{'state':'unavailable','value':None,
                'reason':'MAIN DATA bytes do not prove per-response integrity/completed valid bytes'},
            'qualification_status':'evidence-only-not-qualified',
            'qualified_primary_result':False}
