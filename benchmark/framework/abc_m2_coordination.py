"""Additive M2.1.1 control-plane time-bracketing evidence (NOT clock sync).

Host monotonic timestamps are host-local. Controller send/receive brackets
provide conservative, shared-clock uncertainty bounds. Neither those bounds
nor this module bind h2load MAIN phase to collector snapshot instants.
"""
from __future__ import annotations

import datetime as datetime
import hashlib
import json
import os
import platform
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from framework.abc_m2_contract import REVISION, fail_if

COORDINATION_REVISION = 'ngi541-abc-m2.1.1-window-r1'
ROLES = frozenset(('dut', 'client'))
EDGES = frozenset(('start', 'end'))


def _positive_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def marker(*, run_id: str, attempt_id: str, window_id: str,
           host_role: str, edge: str) -> dict:
    """Capture an event bracket locally on a Linux host, without remote clock conversion."""
    fail_if(platform.system() != 'Linux', 'M2 marker requires Linux')
    fail_if(host_role not in ROLES or edge not in EDGES, 'bad host role/edge')
    fail_if(any(not isinstance(x, str) or not x for x in (run_id, attempt_id, window_id)),
            'empty M2 experiment identifier')
    before = time.monotonic_ns()
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='utf-8').strip()
    hostname = socket.gethostname()
    utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    after = time.monotonic_ns()
    fail_if(not boot_id or after < before, 'marker clock or boot identity invalid')
    return {'schema_version': 1, 'revision': COORDINATION_REVISION,
            'kind': 'linux-host-marker', 'run_id': run_id, 'attempt_id': attempt_id,
            'window_id': window_id, 'host_role': host_role, 'edge': edge,
            'boot_id': boot_id, 'hostname': hostname,
            'monotonic_ns_before': before, 'monotonic_ns_after': after,
            'utc_advisory_only': utc}


def validate_marker(m: dict, *, role: str | None = None, edge: str | None = None) -> None:
    fail_if(not isinstance(m, dict) or m.get('kind') != 'linux-host-marker' or
            m.get('revision') != COORDINATION_REVISION, 'unknown marker revision')
    fail_if(m.get('host_role') not in ROLES or m.get('edge') not in EDGES,
            'marker role/edge invalid')
    if role is not None:
        fail_if(m.get('host_role') != role, 'marker host role mismatch')
    if edge is not None:
        fail_if(m.get('edge') != edge, 'marker edge mismatch')
    for k in ('run_id', 'attempt_id', 'window_id', 'hostname', 'boot_id'):
        fail_if(not isinstance(m.get(k), str) or not m[k], f'marker missing {k}')
    a, b = m.get('monotonic_ns_before'), m.get('monotonic_ns_after')
    fail_if(not _positive_int(a) or not _positive_int(b) or b < a,
            'marker local monotonic bracket invalid')


def receipt(*, host_marker: dict, controller_boot_id: str, controller_hostname: str,
            send_before_ns: int, receive_after_ns: int, transport: str) -> dict:
    """Controller receipt; remote event is conservatively enclosed by send/receive."""
    validate_marker(host_marker)
    fail_if(transport not in ('ssh', 'local-test'), 'unsupported transport')
    fail_if(any(not isinstance(v, str) or not v for v in
                (controller_boot_id, controller_hostname)), 'controller identity missing')
    fail_if(not _positive_int(send_before_ns) or not _positive_int(receive_after_ns) or
            receive_after_ns < send_before_ns, 'bad controller time bracket')
    return {'schema_version': 1, 'revision': COORDINATION_REVISION,
            'kind': 'controller-receipt', 'host_marker': host_marker,
            'controller': {'hostname': controller_hostname, 'boot_id': controller_boot_id},
            'controller_before_ns': send_before_ns, 'controller_after_ns': receive_after_ns,
            'transport': transport,
            'qualified_time_sync': False}


def validate_receipt(r: dict, *, role: str | None = None, edge: str | None = None) -> None:
    fail_if(not isinstance(r, dict) or r.get('revision') != COORDINATION_REVISION or
            r.get('kind') != 'controller-receipt', 'unknown controller receipt')
    validate_marker(r.get('host_marker'), role=role, edge=edge)
    c = r.get('controller')
    fail_if(not isinstance(c, dict) or not c.get('boot_id') or not c.get('hostname'),
            'controller identity missing')
    a, b = r.get('controller_before_ns'), r.get('controller_after_ns')
    fail_if(not _positive_int(a) or not _positive_int(b) or a > b, 'controller bracket invalid')
    fail_if(r.get('transport') not in ('ssh','local-test') or
            r.get('qualified_time_sync') is not False, 'controller evidence overclaims sync')


def local_receipt(*, role: str, edge: str, run_id: str, attempt_id: str,
                  window_id: str) -> dict:
    """Same-machine functional diagnostic; never CloudLab cross-host proof."""
    before = time.monotonic_ns()
    m = marker(run_id=run_id, attempt_id=attempt_id, window_id=window_id,
               host_role=role, edge=edge)
    after = time.monotonic_ns()
    return receipt(host_marker=m, controller_boot_id=m['boot_id'],
                   controller_hostname=m['hostname'], send_before_ns=before,
                   receive_after_ns=after, transport='local-test')


def ssh_receipt(*, ssh_target: str, remote_repo: str, role: str,
                edge: str, run_id: str, attempt_id: str, window_id: str,
                timeout_seconds: float = 15.0) -> dict:
    """Remote marker under one SSH call; no retries, preserves one request envelope.

    SSH accepts a single remote command string; quote each argument. The repo
    path must already be available on the remote Linux host. SSH key/known_hosts
    must be provisioned by the operator (BatchMode=yes, strict host keys).
    """
    import shlex
    fail_if(not ssh_target or ssh_target.startswith('-') or not remote_repo.startswith('/'),
            'unsafe/missing SSH destination or remote absolute repository')
    fail_if(role not in ROLES or edge not in EDGES, 'bad remote marker role/edge')
    command_args = ['env', f'PYTHONPATH={remote_repo}/benchmark', 'python3', '-m',
                    'framework.abc_m2_bridge_cli', 'marker',
                    '--run-id', run_id, '--attempt-id', attempt_id,
                    '--window-id', window_id, '--host-role', role, '--edge', edge]
    remote_cmd = ' '.join(shlex.quote(p) for p in command_args)
    before = time.monotonic_ns()
    response = subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                               '-o','ConnectTimeout=5',ssh_target,remote_cmd],
                              capture_output=True, text=True, timeout=timeout_seconds,
                              check=False)
    after = time.monotonic_ns()
    fail_if(response.returncode != 0,
            f'SSH marker failed (status {response.returncode}); no automatic retry')
    try:
        m = json.loads(response.stdout)
    except (ValueError, TypeError) as exc:
        raise ValueError('SSH output not a single JSON marker') from exc
    validate_marker(m, role=role, edge=edge)
    fail_if(any(m[k] != val for k, val in
                [('run_id', run_id),('attempt_id',attempt_id),('window_id',window_id)]),
            'SSH host marker identifiers disagree with controller request')
    controller_boot = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='utf-8').strip()
    return receipt(host_marker=m, controller_boot_id=controller_boot,
                   controller_hostname=socket.gethostname(),
                   send_before_ns=before, receive_after_ns=after,
                   transport='ssh')


def assess(*, start_receipts: dict[str, dict], end_receipts: dict[str, dict],
           max_boundary_uncertainty_ms: float) -> dict:
    """Controller-based conservative skew bound, not guaranteed main-phase sync."""
    fail_if(type(max_boundary_uncertainty_ms) not in (int,float) or
            not (0 < max_boundary_uncertainty_ms <= 5000),
            'invalid declared boundary uncertainty threshold')
    fail_if(set(start_receipts) != ROLES or set(end_receipts) != ROLES,
            'required DUT/client receipts not provided')
    for edge, group in (('start',start_receipts),('end',end_receipts)):
        for role, r in group.items():
            validate_receipt(r, role=role, edge=edge)
    all_recs = list(start_receipts.values()) + list(end_receipts.values())
    bases = [r['host_marker'] for r in all_recs]
    ids = ('run_id','attempt_id','window_id')
    for k in ids:
        fail_if(len({m[k] for m in bases}) != 1, f'controller inconsistent {k}')
    controllers = {(r['controller']['boot_id'],r['controller']['hostname']) for r in all_recs}
    fail_if(len(controllers) != 1, 'controller boot/identity changed')
    for role in ROLES:
        x,y = start_receipts[role]['host_marker'], end_receipts[role]['host_marker']
        fail_if(x['boot_id'] != y['boot_id'] or x['hostname'] != y['hostname'],
                f'{role} host identity changed between edges')
        fail_if(x['monotonic_ns_after'] >= y['monotonic_ns_before'],
                f'{role} own local time reversed or overlapping')
    end_of_start = max(r['controller_after_ns'] for r in start_receipts.values())
    beginning_of_end = min(r['controller_before_ns'] for r in end_receipts.values())
    fail_if(end_of_start >= beginning_of_end, 'controller start/end rounds overlap')
    start_uncertainty_ns = (max(r['controller_after_ns'] for r in start_receipts.values()) -
                            min(r['controller_before_ns'] for r in start_receipts.values()))
    end_uncertainty_ns = (max(r['controller_after_ns'] for r in end_receipts.values()) -
                          min(r['controller_before_ns'] for r in end_receipts.values()))
    worst_ms = max(start_uncertainty_ns, end_uncertainty_ns) / 1e6
    # True cross-host marker skew is bounded by each round's shared-controller envelope.
    quality = ('within-provisional-threshold' if worst_ms <= max_boundary_uncertainty_ms
               else 'exceeds-provisional-threshold')
    transports = {r['transport'] for r in all_recs}
    if transports != {'ssh'}:
        quality = 'functional-local-only'
    elif (start_receipts['dut']['host_marker']['boot_id'] ==
          start_receipts['client']['host_marker']['boot_id']):
        quality = 'same-linux-kernel-unqualified'
    return {'schema_version':1,'revision':COORDINATION_REVISION,
            'kind':'controller-window-assessment',
            'run_id':bases[0]['run_id'],'attempt_id':bases[0]['attempt_id'],
            'window_id':bases[0]['window_id'],'collection_mode':'P',
            'controller':all_recs[0]['controller'],
            'start_skew_upper_bound_ms':start_uncertainty_ns/1e6,
            'end_skew_upper_bound_ms':end_uncertainty_ns/1e6,
            'max_skew_upper_bound_ms':worst_ms,
            'declared_threshold_ms':max_boundary_uncertainty_ms,
            'quality':quality,
            'controller_elapsed_seconds_bounds': {
                'minimum':(beginning_of_end-end_of_start)/1e9,
                'maximum':(max(r['controller_after_ns'] for r in end_receipts.values())-
                           min(r['controller_before_ns'] for r in start_receipts.values()))/1e9},
            'loadgen_main_phase_bound': False,
            'snapshots_contain_main_phase_proven': False,
            'qualified_primary_result': False,
            'warnings':[
                'Host monotonic clocks were never compared across hosts.',
                'Controller envelopes bound marker skew, not the loadgen MAIN boundary.',
                'No application bytes or CPU/GiB are qualified by this document.',
                'Mark and counter read are distinct operations; alignment must be independently bounded.']}


def assess_snapshot_enclosure(*, start: dict, end: dict, start_marker: dict,
                             end_marker: dict) -> dict:
    """Conservative inclusion of host-local marker events in counter sampling interval."""
    for m, edge in ((start_marker,'start'),(end_marker,'end')):
        validate_marker(m, role=start.get('host_role'), edge=edge)
    for k in ('run_id','attempt_id','window_id','host_role'):
        fail_if(start.get(k) != end.get(k) or
                start.get(k) != start_marker.get(k) or
                end.get(k) != end_marker.get(k), f'enclosure identity mismatch: {k}')
    boot = start['identity']['boot_id']
    fail_if(boot != end['identity']['boot_id'] or
            boot != start_marker['boot_id'] or boot != end_marker['boot_id'],
            'snapshot/marker boot mismatch')
    s0 = start['capture']['monotonic_ns_before']
    s1 = start['capture']['monotonic_ns_after']
    e0 = end['capture']['monotonic_ns_before']
    e1 = end['capture']['monotonic_ns_after']
    m0 = start_marker['monotonic_ns_before']
    m1 = start_marker['monotonic_ns_after']
    n0 = end_marker['monotonic_ns_before']
    n1 = end_marker['monotonic_ns_after']
    fail_if(not all(_positive_int(x) for x in (s0,s1,e0,e1,m0,m1,n0,n1)) or
            not (s0 <= s1 <= m0 <= m1 < n0 <= n1 <= e0 <= e1),
            'snapshots do not enclose markers in correct temporal order')
    return {'schema_version':1,'revision':COORDINATION_REVISION,
            'kind':'local-counter-enclosure','run_id':start['run_id'],
            'attempt_id':start['attempt_id'],'window_id':start['window_id'],
            'host_role':start['host_role'],
            'pre_window_padding_upper_bound_ms':(m1-s0)/1e6,
            'post_window_padding_upper_bound_ms':(e1-n0)/1e6,
            'counters_enclose_markers':True,
            'exact_main_phase_bound':False,
            'qualified_primary_result':False}
