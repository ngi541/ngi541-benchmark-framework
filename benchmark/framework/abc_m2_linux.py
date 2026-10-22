"""Read-only Linux M2.1 primary collector and counter-delta normalizer.

Capture around an orchestrated main window; results do not establish loadgen
payload integrity, cross-host synchronization or physical-NIC fidelity.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import platform
import re
import socket
import time
from pathlib import Path
from typing import Any

from framework.abc_m2_contract import REVISION, fail_if, load_registry, metric_record, validate_observation_v2
from framework.io_utils import FrameworkError

NET_FIELDS = ('rx_bytes', 'tx_bytes', 'rx_packets', 'tx_packets', 'rx_dropped',
              'tx_dropped', 'rx_errors', 'tx_errors')
CPU_NAMES = ('user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq',
             'steal', 'guest', 'guest_nice')
CG_KEYS = ('usage_usec', 'user_usec', 'system_usec', 'nr_throttled', 'throttled_usec')
# These /proc/net/snmp fields are configuration or instantaneous gauges, not
# cumulative counters. Never reject a run or compute a delta on their decrease.
PROTOCOL_GAUGES = frozenset({
    'Ip.Forwarding', 'Ip.DefaultTTL', 'Ip.ReasmTimeout',
    'Tcp.RtoAlgorithm', 'Tcp.RtoMin', 'Tcp.RtoMax',
    'Tcp.MaxConn', 'Tcp.CurrEstab',
})


def parse_cpu_set(raw: str) -> list[int]:
    fail_if(not isinstance(raw, str) or not raw or not re.fullmatch(r'[0-9,-]+', raw), 'invalid CPU set')
    result: set[int] = set()
    for entry in raw.split(','):
        match = re.fullmatch(r'(\d+)(?:-(\d+))?', entry)
        fail_if(match is None, 'invalid CPU range')
        first, last = int(match[1]), int(match[2] or match[1])
        fail_if(last < first or last - first > 4095, 'invalid CPU range bounds')
        result.update(range(first, last + 1))
    fail_if(not result, 'empty CPU set')
    return sorted(result)


def parse_proc_stat(content: str, cpus: list[int]) -> dict[str, dict[str, int]]:
    rows: dict[str, dict[str, int]] = {}
    for line in content.splitlines():
        tokens = line.split()
        if tokens and re.fullmatch(r'cpu\d+', tokens[0]):
            parts = tokens[1:]
            fail_if(len(parts) < 8 or any(not p.isdecimal() for p in parts), 'invalid /proc/stat')
            rows[tokens[0]] = dict(zip(CPU_NAMES, map(int, parts[:10])))
    for n in cpus:
        fail_if(f'cpu{n}' not in rows, f'CPU {n} not present in /proc/stat')
    return {f'cpu{n}': rows[f'cpu{n}'] for n in cpus}


def parse_named_pairs(content: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in content.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdecimal():
            result[parts[0]] = int(parts[1])
    return result


def parse_net_protocols(content: str) -> dict[str, int]:
    lines = [l.split() for l in content.splitlines() if l.strip()]
    result: dict[str, int] = {}
    for header, values in zip(lines[::2], lines[1::2]):
        fail_if(not header or not values or header[0] != values[0] or
                len(header) != len(values), 'malformed /proc/net protocol counters')
        for key, value in zip(header[1:], values[1:]):
            fail_if(re.fullmatch(r'-?\d+', value) is None, 'non-numeric /proc/net value')
            result[header[0].rstrip(':') + '.' + key] = int(value)
    return result


def _read(path: Path) -> str:
    return path.read_text(encoding='utf-8')


def capture(*, run_id: str, attempt_id: str, window_id: str, phase: str,
            host_role: str, cpus: list[int], iface: str,
            cgroup_path: Path | None = None, proc: Path = Path('/proc'),
            sysnet: Path = Path('/sys/class/net')) -> dict[str, Any]:
    fail_if(platform.system() != 'Linux', 'M2.1 capture must run under Linux')
    fail_if(phase not in ('start', 'end') or host_role not in ('dut', 'client'), 'invalid phase or role')
    fail_if(not all(isinstance(x, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', x)
                    for x in (run_id, attempt_id, window_id)), 'invalid run/window/attempt')
    fail_if(not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', iface), 'invalid interface name')
    fail_if(not cpus or len(set(cpus)) != len(cpus) or any(n < 0 for n in cpus), 'invalid cpus')
    iface_root = sysnet / iface / 'statistics'
    fail_if(not iface_root.is_dir(), f'interface not found: {iface}')
    tick = os.sysconf('SC_CLK_TCK')
    start_ns = time.monotonic_ns()
    stamp = dt.datetime.now(dt.timezone.utc).isoformat()
    cpu = parse_proc_stat(_read(proc / 'stat'), cpus)
    net = {name: int(_read(iface_root / name).strip()) for name in NET_FIELDS}
    fail_if(any(n < 0 for n in net.values()), 'negative netdev statistic')
    boot_id = _read(proc / 'sys/kernel/random/boot_id').strip()
    fail_if(not boot_id, 'missing boot id')
    cgroup = {'state': 'unavailable', 'reason': 'dedicated cgroup path not supplied',
              'values': None, 'identity': None}
    if cgroup_path is not None:
        cgroup_path = Path(cgroup_path)
        try:
            values = parse_named_pairs(_read(cgroup_path / 'cpu.stat'))
            fail_if(not {'usage_usec', 'user_usec', 'system_usec'} <= values.keys(),
                    'cgroup v2 cpu.stat missing mandatory fields')
            meta = cgroup_path.stat()
            cgroup = {'state': 'measured', 'reason': None, 'values': values,
                      'identity': {'path': str(cgroup_path.resolve()), 'st_dev': meta.st_dev,
                                   'st_ino': meta.st_ino},
                      'cpu_max': _read(cgroup_path / 'cpu.max').strip() if (cgroup_path / 'cpu.max').exists() else None,
                      'cpuset_effective': _read(cgroup_path / 'cpuset.cpus.effective').strip()
                      if (cgroup_path / 'cpuset.cpus.effective').exists() else None}
        except (OSError, ValueError) as exc:
            cgroup = {'state': 'unavailable', 'reason': f'cgroup cpu.stat inaccessible: {type(exc).__name__}',
                      'values': None, 'identity': None}
    net_protocols = {}
    net_errors = {}
    for name in ('snmp', 'netstat'):
        try:
            net_protocols[name] = parse_net_protocols(_read(proc / 'net' / name))
        except (OSError, FrameworkError) as exc:
            net_protocols[name] = None
            net_errors[name] = f'{type(exc).__name__}: {str(exc)[:120]}'
    end_ns = time.monotonic_ns()
    return {
        'schema_version': 2, 'contract_revision': REVISION, 'kind': 'linux-primary-snapshot',
        'run_id': run_id, 'attempt_id': attempt_id, 'window_id': window_id, 'phase': phase,
        'host_role': host_role,
        'capture': {'utc_started': stamp, 'monotonic_ns_before': start_ns,
                    'monotonic_ns_after': end_ns, 'read_duration_ns': end_ns - start_ns},
        'identity': {'boot_id': boot_id, 'hostname': socket.gethostname(),
                     'kernel': platform.release(), 'cpu_tick_hz': tick,
                     'cpus': cpus, 'interface': iface, 'network_scope': 'current-network-namespace',
                     'container_or_vm': 'unknown-needs-topology-qualification'},
        'counters': {'cpu_ticks': cpu, 'netdev': net, 'cgroup': cgroup,
                     'protocols': net_protocols, 'protocol_read_errors': net_errors},
    }


def counter_deltas(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    fail_if(set(a) != set(b), 'counter schema changed across window')
    delta = {k: b[k] - a[k] for k in a}
    fail_if(any(not isinstance(v, int) or v < 0 for v in delta.values()),
            'counter reset/rollover/invalid values across main window')
    return delta


def derive(start: dict, end: dict, *, arm: str) -> dict:
    fail_if(arm not in ('A', 'B', 'C'), 'invalid ABC arm')
    for s in (start, end):
        fail_if(not isinstance(s, dict) or s.get('schema_version') != 2 or
                s.get('contract_revision') != REVISION or s.get('kind') != 'linux-primary-snapshot',
                'incorrect M2 snapshot revision/kind')
    fail_if(start.get('phase') != 'start' or end.get('phase') != 'end', 'snapshot phases incorrect')
    for key in ('run_id', 'attempt_id', 'window_id', 'host_role'):
        fail_if(start[key] != end[key], f'{key} changed during window')
    for key in ('boot_id', 'hostname', 'kernel', 'cpu_tick_hz', 'cpus', 'interface', 'network_scope'):
        fail_if(start['identity'][key] != end['identity'][key], f'Linux host identity changed: {key}')
    a, b = start['capture'], end['capture']
    fail_if(a['monotonic_ns_after'] >= b['monotonic_ns_before'],
            'snapshots overlap or end precedes start')
    # Exact counter sampling instants lie within the recorded capture brackets.
    duration_min = (b['monotonic_ns_before'] - a['monotonic_ns_after']) / 1e9
    duration_max = (b['monotonic_ns_after'] - a['monotonic_ns_before']) / 1e9
    duration_center = (duration_min + duration_max) / 2
    fail_if(duration_min <= 0, 'non-positive minimum measurement duration')
    tick = start['identity']['cpu_tick_hz']
    fail_if(type(tick) is not int or tick <= 0, 'invalid CPU tick frequency')
    cpu_deltas = {}
    per_core_busy = []
    busy_seconds = 0.0
    for cpu, old in start['counters']['cpu_ticks'].items():
        delta = counter_deltas(old, end['counters']['cpu_ticks'][cpu])
        # guest & guest_nice are INCLUDED in user/nice, do not count twice.
        total = sum(delta[k] for k in CPU_NAMES[:8])
        busy = sum(delta[k] for k in ('user', 'nice', 'system', 'irq', 'softirq'))
        fail_if(total <= 0 or busy > total, f'invalid /proc/stat window for {cpu}')
        per_core_busy.append(100 * busy / total)
        busy_seconds += busy / tick
        cpu_deltas[cpu] = delta
    nic = counter_deltas(start['counters']['netdev'], end['counters']['netdev'])
    cg_a, cg_b = start['counters']['cgroup'], end['counters']['cgroup']
    cg_delta = None
    cg_reason = 'dedicated cgroup unavailable on both boundaries'
    if cg_a['state'] == cg_b['state'] == 'measured':
        fail_if(cg_a['identity'] != cg_b['identity'], 'cgroup path/inode changed: risk of PID reuse')
        cg_delta = counter_deltas(cg_a['values'], cg_b['values'])
    else:
        cg_reason = '; '.join(x.get('reason') or 'cgroup missing' for x in (cg_a, cg_b))
    proto_delta: dict[str, Any] = {}
    proto_gauges: dict[str, Any] = {}
    for filename in ('snmp', 'netstat'):
        x = start['counters']['protocols'][filename]
        y = end['counters']['protocols'][filename]
        if x is None or y is None:
            proto_delta[filename] = None
            proto_gauges[filename] = None
            continue
        fail_if(set(x) != set(y), f'protocol fields changed across window: {filename}')
        proto_gauges[filename] = {
            k: {'before': x[k], 'after': y[k]} for k in x if k in PROTOCOL_GAUGES}
        proto_delta[filename] = counter_deltas(
            {k:v for k,v in x.items() if k not in PROTOCOL_GAUGES},
            {k:v for k,v in y.items() if k not in PROTOCOL_GAUGES})
    role = start['host_role']
    registry = load_registry()
    metrics = {}

    def put(name, state, value=None, reason=None, source='linux-m2.1-start-end', detail=None):
        metrics[name] = metric_record(name=name, state=state, value=value, reason=reason,
            source=source, host_role=role, window_id=start['window_id'], detail=detail, registry=registry)

    if role == 'dut':
        for name, src in [('nic_tx_bytes', 'tx_bytes'), ('nic_rx_bytes', 'rx_bytes'),
                          ('nic_tx_drops', 'tx_dropped'), ('nic_rx_drops', 'rx_dropped')]:
            put(name, 'measured', nic[src], source=f'/sys/class/net/{start["identity"]["interface"]}/statistics/{src}',
                detail={'counter_scope': 'network-interface', 'not_application_bytes': True})
        put('dut_process_cpu_seconds_per_gib', 'unavailable', reason=
            'dedicated-cgroup CPU/GiB requires independently verified payload bytes and orchestrator-aligned main window')
        put('dut_host_cpu_seconds_per_gib', 'unavailable', reason=
            'host CPU/GiB requires independently verified payload bytes and orchestrator-aligned main window')
        if arm == 'A':
            p = proto_delta.get('snmp')
            if p is not None and 'Tcp.RetransSegs' in p:
                put('tcp_retransmits', 'measured', p['Tcp.RetransSegs'], source='/proc/net/snmp Tcp.RetransSegs',
                    detail={'counter_scope':'host-network-namespace; not isolated to experiment'})
            else:
                put('tcp_retransmits', 'unavailable', reason='TCP SNMP counter missing')
        else:
            put('tcp_retransmits', 'not_applicable', reason='QUIC B/C use UDP, not TCP transport')
    else:
        put('client_total_busy_percent', 'measured', sum(per_core_busy)/len(per_core_busy),
            source='/proc/stat per selected cpu', detail={'aggregation':'mean of selected per-core mean busy'})
        put('client_max_single_core_busy_percent', 'unavailable',
            reason='start/end counters measure full-window per-core means, not instantaneous peak; interval sampling required',
            source='/proc/stat per selected cpu', detail={
                'max_single_core_window_mean_percent': max(per_core_busy),
                'is_instantaneous_peak': False, 'cannot_prove_95_percent_peak_gate': True})
        put('dut_process_cpu_seconds_per_gib', 'not_applicable', reason='DUT-only measurement')
        put('dut_host_cpu_seconds_per_gib', 'not_applicable', reason='DUT-only measurement')
        put('tcp_retransmits', 'not_applicable' if arm != 'A' else 'unavailable',
            reason='client snapshot does not establish DUT TCP retransmissions')
    for name in ('application_goodput_mbps', 'main_window_seconds', 'valid_application_payload_bytes'):
        put(name, 'unavailable', reason='requires validated loadgen payload/main-window and cross-host alignment evidence')
    observation = {
        'schema_version': 2, 'contract_revision': REVISION, 'arm': arm,
        'collection_mode': 'P', 'run_id': start['run_id'], 'attempt_id': start['attempt_id'],
        'window_id': start['window_id'], 'host_role': role,
        'qualification_status': 'evidence-only-not-qualified', 'metrics': metrics,
        'raw_counter_evidence': {
            'elapsed_seconds_range': {'minimum': duration_min, 'midpoint': duration_center,
                                      'maximum': duration_max},
            'snapshot_capture_duration_ns': [a['read_duration_ns'], b['read_duration_ns']],
            'host_cpu_busy_seconds': busy_seconds,
            'per_cpu_busy_percent_mean': dict(zip(start['identity']['cpus'], per_core_busy)),
            'per_cpu_tick_deltas': cpu_deltas, 'nic_deltas': nic,
            'cgroup_cpu_stat_deltas': cg_delta, 'cgroup_unavailable_reason': None if cg_delta else cg_reason,
            'protocol_counter_deltas': proto_delta,
            'protocol_gauges_before_after': proto_gauges,
            'host_role_scope': role,
            'warnings': [
                'No cross-host monotonic clock comparison: clocks are host-local.',
                'Endpoint snapshots alone cannot establish instantaneous peak CPU occupancy.',
                'Docker/LinuxKit data qualify collector functionality, not hardware throughput.',
                'Host NIC and protocol counters are not per-application and may include other traffic.',
                'Host busy CPU includes unrelated workloads unless allocation/isolation is independently qualified.',
                'Counter snapshots do not prove byte accounting or TLS/payload verification.'
            ]},
    }
    validate_observation_v2(observation, registry)
    return observation
