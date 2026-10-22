"""Additive M2 evidence contract v2; leaves ABC draft schema v1 unchanged.

A telemetry observation is evidence, NOT automatic scientific-run acceptance.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from framework.io_utils import FrameworkError

REVISION = 'ngi541-abc-m2-0.2-additive-r1'
REGISTRY_REVISION = 'ngi541-abc-m2-draft-v0.2'
LEGACY_SHA256 = '99805dd378310ec539246e655d3f2a690036e4e50ac83c27c52765d1a50fb387'
STATES = frozenset({'measured', 'unavailable', 'not_applicable', 'invalid'})
MODES = frozenset({'P', 'C', 'K'})
SHA256_RE = re.compile(r'[0-9a-f]{64}\Z')


def fail_if(condition: bool, reason: str) -> None:
    if condition:
        raise FrameworkError(reason)


def registry_path() -> Path:
    return Path(__file__).resolve().parents[1] / 'protocols' / 'abc-m2-metric-registry-v0.2.json'


def load_registry(path: Path | None = None) -> dict[str, Any]:
    data = json.loads((path or registry_path()).read_text(encoding='utf-8'))
    fail_if(data.get('registry_version') != REGISTRY_REVISION, 'M2 registry version mismatch')
    fail_if(data.get('legacy_protocol_sha256') != LEGACY_SHA256, 'M2 historical boundary mismatch')
    fail_if(data.get('status') != 'design-not-frozen', 'M2 registry must remain draft')
    fail_if(set(data.get('states', [])) != STATES or set(data.get('measurement_modes', {})) != MODES,
            'M2 registry state/mode regression')
    names = [m.get('name') for m in data.get('metrics', [])]
    fail_if(len(names) != 26 or len(names) != len(set(names)), 'M2 registry must have 26 unique metrics')
    for m in data['metrics']:
        fail_if(not isinstance(m.get('unit'), str) or not m['unit'], 'M2 metric missing unit')
        fail_if(not isinstance(m.get('scope'), str) or not m['scope'], 'M2 metric missing scope')
        fail_if(not set(m.get('modes', [])) <= MODES, 'M2 invalid mode')
        fail_if(not set(m.get('required_for', [])) <= set('ABC'), 'M2 invalid arm')
    return data


def metric_record(*, name: str, state: str, value: int | float | None,
                  reason: str | None, source: str, host_role: str,
                  window_id: str, collection_mode: str = 'P',
                  sampling_interval_seconds: float | None = None,
                  detail: dict | None = None, registry: dict | None = None) -> dict:
    metrics = {m['name']: m for m in (registry or load_registry())['metrics']}
    fail_if(name not in metrics, f'M2 unknown metric {name}')
    item = metrics[name]
    result = dict(state=state, value=value, reason=reason, unit=item['unit'],
                  scope=item['scope'], source=source, host_role=host_role,
                  window_id=window_id, collection_mode=collection_mode,
                  sampling_interval_seconds=sampling_interval_seconds,
                  detail=detail or {})
    validate_metric_v2(result, name, item)
    return result


def validate_metric_v2(value: dict, name: str, declaration: dict) -> None:
    fail_if(not isinstance(value, dict), f'{name}: metric record required')
    state = value.get('state')
    fail_if(state not in STATES, f'{name}: unknown state')
    if state == 'measured':
        n = value.get('value')
        fail_if(isinstance(n, bool) or not isinstance(n, (int, float)) or
                not math.isfinite(n) or n < 0, f'{name}: measured value invalid')
        fail_if(value.get('reason') is not None, f'{name}: measured cannot carry reason')
    else:
        fail_if(value.get('value') is not None or not isinstance(value.get('reason'), str) or
                not value['reason'].strip(), f'{name}: {state} must have null and reason')
    for key in ('source', 'window_id', 'host_role'):
        fail_if(not isinstance(value.get(key), str) or not value[key], f'{name}: missing {key}')
    fail_if(value.get('host_role') not in ('dut', 'client'), f'{name}: invalid host_role')
    fail_if(value.get('scope') != declaration['scope'] or value.get('unit') != declaration['unit'],
            f'{name}: unit/scope regression')
    fail_if(value.get('collection_mode') not in declaration['modes'], f'{name}: invalid collection_mode')
    interval = value.get('sampling_interval_seconds')
    fail_if(interval is not None and (isinstance(interval, bool) or not isinstance(interval, (float, int)) or
            not math.isfinite(interval) or interval <= 0), f'{name}: invalid sampling interval')
    fail_if(not isinstance(value.get('detail'), dict), f'{name}: detail must be object')


def validate_observation_v2(record: dict, registry: dict | None = None) -> None:
    registry = registry or load_registry()
    fail_if(not isinstance(record, dict) or record.get('schema_version') != 2 or
            record.get('contract_revision') != REVISION, 'M2 observation schema/revision mismatch')
    arm, mode = record.get('arm'), record.get('collection_mode')
    fail_if(arm not in ('A', 'B', 'C') or mode not in MODES, 'M2 arm/mode invalid')
    fail_if(record.get('host_role') not in ('dut', 'client'), 'M2 host role invalid')
    for key in ('run_id', 'window_id', 'attempt_id'):
        fail_if(not isinstance(record.get(key), str) or not record[key], f'M2 requires {key}')
    fail_if(record.get('qualification_status') != 'evidence-only-not-qualified',
            'M2 snapshot evidence cannot assert science-run qualification')
    values = record.get('metrics')
    fail_if(not isinstance(values, dict), 'M2 metrics dictionary required')
    declarations = {m['name']: m for m in registry['metrics']}
    for name, value in values.items():
        fail_if(name not in declarations, f'unknown M2 metric {name}')
        declaration = declarations[name]
        validate_metric_v2(value, name, declaration)
        fail_if(value['collection_mode'] != mode or value['window_id'] != record['window_id'] or
                value['host_role'] != record['host_role'], f'{name}: provenance mismatch')
        if arm not in declaration['required_for']:
            fail_if(value['state'] != 'not_applicable', f'{name}: metric is inapplicable to arm {arm}')


def validate_complete_primary_claim(record: dict, registry: dict | None = None) -> None:
    """Fail closed: same-host collector alone cannot satisfy a full scientific claim."""
    validate_observation_v2(record, registry)
    fail_if(record['collection_mode'] != 'P', 'complete primary claim requires P')
    fail_if(record.get('qualification_status') != 'qualified',
            'M2 evidence-only record is NOT a qualified primary outcome')
