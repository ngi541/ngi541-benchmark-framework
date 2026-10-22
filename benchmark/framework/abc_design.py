from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from framework.io_utils import FrameworkError

ARMS = {
    "A": ("h2", "openssl"),
    "B": ("h3", "openssl"),
    "C": ("h3", "ngi541"),
}
PROFILES = ("clas12-event-stream", "lcls-detector-frame", "hacc-multifile-dataset")
CONCURRENCY_LEVELS = (4, 16, 64)
# The HTTP/3 causal pair is adjacent in every repetition. Each member leads twice;
# A precedes/follows the B/C pair twice. No selection depends on measured values.
ROUND_ORDERS = (("A", "B", "C"), ("C", "B", "A"),
                ("B", "C", "A"), ("A", "C", "B"))


def _fail_if(condition: bool, message: str) -> None:
    if condition:
        raise FrameworkError(message)


def load_abc_design(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    validate_abc_design(value)
    return value


def validate_abc_design(value: dict[str, Any]) -> None:
    _fail_if(not isinstance(value, dict), "ABC design must be an object")
    _fail_if(value.get("schema_version") != 1, "ABC schema_version must be 1")
    _fail_if(value.get("status") != "design-draft-non-executable",
             "ABC design must be explicitly non-executable until qualification")
    _fail_if(value.get("question") != (
        "How much of the high-speed QUIC/HTTP/3 efficiency gap is attributable to "
        "cryptographic execution, and under which workload and hardware conditions "
        "can an optimized crypto engine meaningfully reduce that gap?"),
        "ABC research question changed")
    arms = value.get("arms")
    _fail_if(not isinstance(arms, dict) or set(arms) != set(ARMS),
             "ABC arms must be exactly A, B, C")
    for arm, (proto, engine) in ARMS.items():
        actual = arms[arm]
        _fail_if(not isinstance(actual, dict) or
                 actual.get("protocol") != proto or
                 actual.get("server_crypto") != engine or
                 actual.get("client_uses_ngi541") is not False or
                 actual.get("direction") != "server-to-client",
                 f"ABC arm {arm} violates server-side-only design")
    execution = value.get("execution")
    _fail_if(not isinstance(execution, dict), "ABC execution missing")
    expected = {
        "repetitions": 4,
        "comparison": "bc-causal-pair-plus-a-reference",
        "ordering": "precommitted-balanced-4-rounds",
        "retry_policy": "no-metric-dependent-retry",
        "outlier_policy": "retain-all-valid-runs",
        "client_connections": 4,
    }
    for name, fixed in expected.items():
        _fail_if(execution.get(name) != fixed or
                 (isinstance(fixed, int) and isinstance(execution.get(name), bool)),
                 f"ABC execution.{name} must equal {fixed!r}")
    conditions = value.get("conditions")
    _fail_if(not isinstance(conditions, list) or len(conditions) != 9,
             "ABC pilot design requires exactly nine conditions")
    seen = set()
    for row in conditions:
        _fail_if(not isinstance(row, dict), "ABC condition must be an object")
        profile = row.get("profile_id")
        concurrent = row.get("concurrent_streams")
        _fail_if(profile not in PROFILES or type(concurrent) is not int or
                 concurrent not in CONCURRENCY_LEVELS or
                 row.get("streams_per_connection") != concurrent // 4 or
                 row.get("condition_id") != f"{profile}-{concurrent}",
                 "invalid ABC scientific condition")
        key = (profile, concurrent)
        _fail_if(key in seen, "duplicate ABC scientific condition")
        seen.add(key)
    _fail_if(seen != {(p, n) for p in PROFILES for n in CONCURRENCY_LEVELS},
             "missing ABC workload/concurrency combination")
    measurements = value.get("measurements")
    _fail_if(not isinstance(measurements, dict) or
             measurements.get("modes") != ["performance", "attribution"] or
             measurements.get("required_performance") != [
                 "application_goodput_mbps", "dut_process_cpu_seconds_per_gib",
                 "dut_host_cpu_seconds_per_gib", "loadgen_max_single_core_busy_percent"],
             "ABC primary measurement contract changed")


def abc_design_sha256(design: dict[str, Any]) -> str:
    validate_abc_design(design)
    return hashlib.sha256(json.dumps(design, sort_keys=True,
                                    separators=(",", ":"), ensure_ascii=False
                                    ).encode("utf-8")).hexdigest()


def build_abc_schedule(design: dict[str, Any]) -> list[dict[str, Any]]:
    validate_abc_design(design)
    conditions = list(design["conditions"])
    runs = []
    for repetition, order in enumerate(ROUND_ORDERS, start=1):
        for offset in range(len(conditions)):
            condition = conditions[(offset + repetition - 1) % len(conditions)]
            for position, arm in enumerate(order, start=1):
                condition_id = condition["condition_id"]
                runs.append({
                    "sequence": len(runs) + 1,
                    "run_id": f"abc-{len(runs) + 1:04d}",
                    "condition_id": condition_id,
                    "repetition": repetition,
                    "arm": arm,
                    "protocol": ARMS[arm][0],
                    "pair_id": f"{condition_id}-rep{repetition}" if arm in ("B", "C") else None,
                    "position": position,
                })
    assert len(runs) == 108
    return runs


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Validate additive A/B/C draft design")
    parser.add_argument("--definition", type=Path,
        default=Path(__file__).resolve().parents[1] / "protocols" / "abc-high-speed-design-draft.json")
    parser.add_argument("--schedule-output", type=Path, help="Write proposed schedule as JSON; no experiments run")
    args = parser.parse_args()
    value = load_abc_design(args.definition)
    runs = build_abc_schedule(value)
    print(f"ABC draft VALID: sha256={abc_design_sha256(value)} conditions={len(value['conditions'])} runs={len(runs)}")
    if args.schedule_output is not None:
        args.schedule_output.write_text(json.dumps(runs, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Schedule written: {args.schedule_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
