from __future__ import annotations

import itertools
import random
from typing import Any

from framework.io_utils import FrameworkError


SUPPORTED_COMPARISON_MODES = {
    "single",
    "fixed",
    "paired-balanced",
    "randomized",
}


def resolve_common_request(request: dict[str, Any]) -> dict[str, Any]:
    variants = request.get("variants")
    parameters = dict(request.get("parameters") or {})

    if not isinstance(variants, list) or not variants:
        raise FrameworkError("request must contain at least one variant")

    if len(set(variants)) != len(variants):
        raise FrameworkError("request variants must be unique")

    repetitions = parameters.get("repetitions", 1)
    if not isinstance(repetitions, int) or repetitions < 1:
        raise FrameworkError("parameters.repetitions must be a positive integer")

    requested_mode = (request.get("comparison") or {}).get("mode")

    if requested_mode is None:
        if len(variants) == 1:
            comparison_mode = "single"
        elif len(variants) == 2:
            comparison_mode = "paired-balanced"
        else:
            comparison_mode = "fixed"
    else:
        comparison_mode = requested_mode

    if comparison_mode not in SUPPORTED_COMPARISON_MODES:
        raise FrameworkError(f"unsupported comparison mode: {comparison_mode}")

    if comparison_mode == "single" and len(variants) != 1:
        raise FrameworkError("single comparison mode requires exactly one variant")

    if comparison_mode == "paired-balanced" and len(variants) != 2:
        raise FrameworkError(
            "paired-balanced comparison mode requires exactly two variants"
        )

    random_seed = (request.get("comparison") or {}).get("random_seed")
    if comparison_mode == "randomized":
        if random_seed is None:
            random_seed = 0
        if not isinstance(random_seed, int):
            raise FrameworkError("comparison.random_seed must be an integer")

    resolved = {
        "workload": request["workload"],
        "variants": list(variants),
        "parameters": parameters,
        "comparison": {
            "mode": comparison_mode,
            "random_seed": random_seed if comparison_mode == "randomized" else None,
        },
    }

    if "environment" in request:
        resolved["environment"] = request["environment"]
    else:
        resolved["deployment"] = request["deployment"]

    if request.get("alias") is not None:
        resolved["alias"] = request["alias"]

    if request.get("conditions") is not None:
        resolved["conditions"] = [
            dict(condition)
            for condition in request["conditions"]
        ]

    scheduling = request.get("scheduling")
    if scheduling is not None:
        if not isinstance(scheduling, dict):
            raise FrameworkError("scheduling must be an object")
        condition_order = scheduling.get("condition_order", "condition-major")
        variant_order = scheduling.get("variant_order", "pair-sequence")
        if condition_order not in {"condition-major", "rotating-rounds"}:
            raise FrameworkError(
                f"unsupported scheduling.condition_order: {condition_order}"
            )
        if variant_order not in {"pair-sequence", "alternate-by-repetition", "balanced-by-condition-round"}:
            raise FrameworkError(
                f"unsupported scheduling.variant_order: {variant_order}"
            )
        resolved["scheduling"] = {
            "condition_order": condition_order,
            "variant_order": variant_order,
        }

    if request.get("measurement_control") is not None:
        resolved["measurement_control"] = request["measurement_control"]

    return resolved


def _parameter_matrix(parameters: dict[str, Any]) -> list[dict[str, Any]]:
    axis_names: list[str] = []
    axis_values: list[list[Any]] = []
    fixed: dict[str, Any] = {}

    for name in sorted(parameters):
        if name == "repetitions":
            continue

        value = parameters[name]
        if isinstance(value, list):
            if not value:
                raise FrameworkError(f"parameter axis {name!r} must not be empty")
            axis_names.append(name)
            axis_values.append(value)
        else:
            fixed[name] = value

    if not axis_names:
        return [fixed]

    rows = []
    for values in itertools.product(*axis_values):
        row = dict(fixed)
        for name, value in zip(axis_names, values):
            row[name] = value
        rows.append(row)

    return rows


def build_schedule(
    experiment_id: str,
    resolved: dict[str, Any],
) -> dict[str, Any]:
    variants = resolved["variants"]
    parameters = resolved["parameters"]
    repetitions = parameters.get("repetitions", 1)
    mode = resolved["comparison"]["mode"]
    random_seed = resolved["comparison"].get("random_seed")
    scheduling = resolved.get("scheduling") or {
        "condition_order": "condition-major",
        "variant_order": "pair-sequence",
    }

    explicit_conditions = resolved.get("conditions")
    if explicit_conditions is not None:
        fixed = {
            name: value
            for name, value in parameters.items()
            if name != "repetitions"
        }
        matrix = []
        for condition in explicit_conditions:
            row = dict(fixed)
            row.update(condition)
            matrix.append(row)
    else:
        matrix = _parameter_matrix(parameters)

    rng = random.Random(random_seed)

    runs: list[dict[str, Any]] = []
    sequence = 0
    pair_sequence = 0

    def append_pair(
        parameter_set: dict[str, Any],
        condition_index: int,
        condition_position: int,
        repetition: int,
    ) -> None:
        nonlocal sequence, pair_sequence
        pair_sequence += 1

        if mode == "single":
            order = list(variants)
            pair_id = None
        elif mode == "paired-balanced":
            order = list(variants)
            if scheduling.get("variant_order") == "alternate-by-repetition":
                if repetition % 2 == 0:
                    order.reverse()
            elif scheduling.get("variant_order") == "balanced-by-condition-round":
                if ((repetition - 1) + condition_index) % 2 == 1:
                    order.reverse()
            elif pair_sequence % 2 == 0:
                order.reverse()
            pair_id = f"pair-{pair_sequence:04d}"
        elif mode == "randomized":
            order = list(variants)
            rng.shuffle(order)
            pair_id = f"pair-{pair_sequence:04d}" if len(order) > 1 else None
        else:
            order = list(variants)
            pair_id = f"pair-{pair_sequence:04d}" if len(order) > 1 else None

        condition_id = f"condition-{condition_index + 1:04d}"
        pair_order = "/".join(order)
        for pair_position, variant in enumerate(order, start=1):
            sequence += 1
            runs.append(
                {
                    "sequence": sequence,
                    "run_id": f"run-{sequence:04d}",
                    "pair_id": pair_id,
                    "variant": variant,
                    "repetition": repetition,
                    "repetition_round": repetition,
                    "condition_id": condition_id,
                    "condition_index": condition_index + 1,
                    "condition_position_in_round": condition_position,
                    "pair_position": pair_position,
                    "pair_order": pair_order,
                    "parameters": dict(parameter_set),
                }
            )

    if scheduling.get("condition_order") == "rotating-rounds":
        if not matrix:
            raise FrameworkError("rotating-rounds requires at least one condition")
        for repetition in range(1, repetitions + 1):
            offset = (repetition - 1) % len(matrix)
            indices = list(range(len(matrix)))
            rotated = indices[offset:] + indices[:offset]
            for position, condition_index in enumerate(rotated, start=1):
                append_pair(
                    matrix[condition_index],
                    condition_index,
                    position,
                    repetition,
                )
    else:
        for condition_index, parameter_set in enumerate(matrix):
            for repetition in range(1, repetitions + 1):
                append_pair(
                    parameter_set,
                    condition_index,
                    condition_index + 1,
                    repetition,
                )

    return {
        "schema_version": 2 if scheduling != {"condition_order": "condition-major", "variant_order": "pair-sequence"} else 1,
        "experiment_id": experiment_id,
        "comparison_mode": mode,
        "random_seed": random_seed if mode == "randomized" else None,
        "scheduling": dict(scheduling),
        "runs": runs,
    }

